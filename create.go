package veracrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// Creating a volume follows the VeraCrypt Volume Format Specification
// (https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html:
// the header-layout table and "Embedded Backup Headers"), and the source it
// describes: src/Common/Volumes.c CreateVolumeHeaderInMemory (the header
// fields, the two CRC-32s, the header key, the XTS encryption of the 448
// bytes after the salt) and src/Common/Format.c FormatVolume (the primary
// header, the backup header rebuilt from the SAME master keys with a NEW
// salt, WriteRandomDataToReservedHeaderAreas, the decoy hidden-volume
// headers, quick versus full format). The reader above follows cryptsetup's
// lib/tcrypt/tcrypt.c, which is the second oracle.
//
// The layout of a file container of S bytes:
//
//	0       64  salt (random, unencrypted)
//	64     448  header (XTS under the header key; Spec: offsets 64-511)
//	512  65024  reserved: random
//	65536  65536  area of the hidden volume's header: random (no hidden
//	             volume is written, so the area holds what VeraCrypt puts
//	             there for one that does not exist: random bytes)
//	131072 S-262144  data area (the master key scope, tweak = offset/512)
//	S-131072  512  backup header (a different salt, the same master keys)
//	S-130560 65024  reserved: random
//	S-65536  65536  backup area of the hidden volume's header: random
const (
	// MinSize is the smallest container: the two 128 KiB header groups and
	// one sector of data.
	MinSize = 299008 // TC_MIN_VOLUME_SIZE (Volumes.h), a multiple of 512
	// MaxSize is the largest container, 1 PiB: TC_MAX_VOLUME_SIZE, the XTS
	// security bound, which also keeps every offset inside an int64.
	MaxSize = 1 << 50
	// MaxPIM bounds the PIM Create accepts. VeraCrypt's own ceiling is
	// higher, but a PIM of 100000 already costs 100 million PBKDF2
	// iterations, and the reader opens at most Limits.MaxPIM (default
	// 2000) without being told to.
	MaxPIM = 100000

	headerGroup   = 131072 // TC_VOLUME_HEADER_GROUP_SIZE: 128 KiB at each end
	headerVersion = 5      // VOLUME_HEADER_VERSION
	minProgram    = 0x010b // TC_VOLUME_MIN_REQUIRED_PROGRAM_VERSION (1.11)
	fillChunk     = 1 << 20
)

// ErrOption wraps every refusal of the arguments of Create.
var ErrOption = errors.New("veracrypt: invalid option")

// ErrRange is returned for a read or write outside the data area.
var ErrRange = errors.New("veracrypt: outside the volume")

// ErrClosed is returned after Close.
var ErrClosed = errors.New("veracrypt: volume closed")

// afterCheck runs in WriteAt between the closed check and the lock; a test
// closes the volume there.
var afterCheck = func() {}

// entropy is where every random byte comes from; tests replace it.
var entropy io.Reader = rand.Reader

func option(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrOption, fmt.Sprintf(format, a...))
}

// CreateOptions says how to create a volume. The zero value is VeraCrypt's
// default: AES, PBKDF2-HMAC-SHA-512, no PIM, no keyfiles, random fill.
type CreateOptions struct {
	// Cipher is the XTS cipher or cascade; default AES. Every chain the
	// reader opens may be created.
	Cipher Cipher
	// KDF is the header key derivation: SHA512 (default), SHA256, BLAKE2s,
	// Whirlpool, Streebog or Argon2id.
	KDF KDF
	// PIM is the Personal Iterations Multiplier; 0 is the default cost.
	// At most MaxPIM.
	PIM int
	// Keyfiles are the contents of the keyfiles, as in Options.
	Keyfiles [][]byte
	// Quick skips the random fill of the data area (VeraCrypt's "Quick
	// Format"): the container's data area is left as the writer has it, so
	// a new file is a sparse file of zero ciphertext, which decrypts to
	// noise but is distinguishable from a filled volume. The default writes
	// random bytes over the whole data area, which is what VeraCrypt's full
	// format does (it encrypts random data under throw-away keys; random
	// bytes written directly are indistinguishable from that and cost no
	// cipher time).
	Quick bool
}

// resolve checks the options and names the chain and KDF row they select.
func (o CreateOptions) resolve() (chain, kdfVariant, error) {
	cname, kname := o.Cipher, o.KDF
	if cname == "" {
		cname = AES
	}
	if kname == "" {
		kname = SHA512
	}
	if o.PIM < 0 || o.PIM > MaxPIM {
		return chain{}, kdfVariant{}, option("PIM %d outside 0..%d", o.PIM, MaxPIM)
	}
	for _, c := range chains {
		if c.name != cname {
			continue
		}
		for _, v := range kdfVariants {
			// RIPEMD-160 is not among VeraCrypt 1.26's PRFs (Crypto.h): such
			// volumes are readable by cryptsetup only, so it is not created.
			if v.kdf == kname && v.veracrypt && !v.boot && kname != RIPEMD160 {
				return c, v, nil
			}
		}
		return chain{}, kdfVariant{}, option("KDF %q cannot create a VeraCrypt header", kname)
	}
	return chain{}, kdfVariant{}, option("unknown cipher %q", cname)
}

// ReadWriterAt is what Create writes and reads back: an *os.File, or any
// random-access store.
type ReadWriterAt interface {
	io.ReaderAt
	io.WriterAt
}

type rwCloser struct{ ReadWriterAt }

func (r rwCloser) Close() error {
	if c, ok := r.ReadWriterAt.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Volume is a freshly created volume: a plaintext view of its data area.
// ReadAt and WriteAt are safe for concurrent use. A volume of size S has a
// data area of S-262144 bytes (Size).
type Volume struct {
	*Device
	w      io.WriterAt
	mu     sync.Mutex
	closed atomic.Bool
}

// Create writes a new VeraCrypt volume of size bytes to w: the primary
// header, the backup header at the end, random bytes in every reserved
// header area and in the area of the hidden volume's header (no hidden
// volume is created, and the area stays deniable), and, unless
// o.Quick, random bytes over the data area. There is no filesystem in the
// data area: it reads as noise until the caller writes to it through the
// returned Volume. The volume opens with Open or OpenFrom, VeraCrypt and
// cryptsetup, with password and o.Keyfiles, and with the PIM and KDF named
// in o (the cipher and KDF are not stored on disk).
//
// size must be a multiple of 512 between MinSize and MaxSize. Create does
// not extend w beyond what it writes: the backup area at the end sets the
// length of a file. Key material is zeroed where Go allows it (the
// password pool, the header keys, the master-key buffer on Close); the
// expanded cipher schedules inside the cipher libraries cannot be.
func Create(w ReadWriterAt, size int64, password []byte, o CreateOptions) (*Volume, error) {
	c, v, err := o.resolve()
	if err != nil {
		return nil, err
	}
	if size < MinSize || size > MaxSize || size%sectorSize != 0 {
		return nil, option("size %d: need a multiple of %d in %d..%d", size, sectorSize, int64(MinSize), int64(MaxSize))
	}
	if len(password) == 0 && len(o.Keyfiles) == 0 {
		return nil, option("no password and no keyfile")
	}
	for i, kf := range o.Keyfiles {
		if len(kf) == 0 { // VeraCrypt's KeyFileProcess fails on an empty keyfile
			return nil, option("keyfile %d is empty", i)
		}
	}
	pool, ok := keyPool(password, o.Keyfiles, true)
	if !ok {
		return nil, option("password of %d bytes longer than the key pool", len(password))
	}
	defer clear(pool)

	h := &Header{
		VeraCrypt:  true,
		Version:    headerVersion,
		MinVersion: minProgram,
		VolumeSize: uint64(size) - 2*headerGroup,
		MKOffset:   headerGroup,
		SectorSize: sectorSize,
		KDF:        v.String(),
		Cipher:     c.name,
	}
	h.MKSize = h.VolumeSize
	if err := generateKeys(&h.keys, c); err != nil {
		clear(h.keys[:])
		return nil, err
	}

	// The two headers differ in salt only, so in their derived key: derive
	// them side by side.
	var hdrs [2][]byte
	var errs [2]error
	var wg sync.WaitGroup
	for i := range hdrs {
		if v.kdf == Argon2id { // 416 MiB to 1 GiB each: one at a time
			hdrs[i], errs[i] = sealHeader(h, c, v, pool, o.PIM)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			hdrs[i], errs[i] = sealHeader(h, c, v, pool, o.PIM)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs[0], errs[1]); err != nil {
		clear(h.keys[:])
		return nil, err
	}

	// Everything but the headers first, the headers last: a half-written
	// container never shows a header over a data area that is not there.
	// A store that can be resized (an *os.File) is cut to size, so that the
	// backup header lies at the end where VeraCrypt looks for it. The
	// first 512 bytes are overwritten with random bytes before anything
	// else, so an older header there cannot open the half-made volume.
	if t, ok := w.(interface{ Truncate(int64) error }); ok {
		if err := t.Truncate(size); err != nil {
			clear(h.keys[:])
			return nil, fmt.Errorf("veracrypt: size the container: %w", err)
		}
	}
	end := uint64(size)
	steps := []struct{ off, n uint64 }{
		{0, headerGroup},                 // the old header, reserved, and the hidden header area
		{end - headerGroup, headerGroup}, // the backup's, reserved and hidden backup areas
	}
	if !o.Quick {
		steps = append(steps, struct{ off, n uint64 }{headerGroup, h.VolumeSize})
	}
	for _, s := range steps {
		if err := fillRandom(w, s.off, s.n); err != nil {
			clear(h.keys[:])
			return nil, err
		}
	}
	// The backup first, the primary last: a volume that opens always has
	// its backup.
	for _, i := range []int{1, 0} {
		off := int64(i) * (size - headerGroup)
		if _, err := w.WriteAt(hdrs[i], off); err != nil {
			clear(h.keys[:])
			return nil, fmt.Errorf("veracrypt: write header at %d: %w", off, err)
		}
	}
	// The header was built from fields newDevice accepts, so it cannot fail.
	d, _ := newDevice(rwCloser{w}, size, h, false, false)
	return &Volume{Device: d, w: w}, nil
}

// CreateFile creates the file at path (it must not exist; mode 0600) and
// writes a volume of size bytes into it. Close the Volume to close the file.
func CreateFile(path string, size int64, password []byte, o CreateOptions) (*Volume, error) {
	if _, _, err := o.resolve(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("veracrypt: %w", err)
	}
	v, err := Create(f, size, password, o)
	if err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return v, nil
}

// generateKeys fills the 256-byte master key area with random bytes (VeraCrypt
// randomises only the chain's keys and leaves the rest of the area as it
// was; random bytes there are valid too, the area is covered by one CRC-32),
// and refuses a weak XTS key: a link whose data key equals
// its tweak key (probability 2^-256).
func generateKeys(keys *[256]byte, c chain) error {
	if _, err := io.ReadFull(entropy, keys[:]); err != nil {
		return fmt.Errorf("veracrypt: random: %w", err)
	}
	for _, l := range c.links {
		if string(keys[l.keyOff:l.keyOff+32]) == string(keys[l.tweakOff:l.tweakOff+32]) {
			return errors.New("veracrypt: weak XTS key drawn")
		}
	}
	return nil
}

// sealHeader builds the 512 bytes of one header: a fresh salt, the fields
// of Spec offsets 64-255 with their CRC-32s, the master keys, and the 448
// bytes after the salt encrypted under the header key as one XTS data unit
// (Volumes.c: header key = PBKDF(password, salt), XTS data unit 0).
func sealHeader(h *Header, c chain, v kdfVariant, pool []byte, pim int) ([]byte, error) {
	out := make([]byte, headerSize)
	salt, d := out[:saltLen], out[saltLen:]
	if _, err := io.ReadFull(entropy, salt); err != nil {
		return nil, fmt.Errorf("veracrypt: random: %w", err)
	}
	copy(d, "VERA")
	binary.BigEndian.PutUint16(d[4:], h.Version)
	binary.BigEndian.PutUint16(d[6:], h.MinVersion)
	binary.BigEndian.PutUint32(d[8:], crc32.ChecksumIEEE(h.keys[:])) // bytes 256-511
	binary.BigEndian.PutUint64(d[28:], h.HiddenSize)
	binary.BigEndian.PutUint64(d[36:], h.VolumeSize)
	binary.BigEndian.PutUint64(d[44:], h.MKOffset)
	binary.BigEndian.PutUint64(d[52:], h.MKSize)
	binary.BigEndian.PutUint32(d[60:], h.Flags)
	binary.BigEndian.PutUint32(d[64:], h.SectorSize)
	binary.BigEndian.PutUint32(d[188:], crc32.ChecksumIEEE(d[:188])) // bytes 64-251
	copy(d[192:], h.keys[:])
	key := v.derive(pool, salt, pim)
	x := newXTSChain(c, key)
	clear(key)
	x.encryptUnit(d)
	return out, nil
}

// fillRandom writes n random bytes at off in 1 MiB pieces.
func fillRandom(w io.WriterAt, off, n uint64) error {
	buf := make([]byte, min(n, fillChunk))
	for n > 0 {
		b := buf[:min(n, uint64(len(buf)))]
		if _, err := io.ReadFull(entropy, b); err != nil {
			return fmt.Errorf("veracrypt: random: %w", err)
		}
		if _, err := w.WriteAt(b, int64(off)); err != nil {
			return fmt.Errorf("veracrypt: write at %d: %w", off, err)
		}
		off += uint64(len(b))
		n -= uint64(len(b))
	}
	return nil
}

// ReadAt reads the plaintext data area.
func (v *Volume) ReadAt(p []byte, off int64) (int, error) {
	if v.closed.Load() {
		return 0, ErrClosed
	}
	return v.Device.ReadAt(p, off)
}

// WriteAt writes plaintext into the data area, encrypting it. Writes that
// do not start or end on a 512-byte boundary read the partial sectors
// first. A write that does not fit inside the data area is refused whole.
func (v *Volume) WriteAt(p []byte, off int64) (int, error) {
	if v.closed.Load() {
		return 0, ErrClosed
	}
	if off < 0 || uint64(off) > v.size || uint64(len(p)) > v.size-uint64(off) {
		return 0, fmt.Errorf("%w: write of %d bytes at %d, data area of %d", ErrRange, len(p), off, v.size)
	}
	afterCheck()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed.Load() { // closed while this write waited
		return 0, ErrClosed
	}
	done := 0
	for done < len(p) {
		n, err := v.writePiece(p[done:min(len(p), done+fillChunk)], uint64(off)+uint64(done))
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

// writePiece writes at most fillChunk bytes inside the data area.
func (v *Volume) writePiece(p []byte, off uint64) (int, error) {
	first := off / sectorSize * sectorSize
	end := (off + uint64(len(p)) + sectorSize - 1) / sectorSize * sectorSize
	buf := make([]byte, end-first)
	edge := func(at uint64) error { // read-modify-write of a partial sector
		s := buf[at-first : at-first+sectorSize]
		if n, err := v.r.ReadAt(s, int64(v.dataOff+at)); n < len(s) {
			return fmt.Errorf("veracrypt: read at %d: %w", v.dataOff+at, err)
		}
		v.c.decryptSectors(s, v.ivOff+at/sectorSize)
		return nil
	}
	if first < off {
		if err := edge(first); err != nil {
			return 0, err
		}
	}
	if last := end - sectorSize; off+uint64(len(p)) < end && (last != first || first == off) {
		if err := edge(last); err != nil {
			return 0, err
		}
	}
	copy(buf[off-first:], p)
	v.c.encryptSectors(buf, v.ivOff+first/sectorSize)
	if _, err := v.w.WriteAt(buf, int64(v.dataOff+first)); err != nil {
		return 0, fmt.Errorf("veracrypt: write at %d: %w", v.dataOff+first, err)
	}
	return len(p), nil
}

// Close zeroes the master keys this Volume holds and closes the underlying
// store if it is an io.Closer. Further reads and writes fail with
// ErrClosed.
func (v *Volume) Close() error {
	if !v.closed.CompareAndSwap(false, true) {
		return nil
	}
	v.mu.Lock()
	clear(v.hdr.keys[:])
	v.mu.Unlock()
	return v.Device.Close()
}
