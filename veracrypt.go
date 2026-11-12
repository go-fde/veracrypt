// Package veracrypt reads VeraCrypt and TrueCrypt volumes in pure Go.
//
// A VeraCrypt header is indistinguishable from random bytes: nothing on
// disk names the key derivation or the cipher. Opening a volume therefore
// tries every allowed KDF on the password (and keyfiles), and every allowed
// cipher chain on each derived key, until the decrypted header starts with
// "VERA" (or TrueCrypt's "TRUE") and its CRC-32s match, as cryptsetup's
// tcrypt support does. Naming the KDF and the cipher in Options skips the
// others, which matters: one KDF costs about half a second.
//
//	dev, err := veracrypt.Open("volume.hc", veracrypt.Options{Password: []byte("pw")})
//
// The decrypted volume starts at its filesystem's first byte. This version
// reads AES and Twofish (and VeraCrypt's AES-Twofish cascade) in XTS mode,
// with PBKDF2 over SHA-512, SHA-256, BLAKE2s-256 or RIPEMD-160, or Argon2id;
// PIM, keyfiles, hidden volumes and backup headers, and system encryption
// (Options.System: an encrypted boot drive or system partition, header at
// byte 31744, including VeraCrypt's boot KDF rows; not a hidden operating
// system). It does not write.
//
// Untrusted images: the trial costs as much as the caller allows; Limits
// bounds the number of key derivations, the PBKDF2 iterations and the
// Argon2id memory a PIM can ask for, and refuses before deriving.
package veracrypt

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Limits bounds the work an open may do. Zero fields take the defaults.
type Limits struct {
	// MaxKeyDerivations is how many KDFs may run; default: all of them.
	MaxKeyDerivations int
	// MaxPIM bounds the PIM; default 2000 (2,015,000 PBKDF2 iterations).
	MaxPIM int
	// MaxIterations bounds the PBKDF2 iterations of one derivation;
	// default 2,015,000.
	MaxIterations int
	// MaxArgon2MemKiB bounds Argon2id's memory; default 1 GiB, the most a
	// VeraCrypt PIM asks for.
	MaxArgon2MemKiB uint32
}

func (l Limits) withDefaults() Limits {
	if l.MaxKeyDerivations == 0 {
		l.MaxKeyDerivations = len(kdfVariants)
	}
	if l.MaxPIM == 0 {
		l.MaxPIM = 2000
	}
	if l.MaxIterations == 0 {
		l.MaxIterations = 15000 + 1000*2000
	}
	if l.MaxArgon2MemKiB == 0 {
		l.MaxArgon2MemKiB = 1 << 20
	}
	return l
}

// Options says how to open a volume.
type Options struct {
	Password []byte
	// Keyfiles are the contents of the keyfiles, in the order VeraCrypt
	// was given them; only the first MiB of each counts.
	Keyfiles [][]byte
	// PIM is VeraCrypt's Personal Iterations Multiplier; 0 is the
	// default. A non-zero PIM tries only VeraCrypt KDFs.
	PIM int
	// KDF and Cipher, when set, are the only ones tried.
	KDF    KDF
	Cipher Cipher
	// Hidden opens the hidden volume (its header at 64 KiB).
	Hidden bool
	// Backup reads the backup header at the end of the device instead.
	Backup bool
	// System opens a system-encryption volume (an encrypted boot drive or
	// system partition): the header is at byte 31744 of the whole drive
	// (cryptsetup's tcrypt --tcrypt-system), VeraCrypt's boot KDF rows are
	// tried as well, and the header's system flag must be set. The device
	// is the whole drive, or an image of it (an image of the partition
	// alone has no header to read). ReadAt offsets are relative to the
	// start of the encrypted area, which is Header().MKOffset on the drive:
	// for an encrypted partition, its first byte, so offset 0 is its
	// filesystem; for a whole-drive encryption, sector 63 or later, before
	// the first partition, so a partition starting at sector S is at
	// offset S*512 - MKOffset (the MBR and boot loader in front of the
	// area are not encrypted and not part of the Device). Not combinable
	// with Hidden or Backup, and a hidden operating system is refused.
	System bool
	// TrueCryptOnly refuses VeraCrypt's "VERA" volumes and KDFs.
	TrueCryptOnly bool
	// Legacy also tries TrueCrypt's oldest KDF (PBKDF2-SHA-1).
	Legacy bool
	Limits Limits
}

func (o *Options) allowsKDF(v kdfVariant) bool {
	switch {
	case o.KDF != "" && v.kdf != o.KDF:
		return false
	case v.legacy && !o.Legacy:
		return false
	case v.veracrypt && o.TrueCryptOnly:
		return false
	case o.PIM != 0 && !v.veracrypt:
		return false
	case v.boot && !o.System:
		return false
	}
	return true
}

// ReadAtCloser is what OpenFrom reads.
type ReadAtCloser interface {
	io.ReaderAt
	io.Closer
}

// Device is an unlocked volume. ReadAt is safe for concurrent use.
type Device struct {
	r       ReadAtCloser
	hdr     *Header
	c       *xtsChain
	dataOff uint64 // where the data area starts on the device
	ivOff   uint64 // the tweak of its first sector
	size    uint64
}

// fileSize is replaceable so that a test can make it fail.
var fileSize = func(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Open opens the volume at path read-only.
func Open(path string, o Options) (*Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("veracrypt: %w", err)
	}
	size, err := fileSize(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("veracrypt: %w", err)
	}
	d, err := OpenFrom(f, size, o)
	if err != nil {
		f.Close()
		return nil, err
	}
	return d, nil
}

// OpenFrom unlocks the volume of size bytes in r. Close on the returned
// Device closes r.
func OpenFrom(r ReadAtCloser, size int64, o Options) (*Device, error) {
	if size < headerSize {
		return nil, corrupt("a device of %d bytes holds no header", size)
	}
	// Where the header may be, in the order cryptsetup's TCRYPT_read_phdr
	// tries them; a position outside the device is not tried.
	var offs []int64
	switch {
	case o.System && (o.Hidden || o.Backup):
		// VeraCrypt keeps no backup of the system header on the drive, and a
		// hidden operating system is a different layout (see newDevice).
		return nil, fmt.Errorf("%w: System with Hidden or Backup", ErrUnsupported)
	case o.System:
		offs = []int64{systemOff}
	case o.Hidden && o.Backup:
		offs = []int64{size + hiddenBackOff}
	case o.Hidden:
		// TrueCrypt before 6.0 kept the hidden header 1536 bytes from the end.
		offs = []int64{hiddenOff, size + hiddenOffOld}
	case o.Backup:
		offs = []int64{size + backupOff}
	default:
		offs = []int64{0}
	}
	err := error(corrupt("no header position fits a device of %d bytes", size))
	for _, off := range offs {
		if off < 0 || off+headerSize > size {
			continue
		}
		var h *Header
		h, err = unlockHeader(r, off, &o)
		if err == nil {
			return newDevice(r, size, h, o.Hidden, o.System)
		}
		if !errors.Is(err, ErrWrongSecret) {
			return nil, err
		}
	}
	return nil, err
}

// newDevice maps the data area of an unlocked header. For system encryption
// the header's MK offset is the byte where the encrypted area starts on the
// whole drive (the start of the encrypted partition, or sector 63 or later
// for a whole-drive encryption), its volume size the area's length, and the
// XTS tweak of its first sector is that offset / 512: the partition's
// position on the drive, as cryptsetup's iv_offset (tcrypt.c:801-856).
func newDevice(r ReadAtCloser, size int64, h *Header, hidden, system bool) (*Device, error) {
	switch {
	case system && !h.System():
		return nil, corrupt("the header at %d is not a system-encryption header (system flag unset)", systemOff)
	case h.System() && !system:
		return nil, fmt.Errorf("%w: system encryption (open the whole drive with Options.System)", ErrUnsupported)
	case system && h.HiddenSize != 0:
		return nil, fmt.Errorf("%w: hidden operating system", ErrUnsupported)
	case h.SectorSize != sectorSize:
		return nil, fmt.Errorf("%w: sector size %d", ErrUnsupported, h.SectorSize)
	case h.Version < 3:
		return nil, fmt.Errorf("%w: header version %d (TrueCrypt before 5.0)", ErrUnsupported, h.Version)
	}
	vsize, dataOff := h.VolumeSize, h.MKOffset
	if hidden {
		vsize = h.HiddenSize
		if h.Version == 3 { // TrueCrypt 5.x: the hidden volume ends 1536 bytes before the device does
			dataOff = uint64(size) - h.HiddenSize - 1536
		}
	}
	if system && dataOff < systemOff+headerSize {
		return nil, corrupt("system data area at %d overlaps the header at %d", dataOff, systemOff)
	}
	if vsize == 0 || vsize%sectorSize != 0 || dataOff%sectorSize != 0 ||
		dataOff > uint64(size) || uint64(size)-dataOff < vsize {
		return nil, corrupt("data area %d+%d outside a device of %d bytes or off 512-byte sectors", dataOff, vsize, size)
	}
	var c chain
	for _, ch := range chains {
		if ch.name == h.Cipher {
			c = ch
		}
	}
	x := newXTSChain(c, h.keys[:])
	return &Device{r: r, hdr: h, c: x, dataOff: dataOff, ivOff: dataOff / sectorSize, size: vsize}, nil
}

// Header returns what the volume header records.
func (d *Device) Header() *Header { return d.hdr }

// Size is the decrypted volume's length.
func (d *Device) Size() int64 { return int64(d.size) }

// Close closes the underlying reader.
func (d *Device) Close() error { return d.r.Close() }

// WriteAt is not implemented.
func (d *Device) WriteAt([]byte, int64) (int, error) { return 0, ErrReadOnly }

// ReadAt reads the decrypted volume at off: the whole-sector span with one
// read, decrypted in one pass per cipher.
func (d *Device) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("veracrypt: negative offset %d", off)
	}
	if uint64(off) >= d.size {
		return 0, io.EOF
	}
	want := len(p)
	if rest := d.size - uint64(off); uint64(want) > rest {
		want = int(rest)
	}
	first := uint64(off) / sectorSize * sectorSize
	end := (uint64(off) + uint64(want) + sectorSize - 1) / sectorSize * sectorSize
	var buf []byte
	if first == uint64(off) && end-first == uint64(want) {
		buf = p[:want]
	} else {
		buf = make([]byte, end-first)
	}
	if n, err := d.r.ReadAt(buf, int64(d.dataOff+first)); n < len(buf) {
		return 0, fmt.Errorf("veracrypt: read at %d: %w", d.dataOff+first, err)
	}
	d.c.decryptSectors(buf, d.ivOff+first/sectorSize)
	n := copy(p, buf[uint64(off)-first:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
