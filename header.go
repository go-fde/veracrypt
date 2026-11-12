package veracrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	headerSize    = 512
	saltLen       = 64
	encLen        = 448 // the encrypted part, one XTS data unit
	sectorSize    = 512
	hiddenOff     = 65536
	hiddenOffOld  = -1536 // TrueCrypt before 6.0, from the end
	backupOff     = -131072
	hiddenBackOff = -65536
	defaultMKOff  = 512   // cryptsetup: mk_offset 0 means 512
	systemOff     = 31744 // TCRYPT_HDR_SYSTEM_OFFSET: sector 62 of the drive
)

// Errors. Every refusal of a malformed image wraps ErrCorrupt.
var (
	ErrWrongSecret = errors.New("veracrypt: no KDF and cipher open the header with this secret")
	ErrCorrupt     = errors.New("veracrypt: corrupt volume")
	ErrUnsupported = errors.New("veracrypt: unsupported volume")
	ErrLimit       = errors.New("veracrypt: limit exceeded")
	ErrReadOnly    = errors.New("veracrypt: read-only")
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

// Header is what the decrypted header records, big-endian on disk
// (cryptsetup TCRYPT_hdr_from_disk).
type Header struct {
	VeraCrypt  bool // magic "VERA"; false for TrueCrypt's "TRUE"
	Version    uint16
	MinVersion uint16
	HiddenSize uint64
	VolumeSize uint64
	MKOffset   uint64 // the data area's start on the device
	MKSize     uint64
	Flags      uint32
	SectorSize uint32
	KDF        string // the variant that opened it, e.g. pbkdf2-sha512-500000
	Cipher     Cipher
	keys       [256]byte
}

// System reports the system-encryption flag (bit 0).
func (h *Header) System() bool { return h.Flags&1 != 0 }

// parse decodes a decrypted 448-byte area and checks it the way
// cryptsetup does: the keys' CRC-32 always, the header's when version > 3.
func parse(d []byte) (*Header, error) {
	h := &Header{
		Version:    binary.BigEndian.Uint16(d[4:]),
		MinVersion: binary.BigEndian.Uint16(d[6:]),
		HiddenSize: binary.BigEndian.Uint64(d[28:]),
		VolumeSize: binary.BigEndian.Uint64(d[36:]),
		MKOffset:   binary.BigEndian.Uint64(d[44:]),
		MKSize:     binary.BigEndian.Uint64(d[52:]),
		Flags:      binary.BigEndian.Uint32(d[60:]),
		SectorSize: binary.BigEndian.Uint32(d[64:]),
	}
	h.VeraCrypt = string(d[:4]) == "VERA"
	if h.Version > 3 && crc32.ChecksumIEEE(d[:188]) != binary.BigEndian.Uint32(d[188:]) {
		return nil, corrupt("header CRC-32")
	}
	copy(h.keys[:], d[192:])
	if crc32.ChecksumIEEE(h.keys[:]) != binary.BigEndian.Uint32(d[8:]) {
		return nil, corrupt("master keys CRC-32")
	}
	if h.MKOffset == 0 {
		h.MKOffset = defaultMKOff
	}
	if h.SectorSize == 0 {
		h.SectorSize = sectorSize
	}
	return h, nil
}

// unlockHeader tries every allowed KDF on the header at off, and every
// allowed cipher chain on each derived key, until the magic appears
// (cryptsetup TCRYPT_init_hdr and TCRYPT_decrypt_hdr). The KDF is not
// stored on disk: trial is the format.
func unlockHeader(r io.ReaderAt, off int64, o *Options) (*Header, error) {
	raw := make([]byte, headerSize)
	if n, err := r.ReadAt(raw, off); n < headerSize {
		return nil, corrupt("read header at %d: %v", off, err)
	}
	salt := raw[:saltLen]
	pool, ok := keyPool(o.Password, o.Keyfiles, !o.TrueCryptOnly)
	if !ok {
		return nil, fmt.Errorf("%w: password longer than the key pool", ErrUnsupported)
	}
	lim := o.Limits.withDefaults()
	if o.PIM < 0 || o.PIM > lim.MaxPIM {
		return nil, fmt.Errorf("%w: PIM %d, limit %d", ErrLimit, o.PIM, lim.MaxPIM)
	}
	d := make([]byte, encLen)
	derivations, skipped := 0, false
	for _, v := range kdfVariants {
		if !o.allowsKDF(v) {
			continue
		}
		iter, mem := v.cost(o.PIM)
		if mem > lim.MaxArgon2MemKiB || (v.kdf != Argon2id && iter > lim.MaxIterations) {
			skipped = true
			continue
		}
		if derivations == lim.MaxKeyDerivations {
			return nil, fmt.Errorf("%w: more than %d key derivations", ErrLimit, lim.MaxKeyDerivations)
		}
		derivations++
		key := v.derive(pool, salt, o.PIM)
		for _, c := range chains {
			if o.Cipher != "" && c.name != o.Cipher {
				continue
			}
			x := newXTSChain(c, key)
			copy(d, raw[saltLen:])
			x.decryptUnit(d)
			magic := string(d[:4])
			if magic != "TRUE" && (magic != "VERA" || o.TrueCryptOnly) {
				continue
			}
			h, err := parse(d)
			if err != nil {
				return nil, err
			}
			h.KDF, h.Cipher = v.String(), c.name
			return h, nil
		}
	}
	if derivations == 0 && skipped {
		return nil, fmt.Errorf("%w: every allowed KDF costs more than the limits allow", ErrLimit)
	}
	return nil, ErrWrongSecret
}
