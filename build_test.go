package veracrypt

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// A test-only writer of VeraCrypt/TrueCrypt volumes, so that every refusal
// can be reached without the GPL corpus. The corpus test is what proves it
// writes what VeraCrypt and TrueCrypt write.

type volSpec struct {
	size       int
	magic      string // "VERA" or "TRUE"
	version    uint16
	variant    kdfVariant
	pim        int
	cipher     Cipher
	password   string
	keyfiles   [][]byte
	headerOff  int // where the header goes
	mkOffset   uint64
	volSize    uint64 // 0: everything after mkOffset
	hiddenSize uint64
	flags      uint32
	sectorSize uint32
	badHdrCRC  bool
	badKeyCRC  bool
}

// variant returns the kdfVariants row whose String() is name. Tests name
// rows instead of indexing them: inserting a row (as cryptsetup's table
// order requires) must not silently change which KDF a test uses. A
// missing name fails the calling test only, so the rest of the binary
// (TestStrings, which pins the table) still runs and says why.
func variant(tb testing.TB, name string) kdfVariant {
	tb.Helper()
	for _, v := range kdfVariants {
		if v.String() == name {
			return v
		}
	}
	tb.Fatalf("no KDF variant %s", name)
	return kdfVariant{}
}

func defaultVol(tb testing.TB) volSpec {
	return volSpec{
		size:     256 << 10,
		magic:    "TRUE",
		version:  5,
		variant:  variant(tb, "pbkdf2-sha512-1000"), // cheap
		cipher:   AES,
		password: "pw",
		mkOffset: 131072,
	}
}

var testKeys = func() [256]byte {
	var k [256]byte
	for i := range k {
		k[i] = byte(i*13 + 7)
	}
	return k
}()

func plainByte(i int) byte { return byte(i*31 + i/512) }

func chainNamed(t testing.TB, c Cipher) chain {
	for _, ch := range chains {
		if ch.name == c {
			return ch
		}
	}
	t.Fatalf("no chain %s", c)
	return chain{}
}

// encrypt is decrypt's inverse: the first link first.
func (x *xtsChain) encryptUnit(p []byte) {
	for _, l := range x.links {
		l.Encrypt(p, p, 0)
	}
}

func (x *xtsChain) encryptSectors(p []byte, first uint64) {
	for _, l := range x.links {
		l.EncryptSectors(p, p, sectorSize, first)
	}
}

// buildVolume writes s's header at s.headerOff and its data area at
// s.mkOffset, and returns the image and the plaintext of the data area.
func buildVolume(t testing.TB, s volSpec) (img, plain []byte) {
	t.Helper()
	img = make([]byte, s.size)
	vsize := s.volSize
	if vsize == 0 {
		vsize = uint64(s.size) - s.mkOffset
	}
	ss := s.sectorSize
	if ss == 0 {
		ss = sectorSize
	}
	d := make([]byte, encLen)
	copy(d, s.magic)
	binary.BigEndian.PutUint16(d[4:], s.version)
	binary.BigEndian.PutUint16(d[6:], 0x0700)
	binary.BigEndian.PutUint64(d[28:], s.hiddenSize)
	binary.BigEndian.PutUint64(d[36:], vsize)
	binary.BigEndian.PutUint64(d[44:], s.mkOffset)
	binary.BigEndian.PutUint64(d[52:], vsize)
	binary.BigEndian.PutUint32(d[60:], s.flags)
	binary.BigEndian.PutUint32(d[64:], ss)
	copy(d[192:], testKeys[:])
	kcrc := crc32.ChecksumIEEE(testKeys[:])
	if s.badKeyCRC {
		kcrc++
	}
	binary.BigEndian.PutUint32(d[8:], kcrc)
	hcrc := crc32.ChecksumIEEE(d[:188])
	if s.badHdrCRC {
		hcrc++
	}
	binary.BigEndian.PutUint32(d[188:], hcrc)

	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	pool, ok := keyPool([]byte(s.password), s.keyfiles, s.magic == "VERA")
	if !ok {
		t.Fatal("password too long for the test")
	}
	hk := s.variant.derive(pool, salt, s.pim)
	hx := newXTSChain(chainNamed(t, s.cipher), hk)
	hx.encryptUnit(d)

	// The data area first, the header last: a header written first would
	// be overwritten by a data area starting at 0.
	plain = make([]byte, vsize)
	for i := range plain {
		plain[i] = plainByte(i)
	}
	if s.mkOffset+vsize <= uint64(s.size) && vsize%sectorSize == 0 {
		dx := newXTSChain(chainNamed(t, s.cipher), testKeys[:])
		data := img[s.mkOffset : s.mkOffset+vsize]
		copy(data, plain)
		dx.encryptSectors(data, s.mkOffset/sectorSize)
	}
	copy(img[s.headerOff:], salt)
	copy(img[s.headerOff+saltLen:], d)
	return img, plain
}
