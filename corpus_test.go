package veracrypt

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-compressions/xz"
)

// The interoperability corpus is cryptsetup's tests/tcrypt-images.tar.xz:
// VeraCrypt and TrueCrypt volumes holding a FAT filesystem whose UUID is
// DEAD-BABE (CAFE-BABE in hidden volumes), checked by
// tests/tcrypt-compat-test. It is GPL-2.0+, so it is fetched, never
// committed: the test reads the archive named by TCRYPT_IMAGES and skips,
// loudly, without it.
const corpusEnv = "TCRYPT_IMAGES"

// Passwords from tcrypt-compat-test.
const (
	password       = "aaaaaaaaaaaa"
	passwordHidden = "bbbbbbbbbbbb"
	password72     = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffffffffffff"
	passwordPIM    = "cccccccccccccccccccc"
)

func loadCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	path := os.Getenv(corpusEnv)
	if path == "" {
		t.Skipf("%s is not set: the VeraCrypt/TrueCrypt-made images are not available, interoperability is NOT tested", corpusEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	xr, err := xz.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(xr)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeGNUSparse {
			continue
		}
		// System-encryption images (whole disks, up to 66 MiB) are not
		// supported by this version: not even read.
		if strings.Contains(h.Name, "/sys_") {
			continue
		}
		if h.Size > 64<<20 {
			t.Fatalf("%s declares %d bytes", h.Name, h.Size)
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name[strings.LastIndex(h.Name, "/")+1:]] = b
	}
}

// image is what a corpus file name says (tcrypt-compat-test get_PARAMS):
// prefix-hash-mode-ciphers[-hidden], ciphers in VeraCrypt's display order.
type image struct {
	name, prefix, hash, mode string
	ciphers                  []string
	hidden                   bool
}

func parseName(n string) image {
	parts := strings.Split(n, "-")
	im := image{name: n, prefix: parts[0], hash: parts[1], mode: parts[2], ciphers: parts[3:]}
	if last := im.ciphers[len(im.ciphers)-1]; last == "hidden" {
		im.hidden = true
		im.ciphers = im.ciphers[:len(im.ciphers)-1]
	}
	return im
}

// kdfOf maps the corpus hash names to this package's KDFs; false for one
// this version does not implement.
func kdfOf(h string) (KDF, bool) {
	switch h {
	case "sha512":
		return SHA512, true
	case "sha256":
		return SHA256, true
	case "blake2s":
		return BLAKE2s, true
	case "ripemd160":
		return RIPEMD160, true
	case "argon2id":
		return Argon2id, true
	case "whirlpool":
		return Whirlpool, true
	case "stribog512":
		return Streebog, true
	}
	return "", false
}

// ciphersOf lists the chains a corpus file name's cipher list can mean;
// empty for one this version does not build. The file names do not follow
// one order: most list VeraCrypt's display order (the reverse of
// cryptsetup's), but the Kuznyechik cascades list cryptsetup's own
// (vc_1-sha512-xts-kuznyechik-camellia is cryptsetup's
// "kuznyechik-camellia"). tcrypt-compat-test only passes the first field
// to -c as a hint, so it never relied on the order. Both orders can name a
// chain (serpent-twofish-aes and aes-twofish-serpent are each other's
// reverse), so the test tries each and lets the FAT UUID decide.
func ciphersOf(listed []string) []Cipher {
	rev := make([]string, len(listed))
	for i, c := range listed {
		rev[len(listed)-1-i] = c
	}
	var out []Cipher
	for _, name := range []Cipher{Cipher(strings.Join(rev, "-")), Cipher(strings.Join(listed, "-"))} {
		for _, c := range chains {
			if c.name == name && !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

func (im image) options(files map[string][]byte) Options {
	o := Options{Password: []byte(password)}
	switch {
	case strings.HasPrefix(im.prefix, "vcpim_1_"):
		o.Password = []byte(passwordPIM)
		o.PIM, _ = strconv.Atoi(strings.TrimPrefix(im.prefix, "vcpim_1_"))
	case strings.HasPrefix(im.prefix, "vck_") || strings.HasPrefix(im.prefix, "tck_"):
		o.Keyfiles = [][]byte{files["keyfile1"], files["keyfile2"]}
		switch {
		case strings.HasPrefix(im.prefix, "vck_1_nopw"):
			o.Password = nil
		case strings.HasPrefix(im.prefix, "vck_1_pw72"):
			o.Password = []byte(password72)
		}
	}
	if strings.HasPrefix(im.prefix, "tc") {
		o.TrueCryptOnly = true
	}
	return o
}

func TestCorpus(t *testing.T) {
	files := loadCorpus(t)
	opened, refused := 0, 0
	for name, img := range files {
		if !strings.HasPrefix(name, "tc") && !strings.HasPrefix(name, "vc") {
			continue
		}
		im := parseName(name)
		t.Run(name, func(t *testing.T) {
			kdf, kdfOK := kdfOf(im.hash)
			candidates := ciphersOf(im.ciphers)
			o := im.options(files)
			o.KDF = kdf
			dev := memDev{bytes.NewReader(img)}
			if !kdfOK || len(candidates) == 0 || im.mode != "xts" {
				o.KDF, o.Cipher = "", ""
				if kdfOK {
					o.KDF = kdf // keep the trial short where we can
				}
				_, err := OpenFrom(dev, int64(len(img)), o)
				if !errors.Is(err, ErrWrongSecret) && !errors.Is(err, ErrUnsupported) {
					t.Fatalf("unsupported %s-%s-%v opened or failed oddly: %v", im.hash, im.mode, im.ciphers, err)
				}
				refused++
				return
			}
			// The first candidate whose header decrypts is the chain; a
			// wrong one fails the header CRCs like a wrong password.
			for _, c := range candidates {
				o.Cipher = c
				if _, err := OpenFrom(dev, int64(len(img)), o); err == nil {
					break
				}
			}
			checkUUID(t, dev, int64(len(img)), o, "DEAD-BABE")
			if im.hidden {
				o.Hidden, o.Password = true, []byte(passwordHidden)
				checkUUID(t, dev, int64(len(img)), o, "CAFE-BABE")
			}
			opened++
		})
	}
	t.Logf("%d opened, %d refused as not supported yet", opened, refused)
	// The README and the docs publish these two numbers: every XTS image
	// opens, and the LRW/CBC ones (TrueCrypt before 5.0) are refused. A
	// change in either is a change in what this package reads, so it must
	// fail here, not drift silently from the published figure.
	const wantOpened, wantRefused = 62, 28
	if opened != wantOpened || refused != wantRefused {
		t.Fatalf("%d opened and %d refused, the README says %d and %d", opened, refused, wantOpened, wantRefused)
	}
}

// TestCorpusFullTrial opens a real image naming neither the KDF nor the
// cipher, as a user would. TestCorpus names both to stay fast, so without
// this the trial order over real images would never run in CI.
// vc_1-stribog512-xts-camellia is the worst case: Streebog is the last row
// of the KDF table, so every KDF runs before the one that matches (11 s on
// one M4 Max core, 23 s under load).
func TestCorpusFullTrial(t *testing.T) {
	files := loadCorpus(t)
	const name = "vc_1-stribog512-xts-camellia"
	img, ok := files[name]
	if !ok {
		t.Fatalf("%s is not in the corpus", name)
	}
	o := Options{Password: []byte(password)}
	checkUUID(t, memDev{bytes.NewReader(img)}, int64(len(img)), o, "DEAD-BABE")
}

func checkUUID(t *testing.T, dev memDev, size int64, o Options, want string) {
	t.Helper()
	d, err := OpenFrom(dev, size, o)
	if err != nil {
		t.Fatalf("open (hidden=%v): %v", o.Hidden, err)
	}
	boot := make([]byte, 512)
	if _, err := d.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	if got := fatUUID(boot); got != want {
		t.Fatalf("UUID %s, want %s (hidden=%v, %s %s)", got, want, o.Hidden, d.Header().KDF, d.Header().Cipher)
	}
}

// fatUUID is blkid's FAT volume ID: offset 67 for FAT32, 39 for FAT12/16.
func fatUUID(b []byte) string {
	off := 39
	if string(b[82:90]) == "FAT32   " {
		off = 67
	}
	id := strings.ToUpper(hex.EncodeToString([]byte{b[off+3], b[off+2], b[off+1], b[off]}))
	return id[:4] + "-" + id[4:]
}

type memDev struct{ *bytes.Reader }

func (memDev) Close() error { return nil }
