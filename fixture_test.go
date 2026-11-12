package veracrypt

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"
)

// fixtureEnv names where TestWriteFixture writes a small VeraCrypt volume,
// gzipped, for packages that stack on this one (go-fde/fde,
// go-filesystems/detect/fdereg) and cannot use this package's test writer:
// magic VERA, PBKDF2-SHA-512 at VeraCrypt's default 500,000 iterations,
// AES-XTS, password "fde", a 1 KiB volume whose bytes are
// byte(i*31 + i/512).
const fixtureEnv = "VERACRYPT_WRITE_FIXTURE"

func TestWriteFixture(t *testing.T) {
	path := os.Getenv(fixtureEnv)
	if path == "" {
		t.Skipf("%s is not set", fixtureEnv)
	}
	s := defaultVol(t)
	s.magic, s.variant, s.password = "VERA", variant(t, "pbkdf2-sha512-500000"), "fde"
	s.size, s.volSize = 131072+1024, 1024
	img, plain := buildVolume(t, s)
	d, err := openImg(t, img, Options{Password: []byte("fde"), KDF: SHA512})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, d), plain) {
		t.Fatal("the fixture does not read back")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(img)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
