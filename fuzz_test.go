package veracrypt

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzParse feeds arbitrary "decrypted" header areas to parse and the
// device checks: an attacker who knows the password controls every byte
// after decryption, so these checks are the boundary. No input may panic,
// and a device that opens may only read inside the image.
func FuzzParse(f *testing.F) {
	s := defaultVol(f)
	img, _ := buildVolume(f, s)
	d, err := openImg(&testing.T{}, img, Options{Password: []byte("pw"), TrueCryptOnly: true})
	if err != nil {
		f.Fatal(err)
	}
	seed := make([]byte, encLen)
	copy(seed, "TRUE")
	f.Add(seed, int64(len(img)), false, false)
	f.Add(seed, int64(1<<20), true, false)
	f.Add(seed, int64(1<<20), false, true)
	_ = d
	f.Fuzz(func(t *testing.T, area []byte, size int64, hidden, system bool) {
		if len(area) != encLen || size < 0 || size > 1<<24 {
			return
		}
		h, err := parse(area)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("unclassified: %v", err)
			}
			return
		}
		h.Cipher = AES
		dev, err := newDevice(memDev{bytes.NewReader(make([]byte, size))}, size, h, hidden, system)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unclassified: %v", err)
			}
			return
		}
		if dev.dataOff+dev.size > uint64(size) {
			t.Fatalf("data area %d+%d past a device of %d", dev.dataOff, dev.size, size)
		}
		if system && dev.dataOff < systemOff+headerSize {
			t.Fatalf("system data area at %d over the header at %d", dev.dataOff, systemOff)
		}
		if _, err := io.Copy(io.Discard, io.NewSectionReader(dev, 0, dev.Size())); err != nil {
			t.Fatalf("read: %v", err)
		}
	})
}
