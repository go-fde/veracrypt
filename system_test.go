package veracrypt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// systemVol is a drive image with a system-encryption header at 31744 and an
// encrypted area at 64 KiB, as the builder writes it.
func systemVol(tb testing.TB, name string, pim int) volSpec {
	s := defaultVol(tb)
	s.magic, s.variant, s.pim = "VERA", variant(tb, name), pim
	s.headerOff, s.flags = systemOff, 1
	s.mkOffset, s.volSize = 64<<10, 128<<10
	return s
}

func TestSystemRoundTrip(t *testing.T) {
	cases := []struct {
		kdf KDF
		row string
	}{
		{SHA256, "pbkdf2-sha256-200000"},
		{BLAKE2s, "pbkdf2-blake2s-256-200000"},
		{RIPEMD160, "pbkdf2-ripemd160-327661"},
		{SHA512, "pbkdf2-sha512-500000"}, // EFI boot loaders use the ordinary rows
	}
	for _, c := range cases {
		t.Run(c.row, func(t *testing.T) {
			s := systemVol(t, c.row, 1) // PIM 1: 2048 iterations for a boot row
			img, plain := buildVolume(t, s)
			d, err := openImg(t, img, Options{Password: []byte("pw"), System: true, PIM: 1, KDF: c.kdf})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readAll(t, d), plain) {
				t.Fatal("decrypted area differs")
			}
			if !d.Header().System() || d.Header().KDF != c.row {
				t.Errorf("header: system=%v kdf=%s", d.Header().System(), d.Header().KDF)
			}
		})
	}
	t.Run("default cost of a boot row", func(t *testing.T) {
		s := systemVol(t, "pbkdf2-sha256-200000", 0)
		img, plain := buildVolume(t, s)
		d, err := openImg(t, img, Options{Password: []byte("pw"), System: true, KDF: SHA256})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(readAll(t, d), plain) {
			t.Fatal("differs")
		}
	})
	t.Run("trial reaches the boot row", func(t *testing.T) {
		s := systemVol(t, "pbkdf2-sha256-200000", 1)
		img, plain := buildVolume(t, s)
		d, err := openImg(t, img, Options{Password: []byte("pw"), System: true, PIM: 1})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(readAll(t, d), plain) {
			t.Fatal("differs")
		}
	})
	t.Run("whole drive, area from sector 63", func(t *testing.T) {
		s := systemVol(t, "pbkdf2-sha256-200000", 1)
		s.mkOffset, s.volSize = 63*512, 0
		img, plain := buildVolume(t, s)
		d, err := openImg(t, img, Options{Password: []byte("pw"), System: true, PIM: 1, KDF: SHA256})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(readAll(t, d), plain) || d.Size() != int64(len(img))-63*512 {
			t.Fatal("whole-drive area differs")
		}
	})
}

// A boot row is a system row only: an ordinary open never tries it.
func TestBootRowsOnlyForSystem(t *testing.T) {
	s := systemVol(t, "pbkdf2-sha256-200000", 1)
	s.headerOff, s.flags = 0, 0
	img, _ := buildVolume(t, s)
	if _, err := openImg(t, img, Options{Password: []byte("pw"), PIM: 1, KDF: SHA256}); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("a boot row opened an ordinary volume: %v", err)
	}
}

func TestSystemRefusals(t *testing.T) {
	cases := []struct {
		name string
		spec func(*volSpec)
		img  func([]byte) []byte
		opts func(*Options)
		want error
		text string
	}{
		{name: "hidden", opts: func(o *Options) { o.Hidden = true }, want: ErrUnsupported, text: "Hidden or Backup"},
		{name: "backup", opts: func(o *Options) { o.Backup = true }, want: ErrUnsupported, text: "Hidden or Backup"},
		{name: "flag unset", spec: func(s *volSpec) { s.flags = 0 }, want: ErrCorrupt, text: "system flag"},
		{name: "hidden operating system", spec: func(s *volSpec) { s.hiddenSize = 64 << 10 }, want: ErrUnsupported, text: "hidden operating system"},
		{name: "area over the header", spec: func(s *volSpec) { s.mkOffset, s.volSize = 31744, 64<<10 }, want: ErrCorrupt, text: "overlaps"},
		{name: "area at 0", spec: func(s *volSpec) { s.mkOffset, s.volSize = 0, 64<<10 }, want: ErrCorrupt, text: "overlaps"},
		{name: "area past the drive", spec: func(s *volSpec) { s.volSize = 1 << 30 }, want: ErrCorrupt, text: "data area"},
		{name: "area off sectors", spec: func(s *volSpec) { s.volSize = 1000 }, want: ErrCorrupt, text: "data area"},
		{name: "area start off sectors", spec: func(s *volSpec) { s.mkOffset = 65537 }, want: ErrCorrupt, text: "data area"},
		{name: "drive too short for the header", img: func(b []byte) []byte { return b[:31744+511] }, want: ErrCorrupt, text: "no header position"},
		{name: "wrong password", opts: func(o *Options) { o.Password = []byte("nope") }, want: ErrWrongSecret},
		{name: "wrong KDF", opts: func(o *Options) { o.KDF = BLAKE2s }, want: ErrWrongSecret},
		{name: "boot row over the iteration limit", opts: func(o *Options) { o.Limits.MaxIterations = 10 }, want: ErrLimit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := systemVol(t, "pbkdf2-sha256-200000", 1)
			if c.spec != nil {
				c.spec(&s)
			}
			img, _ := buildVolume(t, s)
			if c.img != nil {
				img = c.img(img)
			}
			o := Options{Password: []byte("pw"), System: true, PIM: 1, KDF: SHA256}
			if c.opts != nil {
				c.opts(&o)
			}
			_, err := openImg(t, img, o)
			if !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			if c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Fatalf("%q does not say %q", err, c.text)
			}
		})
	}
}

// A system header opened as an ordinary volume says how to open it.
func TestSystemHeaderWithoutOption(t *testing.T) {
	s := systemVol(t, "pbkdf2-sha512-500000", 1)
	s.headerOff = 0
	img, _ := buildVolume(t, s)
	_, err := openImg(t, img, Options{Password: []byte("pw"), PIM: 1, KDF: SHA512})
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "Options.System") {
		t.Fatalf("%v", err)
	}
}
