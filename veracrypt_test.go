package veracrypt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openImg(t *testing.T, img []byte, o Options) (*Device, error) {
	t.Helper()
	return OpenFrom(memDev{bytes.NewReader(img)}, int64(len(img)), o)
}

func readAll(t *testing.T, d *Device) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(d, 0, d.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		spec func(*volSpec)
		opts func(*Options)
	}{
		{"truecrypt aes", func(*volSpec) {}, func(*Options) {}},
		{"twofish", func(s *volSpec) { s.cipher = Twofish }, func(*Options) {}},
		{"aes-twofish cascade", func(s *volSpec) { s.cipher = TwofishAES }, func(*Options) {}},
		{"serpent", func(s *volSpec) { s.cipher = Serpent }, func(*Options) {}},
		{"camellia-serpent cascade", func(s *volSpec) { s.cipher = SerpentCamellia }, func(*Options) {}},
		{"serpent-twofish-aes cascade", func(s *volSpec) { s.cipher = AESTwofishSerpent }, func(*Options) {}},
		{"veracrypt pim", func(s *volSpec) {
			s.magic, s.variant, s.pim = "VERA", kdfVariants[4], 1
		}, func(o *Options) { o.PIM, o.KDF = 1, SHA512 }},
		{"keyfiles", func(s *volSpec) {
			s.keyfiles = [][]byte{[]byte("one"), bytes.Repeat([]byte{9}, 300)}
		}, func(o *Options) { o.Keyfiles = [][]byte{[]byte("one"), bytes.Repeat([]byte{9}, 300)} }},
		{"legacy sha1", func(s *volSpec) { s.variant = kdfVariants[3] }, func(o *Options) { o.Legacy = true }},
		{"named kdf and cipher", func(*volSpec) {}, func(o *Options) { o.KDF, o.Cipher = SHA512, AES }},
		{"header mk_offset 0 means 512", func(s *volSpec) { s.mkOffset = 0; s.volSize = uint64(s.size) - 512 }, func(*Options) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := defaultVol()
			c.spec(&s)
			img, plain := buildVolume(t, s)
			if s.mkOffset == 0 {
				// the data area really starts at 512
				s.mkOffset = 512
				img, plain = buildVolume(t, s)
				s.mkOffset = 0
				img2, _ := buildVolume(t, s)
				copy(img[:512], img2[:512])
			}
			o := Options{Password: []byte(s.password), TrueCryptOnly: s.magic == "TRUE"}
			c.opts(&o)
			d, err := openImg(t, img, o)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if got := readAll(t, d); !bytes.Equal(got, plain) {
				t.Fatal("decrypted volume differs")
			}
			if d.Header().Cipher != s.cipher {
				t.Errorf("cipher %s", d.Header().Cipher)
			}
		})
	}
}

func TestHiddenAndBackup(t *testing.T) {
	s := defaultVol()
	s.size = 512 << 10
	s.headerOff = 65536
	s.mkOffset = 256 << 10
	s.volSize = 128 << 10
	s.hiddenSize = 128 << 10
	img, plain := buildVolume(t, s)
	d, err := openImg(t, img, Options{Password: []byte("pw"), Hidden: true, TrueCryptOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, d), plain) {
		t.Fatal("hidden volume differs")
	}
	// The same header as a backup: at -131072, and the hidden backup at -65536.
	for _, c := range []struct {
		off    int
		hidden bool
	}{{s.size - 131072, false}, {s.size - 65536, true}} {
		b := s
		b.headerOff = c.off
		img, plain := buildVolume(t, b)
		d, err := openImg(t, img, Options{Password: []byte("pw"), Backup: true, Hidden: c.hidden, TrueCryptOnly: true})
		if err != nil {
			t.Fatalf("backup at %d: %v", c.off, err)
		}
		if !bytes.Equal(readAll(t, d), plain) {
			t.Fatalf("backup at %d differs", c.off)
		}
	}
}

// TestTrial: without a named KDF or cipher, every allowed one is tried.
func TestTrial(t *testing.T) {
	s := defaultVol()
	s.cipher = TwofishAES
	img, plain := buildVolume(t, s)
	d, err := openImg(t, img, Options{Password: []byte("pw"), TrueCryptOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, d), plain) || d.Header().KDF != "pbkdf2-sha512-1000" {
		t.Fatalf("trial: %s", d.Header().KDF)
	}
	// One derivation allowed: the third variant is never reached.
	if _, err := openImg(t, img, Options{Password: []byte("pw"), TrueCryptOnly: true,
		Limits: Limits{MaxKeyDerivations: 1}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("derivation limit: %v", err)
	}
}

func TestLimits(t *testing.T) {
	img, _ := buildVolume(t, defaultVol())
	for name, o := range map[string]Options{
		"pim over the limit": {PIM: 1 << 30},
		"negative pim":       {PIM: -1},
		"iterations":         {KDF: SHA512, Limits: Limits{MaxIterations: 10}},
		"argon2 memory":      {KDF: Argon2id, Limits: Limits{MaxArgon2MemKiB: 1024}},
	} {
		o.Password = []byte("pw")
		if _, err := openImg(t, img, o); !errors.Is(err, ErrLimit) {
			t.Errorf("%s: %v, want ErrLimit", name, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name string
		spec func(*volSpec)
		img  func([]byte) []byte
		opts func(*Options)
		want error
		text string
	}{
		{name: "wrong password", opts: func(o *Options) { o.Password = []byte("nope") }, want: ErrWrongSecret},
		{name: "header CRC", spec: func(s *volSpec) { s.badHdrCRC = true }, want: ErrCorrupt, text: "header CRC"},
		{name: "keys CRC", spec: func(s *volSpec) { s.badKeyCRC = true }, want: ErrCorrupt, text: "keys CRC"},
		{name: "header CRC unchecked before version 4", spec: func(s *volSpec) { s.badHdrCRC, s.version = true, 3 }, want: nil},
		{name: "version 2", spec: func(s *volSpec) { s.version = 2 }, want: ErrUnsupported, text: "version 2"},
		{name: "system", spec: func(s *volSpec) { s.flags = 1 }, want: ErrUnsupported, text: "system"},
		{name: "sector size", spec: func(s *volSpec) { s.sectorSize = 4096 }, want: ErrUnsupported, text: "sector size"},
		{name: "data past the device", spec: func(s *volSpec) { s.volSize = 1 << 30 }, want: ErrCorrupt, text: "data area"},
		{name: "data unaligned", spec: func(s *volSpec) { s.volSize = 1000 }, want: ErrCorrupt, text: "data area"},
		{name: "tiny device", img: func(b []byte) []byte { return b[:100] }, want: ErrCorrupt, text: "holds no header"},
		{name: "veracrypt refused", spec: func(s *volSpec) { s.magic = "VERA" }, want: ErrWrongSecret},
		{name: "password too long", opts: func(o *Options) { o.Password = bytes.Repeat([]byte{1}, 65) }, want: ErrUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := defaultVol()
			if c.spec != nil {
				c.spec(&s)
			}
			img, _ := buildVolume(t, s)
			if c.img != nil {
				img = c.img(img)
			}
			o := Options{Password: []byte("pw"), TrueCryptOnly: true}
			if c.opts != nil {
				c.opts(&o)
			}
			_, err := openImg(t, img, o)
			if c.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			if c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Fatalf("%q does not say %q", err, c.text)
			}
		})
	}
}

func TestHeaderPositions(t *testing.T) {
	img, _ := buildVolume(t, defaultVol())
	// a device too small for a hidden header at 64 KiB or 1536 from the end
	small := img[:1024]
	if _, err := openImg(t, small, Options{Password: []byte("pw"), Hidden: true, Backup: true}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("no position fits: %v", err)
	}
	// a hidden header that is not there at either position
	if _, err := openImg(t, img, Options{Password: []byte("pw"), Hidden: true, TrueCryptOnly: true}); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("no hidden volume: %v", err)
	}
}

// failingDev claims a size but cannot be read.
type failingDev struct{}

func (failingDev) ReadAt([]byte, int64) (int, error) { return 0, errors.New("device error") }
func (failingDev) Close() error                      { return nil }

func TestUnreadableHeader(t *testing.T) {
	if _, err := OpenFrom(failingDev{}, 1<<20, Options{Password: []byte("pw")}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("%v", err)
	}
}

func TestReadAtEdges(t *testing.T) {
	img, plain := buildVolume(t, defaultVol())
	d, err := openImg(t, img, Options{Password: []byte("pw"), TrueCryptOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("negative offset")
	}
	if n, err := d.ReadAt(make([]byte, 1), d.Size()); n != 0 || err != io.EOF {
		t.Errorf("at the end: %d %v", n, err)
	}
	b := make([]byte, 700)
	if n, err := d.ReadAt(b, 3); err != nil || n != 700 || !bytes.Equal(b, plain[3:703]) {
		t.Errorf("unaligned: %d %v", n, err)
	}
	if n, err := d.ReadAt(b, d.Size()-10); n != 10 || err != io.EOF || !bytes.Equal(b[:10], plain[len(plain)-10:]) {
		t.Errorf("past the end: %d %v", n, err)
	}
	if _, err := d.WriteAt(b, 0); !errors.Is(err, ErrReadOnly) {
		t.Errorf("WriteAt: %v", err)
	}
	short := *d
	short.r = memDev{bytes.NewReader(img[:len(img)-512])}
	if _, err := short.ReadAt(make([]byte, 512), d.Size()-512); err == nil {
		t.Error("read past a truncated device")
	}
}

func TestOpenFile(t *testing.T) {
	img, plain := buildVolume(t, defaultVol())
	path := filepath.Join(t.TempDir(), "v.tc")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path, Options{Password: []byte("pw"), TrueCryptOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readAll(t, d), plain) {
		t.Error("differs")
	}
	if err := d.Close(); err != nil {
		t.Error(err)
	}
	if _, err := Open(path, Options{Password: []byte("nope"), TrueCryptOnly: true}); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), Options{}); err == nil {
		t.Error("missing file opened")
	}
	f, _ := os.Open(path)
	f.Close()
	if _, err := fileSize(f); err == nil {
		t.Error("Stat of a closed file")
	}
	saved := fileSize
	defer func() { fileSize = saved }()
	fileSize = func(*os.File) (int64, error) { return 0, errors.New("no size") }
	if _, err := Open(path, Options{}); err == nil || !strings.Contains(err.Error(), "no size") {
		t.Errorf("stat failure: %v", err)
	}
}

func TestKeyPool(t *testing.T) {
	if _, ok := keyPool(bytes.Repeat([]byte{1}, 65), nil, false); ok {
		t.Error("65 bytes fit a TrueCrypt pool")
	}
	if p, ok := keyPool(bytes.Repeat([]byte{1}, 65), nil, true); !ok || len(p) != 65 {
		t.Error("VeraCrypt takes up to 128 bytes")
	}
	big := bytes.Repeat([]byte{7}, keyfileMax+10)
	a, _ := keyPool(nil, [][]byte{big}, false)
	b, _ := keyPool(nil, [][]byte{big[:keyfileMax]}, false)
	if !bytes.Equal(a, b) {
		t.Error("more than the first MiB of a keyfile counted")
	}
}

func TestStrings(t *testing.T) {
	if s := kdfVariants[6].String(); s != "argon2id-t6-m425984KiB" {
		t.Error(s)
	}
	if s := kdfVariants[4].String(); s != "pbkdf2-sha512-500000" {
		t.Error(s)
	}
	if it, mem := kdfVariants[6].cost(40); it != 22 || mem != 1<<20 {
		t.Errorf("argon2id pim 40: %d %d", it, mem)
	}
	if it, mem := kdfVariants[6].cost(8); it != 5 || mem != 1024*(64+7*32) {
		t.Errorf("argon2id pim 8: %d %d", it, mem)
	}
	h := &Header{Flags: 1}
	if !h.System() {
		t.Error("system flag")
	}
}
