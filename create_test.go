package veracrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// store is a fixed-size random-access store that can be told to fail.
type store struct {
	b         []byte
	failWrite int // fail the Nth WriteAt (1-based); 0: never
	failRead  int // fail the Nth ReadAt; 0: never
	writes    int
	reads     int
	closed    bool

	failTrunc bool
	truncated int64
}

var errStore = errors.New("store failure")

func (s *store) ReadAt(p []byte, off int64) (int, error) {
	s.reads++
	if s.reads == s.failRead {
		return 0, errStore
	}
	if off < 0 || off >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *store) WriteAt(p []byte, off int64) (int, error) {
	s.writes++
	if s.writes == s.failWrite {
		return 0, errStore
	}
	if off < 0 || off+int64(len(p)) > int64(len(s.b)) {
		return 0, io.ErrShortWrite
	}
	return copy(s.b[off:], p), nil
}

func (s *store) Close() error { s.closed = true; return nil }

// Truncate makes store an io.Truncater-style store: it records the size.
func (s *store) Truncate(n int64) error {
	if s.failTrunc {
		return errStore
	}
	s.truncated = n
	return nil
}

func TestCreateTruncatesAndRefusesFailure(t *testing.T) {
	st := newStore(testSize)
	if _, err := Create(st, testSize, []byte("pw"), CreateOptions{PIM: 1}); err != nil || st.truncated != testSize {
		t.Fatal(err, st.truncated)
	}
	st = newStore(testSize)
	st.failTrunc = true
	if _, err := Create(st, testSize, []byte("pw"), CreateOptions{PIM: 1}); !errors.Is(err, errStore) || st.writes != 0 {
		t.Fatal(err)
	}
}

// A volume closed while a write waits for the lock refuses the write.
func TestWriteAfterCloseDuringWait(t *testing.T) {
	v, err := Create(newStore(testSize), testSize, []byte("pw"), CreateOptions{PIM: 1, Quick: true})
	if err != nil {
		t.Fatal(err)
	}
	afterCheck = func() { v.closed.Store(true) }
	defer func() { afterCheck = func() {} }()
	if n, err := v.WriteAt([]byte{1}, 0); !errors.Is(err, ErrClosed) || n != 0 {
		t.Fatal(n, err)
	}
}

// failingReader fails after n successful reads.
type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errStore
	}
	f.n--
	for i := range p {
		p[i] = byte(i*7 + f.n)
	}
	return len(p), nil
}

func withEntropy(t *testing.T, r io.Reader) {
	old := entropy
	entropy = r
	t.Cleanup(func() { entropy = old })
}

const testSize = MinSize + 8*sectorSize

func newStore(size int) *store { return &store{b: make([]byte, size)} }

func pattern(n, seed int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*131 + seed + i/512)
	}
	return p
}

// The round trip through the reader, every cipher against every KDF, with a
// low PIM.
func TestCreateRoundTripMatrix(t *testing.T) {
	kdfs := []KDF{SHA512, SHA256, BLAKE2s, Whirlpool, Streebog, Argon2id}
	for _, c := range chains {
		for _, k := range kdfs {
			t.Run(fmt.Sprintf("%s/%s", c.name, k), func(t *testing.T) {
				st := newStore(testSize)
				o := CreateOptions{Cipher: c.name, KDF: k, PIM: 1}
				v, err := Create(st, testSize, []byte("hunter2"), o)
				if err != nil {
					t.Fatal(err)
				}
				want := pattern(3000, int(c.name[0]))
				if n, err := v.WriteAt(want, 100); err != nil || n != len(want) {
					t.Fatalf("write: %d %v", n, err)
				}
				for _, backup := range []bool{false, true} {
					d, err := OpenFrom(memDev{bytes.NewReader(st.b)}, testSize,
						Options{Password: []byte("hunter2"), PIM: 1, Backup: backup})
					if err != nil {
						t.Fatalf("backup=%v: %v", backup, err)
					}
					h := d.Header()
					if !h.VeraCrypt || h.Cipher != c.name || h.Version != 5 || h.MinVersion != 0x010b ||
						h.MKOffset != 131072 || h.VolumeSize != uint64(testSize-262144) || h.MKSize != h.VolumeSize ||
						h.SectorSize != 512 || h.HiddenSize != 0 || h.Flags != 0 || d.Size() != int64(testSize-262144) {
						t.Fatalf("header %+v", h)
					}
					got := make([]byte, len(want))
					if _, err := d.ReadAt(got, 100); err != nil || !bytes.Equal(got, want) {
						t.Fatalf("backup=%v: read back: %v", backup, err)
					}
				}
				if _, err := OpenFrom(memDev{bytes.NewReader(st.b)}, testSize,
					Options{Password: []byte("wrong"), PIM: 1, Cipher: c.name, KDF: k}); !errors.Is(err, ErrWrongSecret) {
					t.Fatalf("wrong password: %v", err)
				}
			})
		}
	}
}

func TestCreateDefaultsAndLayout(t *testing.T) {
	size := 1 << 20
	st := newStore(size)
	v, err := Create(st, int64(size), []byte("pw"), CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if h := v.Header(); h.Cipher != AES || h.KDF != "pbkdf2-sha512-500000" || v.Size() != int64(size-262144) {
		t.Fatalf("%+v", h)
	}
	// Two different salts, one master key.
	p, b := st.b[:saltLen], st.b[size-headerGroup:size-headerGroup+saltLen]
	if bytes.Equal(p, b) {
		t.Fatal("primary and backup share a salt")
	}
	dp, err := OpenFrom(memDev{bytes.NewReader(st.b)}, int64(size), Options{Password: []byte("pw")})
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenFrom(memDev{bytes.NewReader(st.b)}, int64(size), Options{Password: []byte("pw"), Backup: true})
	if err != nil {
		t.Fatal(err)
	}
	if dp.Header().keys != db.Header().keys || dp.Header().keys != v.Header().keys {
		t.Fatal("primary and backup disagree on the master keys")
	}
	// No hidden volume: neither hidden header opens, and every reserved
	// area and the data area is not zero.
	for _, o := range []Options{{Hidden: true}, {Hidden: true, Backup: true}} {
		o.Password = []byte("pw")
		o.KDF, o.Cipher = SHA512, AES
		if _, err := OpenFrom(memDev{bytes.NewReader(st.b)}, int64(size), o); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("hidden %+v: %v", o, err)
		}
	}
	for _, r := range [][2]int{{512, headerGroup}, {size - headerGroup + 512, size}, {headerGroup, size - headerGroup}} {
		if zeros := countZeros(st.b[r[0]:r[1]]); zeros > (r[1]-r[0])/100 {
			t.Fatalf("%v holds %d zero bytes of %d: not random", r, zeros, r[1]-r[0])
		}
	}
}

func countZeros(b []byte) (n int) {
	for _, c := range b {
		if c == 0 {
			n++
		}
	}
	return n
}

func TestCreateQuick(t *testing.T) {
	size := 1 << 20
	st := newStore(size)
	if _, err := Create(st, int64(size), []byte("pw"), CreateOptions{Quick: true, PIM: 1}); err != nil {
		t.Fatal(err)
	}
	if countZeros(st.b[headerGroup:size-headerGroup]) != size-2*headerGroup {
		t.Fatal("quick format wrote into the data area")
	}
	if countZeros(st.b[512:headerGroup]) > 1000 {
		t.Fatal("quick format left the reserved header area zero")
	}
}

func TestCreateKeyfiles(t *testing.T) {
	st := newStore(testSize)
	kf := [][]byte{pattern(100, 1), pattern(5000, 2)}
	if _, err := Create(st, testSize, nil, CreateOptions{Keyfiles: kf, PIM: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFrom(memDev{bytes.NewReader(st.b)}, testSize, Options{Keyfiles: kf, PIM: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFrom(memDev{bytes.NewReader(st.b)}, testSize, Options{Password: []byte("x"), PIM: 1}); !errors.Is(err, ErrWrongSecret) {
		t.Fatal(err)
	}
}

func TestCreateRefusals(t *testing.T) {
	long := bytes.Repeat([]byte("p"), 129)
	for name, c := range map[string]struct {
		size int64
		pw   []byte
		o    CreateOptions
	}{
		"cipher":      {testSize, []byte("pw"), CreateOptions{Cipher: "rot13"}},
		"kdf":         {testSize, []byte("pw"), CreateOptions{KDF: "md5"}},
		"legacy kdf":  {testSize, []byte("pw"), CreateOptions{KDF: SHA1}},
		"ripemd":      {testSize, []byte("pw"), CreateOptions{KDF: RIPEMD160}},
		"empty kf":    {testSize, []byte("pw"), CreateOptions{Keyfiles: [][]byte{{1}, {}}}},
		"pim neg":     {testSize, []byte("pw"), CreateOptions{PIM: -1}},
		"pim big":     {testSize, []byte("pw"), CreateOptions{PIM: MaxPIM + 1}},
		"small":       {MinSize - 512, []byte("pw"), CreateOptions{}},
		"unaligned":   {testSize + 1, []byte("pw"), CreateOptions{}},
		"huge":        {MaxSize + 512, []byte("pw"), CreateOptions{}},
		"negative":    {-512, []byte("pw"), CreateOptions{}},
		"no secret":   {testSize, nil, CreateOptions{}},
		"long secret": {testSize, long, CreateOptions{}},
	} {
		st := newStore(testSize)
		if _, err := Create(st, c.size, c.pw, c.o); !errors.Is(err, ErrOption) {
			t.Errorf("%s: %v", name, err)
		}
		if st.writes != 0 {
			t.Errorf("%s: wrote before refusing", name)
		}
	}
}

// Every random read and every write may fail, and each failure is reported.
func TestCreateFailures(t *testing.T) {
	for n := 0; n < 12; n++ {
		withEntropy(t, &failingReader{n: n})
		_, err := Create(newStore(testSize), testSize, []byte("pw"), CreateOptions{PIM: 1})
		if n < 6 {
			// keys, 2 salts, 3 fills (reserved, backup reserved, data)
			if !errors.Is(err, errStore) {
				t.Errorf("entropy fails after %d reads: %v", n, err)
			}
		}
	}
	withEntropy(t, &failingReader{n: 1 << 30})
	for n := 1; n <= 5; n++ {
		st := newStore(testSize)
		st.failWrite = n
		_, err := Create(st, testSize, []byte("pw"), CreateOptions{PIM: 1})
		if n <= 5 && !errors.Is(err, errStore) {
			t.Errorf("write %d fails: %v", n, err)
		}
	}
	// A constant source draws equal data and tweak keys.
	withEntropy(t, zeroReader{})
	if _, err := Create(newStore(testSize), testSize, []byte("pw"), CreateOptions{}); err == nil {
		t.Fatal("weak key accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestVolumeWriteAt(t *testing.T) {
	size := MinSize + 3<<20 + 512
	st := newStore(size)
	v, err := Create(st, int64(size), []byte("pw"), CreateOptions{Quick: true, Cipher: SerpentTwofishAES, PIM: 1})
	if err != nil {
		t.Fatal(err)
	}
	vs := int(v.Size())
	model := make([]byte, vs)
	check := func() {
		t.Helper()
		got := make([]byte, vs)
		if _, err := v.ReadAt(got, 0); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		// The zero ciphertext decrypts to noise where nothing was written,
		// so compare only what the model has written.
		for i := range model {
			if model[i] != 0 && got[i] != model[i] {
				t.Fatalf("byte %d: %d != %d", i, got[i], model[i])
			}
		}
	}
	for i, c := range []struct{ off, n int }{
		{0, 512},            // aligned sector
		{512, 1024},         // aligned run
		{1, 1},              // inside a sector
		{1000, 100},         // across a sector boundary
		{2047, 3},           // ends mid-sector, starts mid-sector
		{5000, 2<<20 + 777}, // over the 1 MiB piece size, both edges partial
		{vs - 600, 600},     // up to the very end
		{vs, 0},             // empty at the end
	} {
		p := pattern(c.n, i+1)
		for j := range p {
			if p[j] == 0 {
				p[j] = 1
			}
		}
		n, err := v.WriteAt(p, int64(c.off))
		if err != nil || n != c.n {
			t.Fatalf("%v: %d %v", c, n, err)
		}
		copy(model[c.off:], p)
		check()
	}
	// The reader opens the same bytes.
	d, err := OpenFrom(memDev{bytes.NewReader(st.b)}, int64(size), Options{Password: []byte("pw"), PIM: 1})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2000)
	if _, err := d.ReadAt(got, 1000); err != nil || !bytes.Equal(got[:100], model[1000:1100]) {
		t.Fatal("reader disagrees", err)
	}
	for _, c := range []struct{ off, n int }{{-1, 1}, {vs + 1, 0}, {vs - 1, 2}, {0, vs + 1}} {
		if n, err := v.WriteAt(make([]byte, c.n), int64(c.off)); !errors.Is(err, ErrRange) || n != 0 {
			t.Errorf("%v: %d %v", c, n, err)
		}
	}
}

func TestVolumeWriteFailures(t *testing.T) {
	size := MinSize + 3*sectorSize
	// A partial first sector and last sector need two reads; a read fails.
	for failRead := 1; failRead <= 2; failRead++ {
		st := newStore(size)
		v, err := Create(st, int64(size), []byte("pw"), CreateOptions{Quick: true})
		if err != nil {
			t.Fatal(err)
		}
		st.reads, st.failRead = 0, failRead
		if n, err := v.WriteAt(make([]byte, 600), 10); !errors.Is(err, errStore) || n != 0 {
			t.Errorf("read %d: %d %v", failRead, n, err)
		}
	}
	// A write fails: the very first piece, and a later one.
	for _, c := range []struct{ off, n, fail, wrote int }{{0, 512, 1, 0}, {0, 2<<20 + 1, 2, fillChunk}} {
		sz := MinSize + 3<<20
		st := newStore(sz)
		v, err := Create(st, int64(sz), []byte("pw"), CreateOptions{Quick: true})
		if err != nil {
			t.Fatal(err)
		}
		st.writes, st.failWrite = 0, c.fail
		if n, err := v.WriteAt(make([]byte, c.n), int64(c.off)); !errors.Is(err, errStore) || n != c.wrote {
			t.Errorf("%+v: %d %v", c, n, err)
		}
	}
}

func TestVolumeClose(t *testing.T) {
	st := newStore(testSize)
	v, err := Create(st, testSize, []byte("pw"), CreateOptions{PIM: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil || !st.closed {
		t.Fatal(err, st.closed)
	}
	if v.hdr.keys != [256]byte{} {
		t.Fatal("master keys not zeroed")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := v.WriteAt(make([]byte, 1), 0); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	// A store that is not an io.Closer: Close succeeds.
	v2, err := Create(noClose{newStore(testSize)}, testSize, []byte("pw"), CreateOptions{PIM: 1})
	if err != nil || v2.Close() != nil {
		t.Fatal(err)
	}
}

type noClose struct{ s *store }

func (n noClose) ReadAt(p []byte, o int64) (int, error)  { return n.s.ReadAt(p, o) }
func (n noClose) WriteAt(p []byte, o int64) (int, error) { return n.s.WriteAt(p, o) }

func TestCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.hc")
	v, err := CreateFile(path, testSize, []byte("pw"), CreateOptions{PIM: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := pattern(2000, 9)
	if _, err := v.WriteAt(want, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Size() != testSize || st.Mode().Perm() != 0o600 {
		t.Fatal(err, st)
	}
	d, err := Open(path, Options{Password: []byte("pw"), PIM: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	got := make([]byte, len(want))
	if _, err := d.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatal("read back", err)
	}
	if _, err := CreateFile(path, testSize, []byte("pw"), CreateOptions{}); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if _, err := CreateFile(path+"x", testSize, []byte("pw"), CreateOptions{Cipher: "rot13"}); !errors.Is(err, ErrOption) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + "x"); err == nil {
		t.Fatal("file made for refused options")
	}
	bad := filepath.Join(t.TempDir(), "bad.hc")
	if _, err := CreateFile(bad, 100, []byte("pw"), CreateOptions{}); !errors.Is(err, ErrOption) {
		t.Fatal(err)
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("failed creation left its file")
	}
}

// FuzzCreate feeds arbitrary options and sizes: no input may panic, a
// refusal wraps ErrOption, and what Create writes opens with the reader.
func FuzzCreate(f *testing.F) {
	f.Add("aes", "sha512", 1, int64(testSize), []byte("pw"))
	f.Add("serpent-twofish-aes", "whirlpool", 0, int64(MinSize), []byte("p"))
	f.Add("rot13", "", -5, int64(7), []byte(""))
	f.Add("", "argon2id", MaxPIM+1, int64(1)<<62, []byte("x"))
	f.Fuzz(func(t *testing.T, cipher, kdf string, pim int, size int64, pw []byte) {
		o := CreateOptions{Cipher: Cipher(cipher), KDF: KDF(kdf), PIM: pim, Quick: true}
		_, _, rerr := o.resolve()
		if rerr != nil && !errors.Is(rerr, ErrOption) {
			t.Fatalf("unclassified: %v", rerr)
		}
		// Create only what is cheap: a small container, a tiny PIM, no
		// Argon2id (64 MiB per header).
		badSize := size < MinSize || size > MaxSize || size%sectorSize != 0
		if rerr != nil || badSize {
			if _, err := Create(newStore(0), size, pw, o); !errors.Is(err, ErrOption) {
				t.Fatalf("not refused: %v", err)
			}
			return
		}
		if size > 1<<20 || pim < 1 || pim > 2 || o.KDF == Argon2id {
			return
		}
		st := newStore(int(size))
		v, err := Create(st, size, pw, o)
		if err != nil {
			if !errors.Is(err, ErrOption) {
				t.Fatalf("unclassified: %v", err)
			}
			return
		}
		defer v.Close()
		if _, err := OpenFrom(memDev{bytes.NewReader(st.b)}, size, Options{Password: pw, PIM: pim, Cipher: o.Cipher, KDF: o.KDF}); err != nil {
			t.Fatalf("created volume does not open: %v", err)
		}
	})
}

// BenchmarkCreate64MiB creates a 64 MiB file container (AES, SHA-512, PIM 1,
// full random fill), the command `veracrypt --text --create --size=64M
// --encryption=AES --hash=SHA-512 --pim=1 --filesystem=none` performs.
func BenchmarkCreate64MiB(b *testing.B) {
	dir := b.TempDir()
	b.SetBytes(64 << 20)
	for i := 0; i < b.N; i++ {
		v, err := CreateFile(filepath.Join(dir, fmt.Sprint(i)), 64<<20, []byte("oracle-passphrase-of-more-than-twenty-bytes"), CreateOptions{PIM: 1})
		if err != nil {
			b.Fatal(err)
		}
		v.Close()
	}
}
