package veracrypt

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// OraclePassword is the passphrase of the volumes TestWriteOracleVolumes
// writes; it is written beside them (as pw.txt, without a newline) so that
// cryptsetup reads it with --key-file, never from a command line.
const oraclePassword = "oracle-passphrase-of-more-than-twenty-bytes" // VeraCrypt refuses a low PIM with fewer than 20

// TestWriteOracleVolumes writes one volume per cipher and KDF into the
// directory named by VERACRYPT_ORACLE_DIR, for VeraCrypt and cryptsetup to
// open: the independent oracles of the writer. It is skipped without the
// variable. The directory must be durable and outside any repository.
func TestWriteOracleVolumes(t *testing.T) {
	dir := os.Getenv("VERACRYPT_ORACLE_DIR")
	if dir == "" {
		t.Skip("VERACRYPT_ORACLE_DIR not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pw.txt"), []byte(oraclePassword), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		for _, k := range []KDF{SHA512, SHA256, BLAKE2s, Whirlpool, Streebog} {
			name := fmt.Sprintf("%s.%s.hc", c.name, k)
			path := filepath.Join(dir, name)
			os.Remove(path)
			v, err := CreateFile(path, 1<<20, []byte(oraclePassword), CreateOptions{Cipher: c.name, KDF: k, PIM: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestCryptsetupAccepts runs `cryptsetup tcryptDump --veracrypt` on every
// volume of VERACRYPT_ORACLE_DIR (see TestWriteOracleVolumes) and checks the
// cipher chain, the PBKDF2 hash, the mode, the key size, the version and the
// MK offset it reports against what was written. The passphrase reaches
// cryptsetup on its standard input, from pw.txt: tcryptDump's --key-file
// names TrueCrypt keyfiles, not the passphrase, and nothing secret goes
// through the command line. Skipped unless VERACRYPT_CRYPTSETUP names the
// cryptsetup binary (it dumps a header without root).
func TestCryptsetupAccepts(t *testing.T) {
	bin, dir := os.Getenv("VERACRYPT_CRYPTSETUP"), os.Getenv("VERACRYPT_ORACLE_DIR")
	if bin == "" || dir == "" {
		t.Skip("VERACRYPT_CRYPTSETUP and VERACRYPT_ORACLE_DIR not set")
	}
	for _, c := range chains {
		for _, k := range []KDF{SHA512, SHA256, BLAKE2s, Whirlpool, Streebog} {
			name := fmt.Sprintf("%s.%s.hc", c.name, k)
			t.Run(name, func(t *testing.T) {
				// tcrypt.c lists Kuznyechik and Streebog, but a cryptsetup built
				// on OpenSSL 3 (Ubuntu's 2.7.0: `cryptsetup benchmark -c
				// kuznyechik-xts-plain64` says "not available", PBKDF2-streebog-512
				// says N/A) cannot run them: it answers "No device header
				// detected". The reader's corpus of real VeraCrypt volumes covers
				// them instead.
				if k == Streebog || strings.Contains(string(c.name), "kuznyechik") {
					t.Skip("this cryptsetup's crypto backend lacks Kuznyechik and Streebog")
				}
				pw, err := os.Open(filepath.Join(dir, "pw.txt"))
				if err != nil {
					t.Fatal(err)
				}
				defer pw.Close()
				cmd := exec.Command(bin, "tcryptDump", "--veracrypt", "--veracrypt-pim=1", filepath.Join(dir, name))
				cmd.Stdin = pw
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
				got := parseDump(string(out))
				want := map[string]string{
					"Version":      "5",
					"Sector size":  "512",
					"MK offset":    "131072",
					"PBKDF2 hash":  string(k),
					"Cipher chain": string(c.name),
					"Cipher mode":  "xts-plain64",
					"MK bits":      fmt.Sprint(512 * len(c.links)),
				}
				for f, w := range want {
					if got[f] != w {
						t.Errorf("%s: cryptsetup says %q, written %q\n%s", f, got[f], w, out)
					}
				}
				t.Logf("cryptsetup: %s", strings.Join(strings.Fields(strings.ReplaceAll(string(out), "\n", ";")), " "))
			})
		}
	}
}

// parseDump reads tcryptDump's "Field:\t\tvalue" lines.
func parseDump(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func TestParseDump(t *testing.T) {
	m := parseDump("VERACRYPT header information for x\nVersion:       \t5\nMK bits:       \t512\nnoise\n")
	if m["Version"] != "5" || m["MK bits"] != "512" || len(m) != 2 {
		t.Fatal(m)
	}
}

// TestVeraCryptRestored checks what VeraCrypt 1.26.31 made of our volume:
// VERACRYPT_ORACLE_DIR/vc/restore.hc is aes.sha512.hc after
// `veracrypt --text --restore-headers` restored the EMBEDDED BACKUP header
// (so VeraCrypt decrypted our backup header and re-sealed it with a new
// salt into the primary slot). It must open with our reader, hold the same
// master keys, and decrypt the same data area. vc/vc64.hc was created by
// `veracrypt --text --create` (AES, SHA-512, PIM 1, no filesystem): its
// header fields are logged next to ours.
func TestVeraCryptRestored(t *testing.T) {
	dir := os.Getenv("VERACRYPT_ORACLE_DIR")
	if dir == "" {
		t.Skip("VERACRYPT_ORACLE_DIR not set")
	}
	o := Options{Password: []byte(oraclePassword), PIM: 1, KDF: SHA512, Cipher: AES}
	orig, err := Open(filepath.Join(dir, "aes.sha512.hc"), o)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := Open(filepath.Join(dir, "vc", "restore.hc"), o)
	if err != nil {
		t.Fatalf("our reader does not open what VeraCrypt restored: %v", err)
	}
	if orig.Header().keys != rest.Header().keys {
		t.Fatal("VeraCrypt restored different master keys")
	}
	a, b := make([]byte, 1<<16), make([]byte, 1<<16)
	orig.ReadAt(a, 0)
	rest.ReadAt(b, 0)
	if !bytes.Equal(a, b) {
		t.Fatal("data area differs")
	}
	raw1, _ := os.ReadFile(filepath.Join(dir, "aes.sha512.hc"))
	raw2, _ := os.ReadFile(filepath.Join(dir, "vc", "restore.hc"))
	if bytes.Equal(raw1[:512], raw2[:512]) {
		t.Fatal("primary header unchanged: nothing was restored")
	}
	ours, theirs := orig.Header(), mustOpenVC(t, dir, o).Header()
	f := func(h *Header) string {
		return fmt.Sprintf("version=%d minver=%#x vera=%v hidden=%d mkoff=%d flags=%d sector=%d", h.Version, h.MinVersion, h.VeraCrypt, h.HiddenSize, h.MKOffset, h.Flags, h.SectorSize)
	}
	t.Logf("ours:       %s", f(ours))
	t.Logf("veracrypt:  %s  volsize=%d mksize=%d", f(theirs), theirs.VolumeSize, theirs.MKSize)
	if f(ours) != f(theirs) {
		t.Errorf("header fields differ:\n%s\n%s", f(ours), f(theirs))
	}
}

func mustOpenVC(t *testing.T, dir string, o Options) *Device {
	d, err := Open(filepath.Join(dir, "vc", "vc64.hc"), o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
