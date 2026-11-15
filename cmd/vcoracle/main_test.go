package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-fde/veracrypt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/xts"
)

const dump = "TCRYPT header information for x.hc\nCipher chain:  \taes\nCipher mode:   \txts-plain64\nPayload offset:\t256\nMK bits:       \t512\nMK dump:\t51 26 df 37 \n\t59 8e 57 6c \n"

func TestParseDump(t *testing.T) {
	chain, mk, payload, err := parseDump(dump)
	if err != nil || chain != "aes" || payload != 256 || !bytes.Equal(mk, []byte{0x51, 0x26, 0xdf, 0x37, 0x59, 0x8e, 0x57, 0x6c}) {
		t.Fatal(chain, mk, err)
	}
	for _, bad := range []string{"", "Cipher chain: aes\n", "MK dump:\tzz\n"} {
		if _, _, _, err := parseDump(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNonce(t *testing.T) {
	if n := nonce(0x0102); n[0] != 2 || n[1] != 1 || len(n) != 16 {
		t.Fatal(n)
	}
}

// aesOnly is a stand-in for Botan built on golang.org/x/crypto, which has
// AES-XTS and Argon2id and is not this repository's code.
func aesOnly() tools {
	return tools{
		dump: func(string) (string, error) {
			return "No device header detected with this passphrase.\n", errors.New("exit 2")
		},
		derive: func(k kdf, pass, salt []byte) ([]byte, error) {
			if k.name != veracrypt.Argon2id {
				return nil, errors.New("not in the stand-in")
			}
			return argon2.IDKey(pass, salt, 3, 64*1024, 1, 192), nil
		},
		xts: func(c string, key, n, data []byte, decrypt bool) ([]byte, error) {
			if c != "AES-256/XTS" {
				return nil, errors.New("not in the stand-in")
			}
			x, err := xts.NewCipher(aes.NewCipher, key)
			if err != nil {
				return nil, err
			}
			out := make([]byte, len(data))
			if decrypt {
				x.Decrypt(out, data, binary.LittleEndian.Uint64(n))
			} else {
				x.Encrypt(out, data, binary.LittleEndian.Uint64(n))
			}
			return out, nil
		},
	}
}

func chainIndex(t *testing.T, c veracrypt.Cipher) int {
	for i := range chains {
		if chains[i].name == c {
			return i
		}
	}
	t.Fatal("no chain", c)
	return 0
}

func TestCheckJudgesAESArgon2id(t *testing.T) {
	v := check(aesOnly(), t.TempDir(), []byte("a-passphrase-long-enough"), chainIndex(t, veracrypt.AES), kdf{veracrypt.Argon2id, ""})
	if v.status != "OK" || !strings.Contains(v.detail, "Botan") {
		t.Fatal(v)
	}
}

func TestCheckStatuses(t *testing.T) {
	pass := []byte("a-passphrase-long-enough")
	// A derive error is a FAIL whatever the KDF: no exemption hides it.
	for _, k := range []kdf{{veracrypt.Streebog, "Streebog-512"}, {veracrypt.SHA512, "SHA-512"}} {
		if v := check(aesOnly(), t.TempDir(), pass, chainIndex(t, veracrypt.AES), k); v.status != "FAIL" || !strings.Contains(v.detail, "derive") {
			t.Fatal(v)
		}
	}
	// Create refuses: a bad directory.
	if v := check(aesOnly(), "/nonexistent-dir", pass, 0, kdf{veracrypt.Argon2id, ""}); v.status != "FAIL" {
		t.Fatal(v)
	}
}

// The last link of a cascade is decrypted first, the first encrypted first,
// each keyed by its own offsets.
func TestXTSChainOrder(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i)
	}
	var calls []string
	tl := tools{xts: func(c string, k, n, data []byte, d bool) ([]byte, error) {
		calls = append(calls, fmt.Sprintf("%s:%d,%d", c, k[0], k[32]))
		return data, nil
	}}
	links := chains[chainIndex(t, veracrypt.SerpentTwofishAES)].links
	if _, err := xtsChain(tl, links, key, make([]byte, 512), nonce(0), true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, " "); got != "AES-256/XTS:64,160 Twofish/XTS:32,128 Serpent/XTS:0,96" {
		t.Fatal(got)
	}
	calls = nil
	xtsChain(tl, links, key, make([]byte, 512), nonce(0), false)
	if got := strings.Join(calls, " "); got != "Serpent/XTS:0,96 Twofish/XTS:32,128 AES-256/XTS:64,160" {
		t.Fatal(got)
	}
	if _, err := xtsChain(tl, links, key[:100], nil, nil, true); err == nil {
		t.Fatal("short key accepted")
	}
	boom := tools{xts: func(string, []byte, []byte, []byte, bool) ([]byte, error) { return nil, errors.New("boom") }}
	if _, err := xtsChain(boom, links, key, nil, nil, true); err == nil {
		t.Fatal("failure lost")
	}
}

func TestRunFailsWhenNothingIsJudged(t *testing.T) {
	tl := aesOnly()
	tl.derive = func(kdf, []byte, []byte) ([]byte, error) { return nil, errors.New("no") }
	var out bytes.Buffer
	if err := run(tl, t.TempDir(), []byte("a-passphrase-long-enough"), &out); err == nil {
		t.Fatal("a run in which nobody judged anything passed")
	}
	if !strings.Contains(out.String(), "failed") {
		t.Fatal(out.String())
	}
}

func TestRootRefusesWithoutEnv(t *testing.T) {
	t.Setenv("VCORACLE", "")
	var cmd *cobra.Command = RootCmd()
	cmd.SetArgs([]string{"--dir", t.TempDir(), "--passfile", "/nonexistent"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "VCORACLE=1") {
		t.Fatal(err)
	}
}

// Negative control: a header key that is not the volume's, and a header that
// was altered after sealing, are refused.
func TestOpenHeaderRefuses(t *testing.T) {
	tl := aesOnly()
	dir := t.TempDir()
	pass := []byte("a-passphrase-long-enough")
	v, err := veracrypt.CreateFile(dir+"/v.hc", 1<<20, pass, veracrypt.CreateOptions{KDF: veracrypt.Argon2id, PIM: pim})
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	raw, _ := os.ReadFile(dir + "/v.hc")
	k := kdf{veracrypt.Argon2id, ""}
	hk, _ := tl.derive(k, pass, raw[:64])
	if _, err := openHeader(tl, chains[0].links, hk, raw[64:512], 1<<20); err != nil {
		t.Fatal(err)
	}
	bad, _ := tl.derive(k, []byte("another-passphrase-long-enough"), raw[:64])
	if _, err := openHeader(tl, chains[0].links, bad, raw[64:512], 1<<20); err == nil {
		t.Fatal("wrong key opened the header")
	}
	if _, err := openHeader(tl, chains[0].links, hk, raw[64:512], 2<<20); err == nil {
		t.Fatal("wrong size accepted")
	}
	flipped := append([]byte{}, raw[64:512]...)
	flipped[300] ^= 1
	if _, err := openHeader(tl, chains[0].links, hk, flipped, 1<<20); err == nil {
		t.Fatal("altered header accepted")
	}
	if _, err := openHeader(tl, chains[0].links, hk[:10], raw[64:512], 1<<20); err == nil {
		t.Fatal("short key accepted")
	}
}
