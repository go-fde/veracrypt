package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
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

// The last link of a cascade is decrypted first, with its own key slices.
func TestDecryptOrder(t *testing.T) {
	mk := make([]byte, 192)
	for i := range mk {
		mk[i] = byte(i)
	}
	var calls []string
	tl := tools{botan: func(c string, key, n, data []byte) ([]byte, error) {
		calls = append(calls, fmt.Sprintf("%s:%d,%d", c, key[0], key[32]))
		return data, nil
	}}
	// serpent-twofish-aes: serpent 0/96, twofish 32/128, aes 64/160.
	if _, err := decrypt(tl, chains[4].links, mk, make([]byte, 512), 256); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, " "); got != "AES-256/XTS:128,160 Twofish/XTS:64,96 Serpent/XTS:0,32" {
		t.Fatal(got)
	}
	if _, err := decrypt(tl, chains[4].links, mk[:100], nil, 0); err == nil {
		t.Fatal("short key accepted")
	}
	boom := tools{botan: func(string, []byte, []byte, []byte) ([]byte, error) { return nil, errors.New("boom") }}
	if _, err := decrypt(boom, chains[0].links, mk, nil, 0); err == nil {
		t.Fatal("botan failure lost")
	}
}

func TestRunReportsUnjudged(t *testing.T) {
	tl := tools{dump: func(string) (string, error) {
		return "x\nNo device header detected with this passphrase.\n", errors.New("exit 2")
	}}
	var out bytes.Buffer
	// Only Kuznyechik chains and Streebog are unjudged; every other refusal
	// by cryptsetup is a failure, so the run must not pass.
	if err := run(tl, t.TempDir(), []byte("a-passphrase-long-enough"), &out); err == nil {
		t.Fatal("a run in which cryptsetup opens nothing passed")
	}
	if !strings.Contains(out.String(), "ok 0, unjudged 35, failed 40") || !strings.Contains(out.String(), "No device header detected") {
		t.Fatal(out.String())
	}
}

func TestRootRefusesWithoutEnv(t *testing.T) {
	t.Setenv("VCORACLE", "")
	cmd := RootCmd()
	cmd.SetArgs([]string{"--dir", t.TempDir(), "--passfile", "/nonexistent"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "VCORACLE=1") {
		t.Fatal(err)
	}
}
