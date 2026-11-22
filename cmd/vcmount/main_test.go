package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

func TestPlainAndFirstDiff(t *testing.T) {
	a, b := plain(2*sectorSize), plain(2*sectorSize)
	if firstDiff(a, b) != -1 {
		t.Fatal("equal buffers differ")
	}
	b[sectorSize+5] ^= 1
	if firstDiff(a, b) != 1 {
		t.Fatal(firstDiff(a, b))
	}
	if firstDiff(a, b[:sectorSize]) != 1 {
		t.Fatal("a short buffer is not a difference")
	}
	if bytes.Equal(a[:sectorSize], a[sectorSize:]) {
		t.Fatal("sectors are not distinct")
	}
}

func TestLastLine(t *testing.T) {
	if lastLine("a\nb \n\n") != "b" || lastLine("") != "" {
		t.Fatal("lastLine")
	}
}

func TestShReadsStdinBytes(t *testing.T) {
	out, err := sh([]byte("hello"), "cat")
	if err != nil || out != "hello" {
		t.Fatal(out, err)
	}
	if _, err := sh(nil, "false"); err == nil {
		t.Fatal("failure lost")
	}
}

func TestCheckPassphrase(t *testing.T) {
	for body, ok := range map[string]bool{
		"short":                          false,
		"a-passphrase-with-newline-ok\n": false,
		"a-passphrase-with\rcr-ok-ok":    false,
		"a-passphrase-long-enough-ok":    true,
	} {
		if err := checkPassphrase([]byte(body)); (err == nil) != ok {
			t.Errorf("%q: %v", body, err)
		}
	}
}

func TestCheckPassphraseBoundary(t *testing.T) {
	if checkPassphrase(bytes.Repeat([]byte("x"), 19)) == nil {
		t.Error("19 bytes accepted")
	}
	if err := checkPassphrase(bytes.Repeat([]byte("x"), 20)); err != nil {
		t.Errorf("20 bytes refused: %v", err)
	}
}

func TestReadStdinPassphrase(t *testing.T) {
	good := "a-passphrase-long-enough-ok"
	got, err := readStdinPassphrase(strings.NewReader(good))
	if err != nil || string(got) != good {
		t.Fatalf("%q, %v", got, err)
	}
	for name, in := range map[string]string{
		"empty":    "",
		"short":    "short",
		"newline":  good + "\n",
		"oversize": strings.Repeat("x", secretsource.MaxSize+1),
		"way over": strings.Repeat("x", 10*secretsource.MaxSize),
	} {
		got, err := readStdinPassphrase(strings.NewReader(in))
		if err == nil || got != nil {
			t.Errorf("%s: accepted", name)
		}
		if err != nil && len(in) > 0 && len(in) < 100 && strings.Contains(err.Error(), in) {
			t.Errorf("%s: error repeats the input", name)
		}
	}
	// exactly MaxSize is the largest accepted
	if _, err := readStdinPassphrase(strings.NewReader(strings.Repeat("x", secretsource.MaxSize))); err != nil {
		t.Errorf("MaxSize refused: %v", err)
	}
}

// Only the stated gap may be refused by cryptsetup.
func TestCryptsetupGap(t *testing.T) {
	if !cryptsetupGap("kuznyechik-camellia", "sha512") || !cryptsetupGap("aes", "stribog512") || !cryptsetupGap("aes", "argon2id") {
		t.Fatal("known gap not recognised")
	}
	if cryptsetupGap("aes", "sha512") || cryptsetupGap("serpent-twofish-aes", "whirlpool") {
		t.Fatal("a supported combination counted as a gap")
	}
}

func TestGateAndRoot(t *testing.T) {
	t.Setenv("VCMOUNT", "")
	for _, args := range [][]string{
		{"guest", "--dir", t.TempDir(), "--stdin"},
		{"guest", "--dir", t.TempDir(), "--secret", "file:x"},
		{"host", "--vm", "x", "--secret", "file:x", "--guest-bin", "x"},
	} {
		cmd := RootCmd()
		cmd.SetArgs(args)
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "VCMOUNT=1") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if os.Geteuid() != 0 {
		if err := runGuest(t.TempDir(), []byte("x"), &bytes.Buffer{}); err == nil {
			t.Fatal("guest ran without root")
		}
	}
}
