package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestShReadsStdinFromFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "in")
	os.WriteFile(f, []byte("hello"), 0o600)
	out, err := sh(f, "cat")
	if err != nil || out != "hello" {
		t.Fatal(out, err)
	}
	if _, err := sh(filepath.Join(t.TempDir(), "missing"), "cat"); err == nil {
		t.Fatal("missing stdin file accepted")
	}
	if _, err := sh("", "false"); err == nil {
		t.Fatal("failure lost")
	}
}

func TestGateAndRoot(t *testing.T) {
	t.Setenv("VCMOUNT", "")
	for _, args := range [][]string{
		{"guest", "--dir", t.TempDir(), "--passfile", "x"},
		{"host", "--vm", "x", "--passfile", "x", "--guest-bin", "x"},
	} {
		cmd := RootCmd()
		cmd.SetArgs(args)
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "VCMOUNT=1") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if os.Geteuid() != 0 {
		if err := runGuest(t.TempDir(), "x", &bytes.Buffer{}); err == nil {
			t.Fatal("guest ran without root")
		}
	}
}
