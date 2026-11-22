//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guest runs real tools (cryptsetup, veracrypt, mkfs, mount) as root in a
// VM. To test what it does when one of them fails, the test binary is
// symlinked under those names in a directory that becomes the whole PATH; the
// fake exits 1 with "boom" when its name (or name:first-argument) is listed in
// VCMOUNT_FAKE_FAIL, and succeeds otherwise.
const fakeFailEnv = "VCMOUNT_FAKE_FAIL"

var fakeToolNames = map[string]bool{
	"cryptsetup": true, "veracrypt": true, "mkfs.ext4": true, "mkfs.vfat": true,
	"mount": true, "umount": true, "sync": true,
}

func fakeTool(name string, args []string) int {
	for _, tok := range strings.Split(os.Getenv(fakeFailEnv), ",") {
		if tok == name || (len(args) > 0 && tok == name+":"+args[0]) {
			os.Stderr.WriteString("boom\n")
			return 1
		}
	}
	return 0
}

// useFakeTools puts the fakes alone on PATH and makes the listed ones fail.
func useFakeTools(t *testing.T, fail ...string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for n := range fakeToolNames {
		if err := os.Symlink(self, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv(fakeFailEnv, strings.Join(fail, ","))
}

func newGuest(t *testing.T) guest {
	return guest{dir: t.TempDir(), pass: []byte(testPass), out: &bytes.Buffer{}}
}

// A mapping that cannot be closed is reported as such, not as the later read.
func TestCryptsetupCloseFailureIsReported(t *testing.T) {
	useFakeTools(t, "cryptsetup:close")
	_, why := newGuest(t).plainViaCryptsetup("vol")
	if !strings.Contains(why, "close failed") {
		t.Fatalf("why = %q", why)
	}
}

func TestMkfsFailureIsReported(t *testing.T) {
	for _, c := range []struct{ fs, tool string }{{"ext4", "mkfs.ext4"}, {"vfat", "mkfs.vfat"}} {
		useFakeTools(t, c.tool)
		g := newGuest(t)
		r, ok := g.filesystem("vol", g.dir, "dev", c.fs, true)
		if ok || !strings.Contains(r, c.fs+": mkfs: ") {
			t.Errorf("%s: %q, %v", c.fs, r, ok)
		}
	}
}

func TestCryptsetupMountFailureIsReported(t *testing.T) {
	useFakeTools(t, "mount")
	g := newGuest(t)
	r, ok := g.filesystem("vol", g.dir, "dev", "ext4", true)
	if ok || !strings.Contains(r, "cryptsetup mount: ") {
		t.Fatalf("%q, %v", r, ok)
	}
}

// The passphrase of every tool call is its standard input, and a run in which
// nothing fails reaches the end of the second pass.
func TestFilesystemReachesTheCryptsetupRead(t *testing.T) {
	useFakeTools(t)
	g := newGuest(t)
	r, ok := g.filesystem("vol", g.dir, "dev", "ext4", true)
	// the fake mount mounts nothing, so the probe file is not there: the
	// failure is the final comparison, not an earlier refusal
	if ok || !strings.Contains(r, "file differs through cryptsetup") {
		t.Fatalf("%q, %v", r, ok)
	}
}
