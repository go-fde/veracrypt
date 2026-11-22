//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTartEnv names the directory of the fake "tart": when set, the test
// binary is the fake (see TestMain), not the test suite.
const fakeTartEnv = "VCMOUNT_FAKE_TART_DIR"

type fakeCall struct {
	Args  []string
	Stdin string
}

func TestMain(m *testing.M) {
	if dir := os.Getenv(fakeTartEnv); dir != "" {
		os.Exit(fakeTart(dir, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeTart answers like tart: "run" makes the VM exist (and blocks until it
// is killed), "exec ... true" fails until the VM exists, every other command
// succeeds. It logs each call's arguments and standard input.
func fakeTart(dir string, args []string) int {
	up := filepath.Join(dir, "up")
	if len(args) > 0 && args[0] == "run" {
		os.WriteFile(up, nil, 0o600)
		time.Sleep(time.Minute)
		return 0
	}
	var in []byte
	if len(args) > 1 && args[0] == "exec" && args[1] == "-i" {
		in, _ = io.ReadAll(os.Stdin)
	}
	line, _ := json.Marshal(fakeCall{Args: args, Stdin: string(in)})
	f, err := os.OpenFile(filepath.Join(dir, "log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 3
	}
	f.Write(append(line, '\n'))
	f.Close()
	if len(args) > 0 && args[0] == "exec" && args[len(args)-1] == "true" {
		if _, err := os.Stat(up); err != nil {
			return 1
		}
	}
	return 0
}

func readFakeLog(t *testing.T, dir string) []fakeCall {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	var calls []fakeCall
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var c fakeCall
		if err := json.Unmarshal(l, &c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls
}

// The passphrase reaches the guest on the standard input of one command, the
// last "vcmount guest --stdin", and nowhere else: not in an argument, not in
// another command's input, and no step writes a staging file for it.
func TestHostSendsThePassphraseOnStdinOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakeTartEnv, dir)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "guestbin")
	if err := os.WriteFile(bin, []byte("ELF-guest-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	h := host{vm: "vm1", guestBin: bin, pass: []byte(testPass), tartBin: self, out: &out}
	if err := h.runHost(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	calls := readFakeLog(t, dir)
	if len(calls) < 5 {
		t.Fatalf("only %d calls: %+v", len(calls), calls)
	}
	withPass := 0
	for i, c := range calls {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, testPass) {
			t.Errorf("call %d: the passphrase is in the arguments: %q", i, joined)
		}
		if strings.Contains(joined, "vcmount-pw") || strings.Contains(joined, "/dev/shm") {
			t.Errorf("call %d stages a file: %q", i, joined)
		}
		if strings.Contains(c.Stdin, testPass) {
			withPass++
			if !strings.HasSuffix(joined, "guest --dir $PWD/out --stdin") {
				t.Errorf("call %d sends the passphrase but is not the guest command: %q", i, joined)
			}
			if c.Stdin != testPass {
				t.Errorf("stdin is %q, want exactly the passphrase", c.Stdin)
			}
		}
	}
	if withPass != 1 {
		t.Errorf("%d calls carry the passphrase, want 1", withPass)
	}
	// the guest binary travels on its own stdin
	found := false
	for _, c := range calls {
		if c.Stdin == "ELF-guest-binary" {
			found = true
		}
	}
	if !found {
		t.Error("the guest binary was not sent")
	}
	// the cleanup runs
	last := calls[len(calls)-1]
	if len(last.Args) == 0 || last.Args[0] != "stop" {
		t.Errorf("last call is %v, want tart stop", last.Args)
	}
	if strings.Contains(out.String(), testPass) {
		t.Error("the output names the passphrase")
	}
}

// A passphrase that fails the rules starts nothing: no VM, no call.
func TestHostRefusesAShortPassphraseBeforeTheVM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakeTartEnv, dir)
	self, _ := os.Executable()
	h := host{vm: "vm1", guestBin: "x", pass: []byte("short"), tartBin: self, out: io.Discard}
	if err := h.runHost(); err == nil {
		t.Fatal("accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "up")); err == nil {
		t.Error("a VM was started for a refused passphrase")
	}
}

// exec is the one place a command is built: with stdin it adds "-i", without
// it adds nothing and the command reads /dev/null.
func TestExecAddsDashIOnlyWithStdin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakeTartEnv, dir)
	self, _ := os.Executable()
	h := host{vm: "v", tartBin: self, out: io.Discard}
	if err := h.exec(nil, "echo", "a"); err != nil {
		t.Fatal(err)
	}
	if err := h.exec(strings.NewReader("in"), "echo", "b"); err != nil {
		t.Fatal(err)
	}
	calls := readFakeLog(t, dir)
	if len(calls) != 2 || strings.Join(calls[0].Args, " ") != "exec v echo a" || strings.Join(calls[1].Args, " ") != "exec -i v echo b" || calls[1].Stdin != "in" {
		t.Fatalf("%+v", calls)
	}
}
