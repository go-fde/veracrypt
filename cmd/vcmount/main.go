// Command vcmount mounts volumes written by github.com/go-fde/veracrypt's
// Create, as root, inside a throwaway Linux VM, with the two programs that
// mount VeraCrypt volumes: cryptsetup (open --type tcrypt --veracrypt) and
// VeraCrypt itself (--text --mount --filesystem=none). The plaintext each
// shows is compared sector for sector with what Create wrote, and a second
// pass makes an ext4 (and, for the SHA-512 volumes, a FAT) filesystem inside
// the volume with one tool and reads a file back with the other.
//
//	vcmount host   drives a Tart VM from macOS: starts it, copies this binary
//	               in, installs VeraCrypt (checksum and PGP signature
//	               verified), runs "vcmount guest --stdin" with the passphrase
//	               on its standard input, stops the VM.
//	vcmount guest  runs inside the VM as root.
//
// The host resolves the passphrase from a go-authn/secretsource reference
// (--secret). It is never in a command line, an environment variable, a log or
// the output, and never a file in the VM: it is the standard input of
// "tart exec -i" feeding "vcmount guest --stdin". Both modes need VCMOUNT=1.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-authn/secretsource"
	"github.com/go-fde/veracrypt"
	"github.com/spf13/cobra"
)

var osExit = os.Exit

const (
	size       = 1 << 20
	dataOff    = 131072
	sectorSize = 512
	pim        = 1
	vcVersion  = "1.26.31"
	vcBase     = "https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_" + vcVersion
	// vcFingerprint is the VeraCrypt team's PGP key, as veracrypt.io lists it.
	vcFingerprint = "5069A233D55A0EEB174A5FC3821ACD02680D16DE"
)

var ciphers = []veracrypt.Cipher{
	veracrypt.AES, veracrypt.Serpent, veracrypt.Twofish, veracrypt.TwofishAES, veracrypt.SerpentTwofishAES,
	veracrypt.AESSerpent, veracrypt.AESTwofishSerpent, veracrypt.SerpentTwofish, veracrypt.Camellia,
	veracrypt.Kuznyechik, veracrypt.KuznyechikCamellia, veracrypt.TwofishKuznyechik, veracrypt.SerpentCamellia,
	veracrypt.AESKuznyechik, veracrypt.CamelliaSerpentKuznyechik,
}

var kdfs = []veracrypt.KDF{veracrypt.SHA512, veracrypt.SHA256, veracrypt.BLAKE2s, veracrypt.Whirlpool, veracrypt.Streebog, veracrypt.Argon2id}

// ---------------------------------------------------------------- guest

// sh runs a command with stdin from memory (or none when nil) and returns its
// combined output. The passphrase is only ever a stdin, never a file.
func sh(stdin []byte, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l[len(l)-1])
}

// plain is the known plaintext of the whole data area.
func plain(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i%sectorSize*7 + i/sectorSize*13 + 1)
	}
	return p
}

// firstDiff names the first sector in which a and b differ, or -1.
func firstDiff(a, b []byte) int {
	if len(a) != len(b) {
		return min(len(a), len(b)) / sectorSize
	}
	for i := range a {
		if a[i] != b[i] {
			return i / sectorSize
		}
	}
	return -1
}

type guest struct {
	dir  string
	pass []byte // the passphrase, in memory only; wiped by runGuest
	out  io.Writer
}

func (g guest) vcMount(vol, mp, fs string, ro bool) (string, error) {
	args := []string{"--text", "--non-interactive", "--stdin", "--mount", vol, mp, "--pim=" + fmt.Sprint(pim),
		"--keyfiles=", "--protect-hidden=no", "--slot=1"}
	if fs != "" {
		args = append(args, "--filesystem="+fs)
	}
	if ro {
		args = append(args, "--mount-options=ro")
	}
	return sh(g.pass, "veracrypt", args...)
}

// vcUmount dismounts every VeraCrypt volume (this program mounts one at a
// time); "-d <path>" does not find a volume mounted with --filesystem=none.
func (g guest) vcUmount(string) { sh(nil, "veracrypt", "--text", "--non-interactive", "-d") }

// plainViaCryptsetup returns the plaintext cryptsetup maps, or why not.
func (g guest) plainViaCryptsetup(vol string) ([]byte, string) {
	const name = "vcmount"
	if out, err := sh(g.pass, "cryptsetup", "open", "--type", "tcrypt", "--veracrypt", fmt.Sprintf("--veracrypt-pim=%d", pim), "--readonly", vol, name); err != nil {
		return nil, "refused: " + lastLine(out)
	}
	b, err := os.ReadFile("/dev/mapper/" + name)
	if out, cerr := sh(nil, "cryptsetup", "close", name); cerr != nil {
		return nil, "close failed (a leftover mapping would poison later volumes): " + lastLine(out)
	}
	if err != nil {
		return nil, "read: " + err.Error()
	}
	return b, ""
}

// cryptsetupGap says whether this cryptsetup (OpenSSL 3, kernel crypto API,
// tcrypt table of 2.7.0) cannot open the combination: Kuznyechik has no
// kernel cipher, Streebog no OpenSSL hash, and 2.7.0 has no Argon2id here.
// Any other refusal is a failure.
func cryptsetupGap(c veracrypt.Cipher, k veracrypt.KDF) bool {
	return k == veracrypt.Streebog || k == veracrypt.Argon2id || strings.Contains(string(c), "kuznyechik")
}

func (g guest) check(c veracrypt.Cipher, k veracrypt.KDF) bool {
	name := fmt.Sprintf("%s/%s", c, k)
	vol := filepath.Join(g.dir, fmt.Sprintf("%s.%s.hc", c, k))
	os.Remove(vol)
	want := plain(size - 2*dataOff)
	v, err := veracrypt.CreateFile(vol, size, g.pass, veracrypt.CreateOptions{Cipher: c, KDF: k, PIM: pim})
	if err == nil {
		_, err = v.WriteAt(want, 0)
		if e := v.Close(); err == nil {
			err = e
		}
	}
	if err != nil {
		fmt.Fprintf(g.out, "FAIL %-42s create: %v\n", name, err)
		return true
	}
	res := []string{}
	bad := false

	// cryptsetup: the plaintext it maps, sector for sector.
	got, why := g.plainViaCryptsetup(vol)
	cryptsetupOK := why == ""
	switch {
	case cryptsetupOK && firstDiff(got, want) >= 0:
		res = append(res, fmt.Sprintf("cryptsetup: DIFFERS at sector %d", firstDiff(got, want)))
		bad = true
	case cryptsetupOK:
		res = append(res, fmt.Sprintf("cryptsetup: %d sectors equal", len(want)/sectorSize))
	case cryptsetupGap(c, k) && strings.Contains(why, "No device header detected"):
		res = append(res, "cryptsetup "+why)
	default:
		res = append(res, "cryptsetup FAILED, not a known gap: "+why)
		bad = true
	}

	// VeraCrypt: the plaintext of its userspace (FUSE) device, which it
	// exposes with --filesystem=none at /tmp/.veracrypt_aux_mnt1/volume.
	mp := filepath.Join(g.dir, "mnt")
	os.MkdirAll(mp, 0o700)
	if out, err := g.vcMount(vol, mp, "none", false); err != nil {
		res = append(res, "veracrypt: MOUNT FAILED: "+lastLine(out))
		bad = true
	} else {
		dev := "/tmp/.veracrypt_aux_mnt1/volume"
		b, err := os.ReadFile(dev)
		switch {
		case err != nil:
			res = append(res, "veracrypt: read: "+err.Error())
			bad = true
		case firstDiff(b, want) >= 0:
			res = append(res, fmt.Sprintf("veracrypt: DIFFERS at sector %d", firstDiff(b, want)))
			bad = true
		default:
			res = append(res, fmt.Sprintf("veracrypt: %d sectors equal", len(want)/sectorSize))
		}
		// Second pass, part one: VeraCrypt's virtual device gets a filesystem.
		if !bad {
			for _, fs := range g.filesystems(k) {
				r, ok := g.filesystem(vol, mp, dev, fs, cryptsetupOK)
				res = append(res, r)
				bad = bad || !ok
				// the volume was dismounted by filesystem(); mount it bare again
				if out, err := g.vcMount(vol, mp, "none", false); err != nil {
					res = append(res, "veracrypt: remount: "+lastLine(out))
					bad = true
					break
				}
			}
		}
		g.vcUmount(mp)
	}
	status := "OK  "
	if bad {
		status = "FAIL"
	}
	fmt.Fprintf(g.out, "%s %-42s %s\n", status, name, strings.Join(res, "; "))
	return bad
}

// filesystems are the filesystems tried inside a volume: ext4 always, FAT for
// the SHA-512 volumes.
func (g guest) filesystems(k veracrypt.KDF) []string {
	if k == veracrypt.SHA512 {
		return []string{"ext4", "vfat"}
	}
	return []string{"ext4"}
}

// filesystem makes fs on VeraCrypt's virtual device dev, dismounts, mounts
// the volume again WITH its filesystem through VeraCrypt, writes a file, and
// (when cryptsetup can open the volume) reads the file back through it.
func (g guest) filesystem(vol, mp, dev, fs string, cryptsetupOK bool) (string, bool) {
	mk := []string{"mkfs.ext4", "-q", "-F", dev}
	if fs == "vfat" {
		mk = []string{"mkfs.vfat", dev}
	}
	if out, err := sh(nil, mk[0], mk[1:]...); err != nil {
		return fs + ": mkfs: " + lastLine(out), false
	}
	g.vcUmount(mp)
	if out, err := g.vcMount(vol, mp, "", false); err != nil {
		return fs + ": veracrypt mount: " + lastLine(out), false
	}
	content := []byte("vcmount " + fs + " " + filepath.Base(vol))
	werr := os.WriteFile(filepath.Join(mp, "probe.txt"), content, 0o600)
	sh(nil, "sync")
	g.vcUmount(mp)
	if werr != nil {
		return fs + ": write: " + werr.Error(), false
	}
	if !cryptsetupOK {
		// Only VeraCrypt can open this volume: it must read its own file back.
		if out, err := g.vcMount(vol, mp, "", true); err != nil {
			return fs + ": veracrypt re-mount: " + lastLine(out), false
		}
		got, err := os.ReadFile(filepath.Join(mp, "probe.txt"))
		g.vcUmount(mp)
		if err != nil || !bytes.Equal(got, content) {
			return fs + ": file differs on VeraCrypt re-read", false
		}
		return fs + ": VeraCrypt wrote and re-read", true
	}
	const name = "vcmount-fs"
	if out, err := sh(g.pass, "cryptsetup", "open", "--type", "tcrypt", "--veracrypt", fmt.Sprintf("--veracrypt-pim=%d", pim), "--readonly", vol, name); err != nil {
		return fs + ": cryptsetup open: " + lastLine(out), false
	}
	defer sh(nil, "cryptsetup", "close", name)
	m2 := mp + "-ro"
	os.MkdirAll(m2, 0o700)
	if out, err := sh(nil, "mount", "-o", "ro", "/dev/mapper/"+name, m2); err != nil {
		return fs + ": cryptsetup mount: " + lastLine(out), false
	}
	defer sh(nil, "umount", m2)
	got, err := os.ReadFile(filepath.Join(m2, "probe.txt"))
	if err != nil || !bytes.Equal(got, content) {
		return fs + ": file differs through cryptsetup", false
	}
	return fs + ": VeraCrypt wrote, cryptsetup read", true
}

// readStdinPassphrase reads the passphrase the host sent on the guest's
// standard input (nothing is ever written to a file in the guest), at most
// secretsource.MaxSize bytes, and applies the same rules as the host does.
func readStdinPassphrase(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, secretsource.MaxSize+1))
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) > secretsource.MaxSize {
		clear(b)
		return nil, fmt.Errorf("the passphrase on standard input is longer than %d bytes", secretsource.MaxSize)
	}
	if err := checkPassphrase(b); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

func runGuest(dir string, pass []byte, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("the guest runs as root: this mounts volumes")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	g := guest{dir: dir, pass: pass, out: out}
	failed, n := 0, 0
	for _, c := range ciphers {
		for _, k := range kdfs {
			n++
			if g.check(c, k) {
				failed++
			}
		}
	}
	fmt.Fprintf(out, "%d volumes, %d failed\n", n, failed)
	if failed > 0 {
		return errors.New("some volumes failed")
	}
	return nil
}

// ----------------------------------------------------------------- host

type host struct {
	vm, guestBin string
	pass         []byte // the passphrase, in memory only
	tartBin      string // "tart"; a test replaces it
	out          io.Writer
}

func (h host) tart() string {
	if h.tartBin != "" {
		return h.tartBin
	}
	return "tart"
}

// exec runs "tart exec" in the VM; stdin, when not nil, is sent to the
// command's standard input ("-i").
func (h host) exec(stdin io.Reader, args ...string) error {
	a := []string{"exec"}
	if stdin != nil {
		a = append(a, "-i")
	}
	cmd := exec.Command(h.tart(), append(append(a, h.vm), args...)...)
	cmd.Stdin = stdin
	cmd.Stdout, cmd.Stderr = h.out, h.out
	return cmd.Run()
}

// checkPassphrase enforces what the help text says: at least 20 bytes
// (VeraCrypt refuses a low PIM with a shorter one) and no newline (Create
// would take it as part of the passphrase, the mounting tools would not).
func checkPassphrase(b []byte) error {
	if len(b) < 20 || bytes.ContainsAny(b, "\r\n") {
		return errors.New("the passphrase must hold at least 20 bytes and no newline")
	}
	return nil
}

func (h host) runHost() error {
	if h.exec(nil, "true") == nil {
		return errors.New("the VM is already running (another session's?): stop it first")
	}
	if err := checkPassphrase(h.pass); err != nil {
		return err
	}
	run := exec.Command(h.tart(), "run", "--no-graphics", h.vm)
	if err := run.Start(); err != nil {
		return err
	}
	// Whatever happens, including SIGINT and SIGTERM: delete the volumes in
	// the VM, then tart stop (so the guest shuts down cleanly), and only then
	// kill the tart process. The passphrase is never a file in the guest: it
	// goes to "vcmount guest --stdin" on the standard input of tart exec -i.
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			h.exec(nil, "sh", "-c", "sudo rm -rf ~/vcmount/out")
			exec.Command(h.tart(), "stop", h.vm).Run()
			run.Process.Kill()
			run.Wait()
		})
	}
	defer cleanup()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cleanup(); osExit(130) }()
	deadline := time.Now().Add(3 * time.Minute)
	for h.exec(nil, "true") != nil {
		if time.Now().After(deadline) {
			return errors.New("the VM does not answer tart exec")
		}
		time.Sleep(3 * time.Second)
	}
	steps := [][]string{
		{"sh", "-c", "mkdir -p ~/vcmount && cd ~/vcmount && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q libfuse2t64 gnupg curl cryptsetup e2fsprogs dosfstools >/dev/null"},
		{"sh", "-c", "cd ~/vcmount && deb=veracrypt-console-" + vcVersion + "-Ubuntu-24.04-arm64.deb && [ -f $deb ] || (curl -fsSLO " + vcBase + "/$deb && curl -fsSLO " + vcBase + "/$deb.sig && curl -fsSLO " + vcBase + "/veracrypt-" + vcVersion + "-sha256sum.txt && curl -fsSLO https://amcrypto.jp/VeraCrypt/VeraCrypt_PGP_public_key.asc)"},
		{"sh", "-c", "cd ~/vcmount && deb=veracrypt-console-" + vcVersion + "-Ubuntu-24.04-arm64.deb && sha256sum --ignore-missing -c veracrypt-" + vcVersion + "-sha256sum.txt 2>/dev/null && export GNUPGHOME=$PWD/gnupg && mkdir -p -m 700 $GNUPGHOME && gpg -q --import VeraCrypt_PGP_public_key.asc 2>/dev/null && { gpg --status-fd 1 --verify $deb.sig $deb > st 2>/dev/null; true; } && grep -q '^\\[GNUPG:\\] GOODSIG ' st && grep -q '^\\[GNUPG:\\] VALIDSIG " + vcFingerprint + " ' st && ! grep -q '^\\[GNUPG:\\] \\(EXPKEYSIG\\|REVKEYSIG\\|EXPSIG\\|BADSIG\\) ' st && sudo apt-get install -y -q ./$deb >/dev/null && veracrypt --version"},
	}
	for _, s := range steps {
		if err := h.exec(nil, s...); err != nil {
			return fmt.Errorf("prepare the VM: %w", err)
		}
	}
	bin, err := os.Open(h.guestBin)
	if err != nil {
		return err
	}
	defer bin.Close()
	if err := h.exec(bin, "sh", "-c", "umask 077; cat > ~/vcmount/vcmount && chmod 700 ~/vcmount/vcmount"); err != nil {
		return err
	}
	// The passphrase is the standard input of the guest program: no file, no
	// argument, no environment variable in the guest.
	return h.exec(bytes.NewReader(h.pass), "sh", "-c", "cd ~/vcmount && sudo VCMOUNT=1 ./vcmount guest --dir $PWD/out --stdin")
}

// ----------------------------------------------------------------- main

// RootCmd is the command.
func RootCmd() *cobra.Command {
	root := &cobra.Command{Use: "vcmount", SilenceUsage: true}
	gate := func() error {
		if os.Getenv("VCMOUNT") != "1" {
			return errors.New("set VCMOUNT=1: this mounts volumes as root in a VM")
		}
		return nil
	}
	const secretHelp = "reference of the passphrase (at least 20 bytes, no newline): systemd-creds:NAME, keychain:SERVICE/ACCOUNT, keepassxc:..., or file:PATH (owner-only, not a symlink, at most 4096 bytes)"
	var dir, gSecret, gPassFile string
	var fromStdin bool
	guestCmd := &cobra.Command{
		Use: "guest", Short: "run inside the VM, as root", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := gate(); err != nil {
				return err
			}
			var pass []byte
			var err error
			if fromStdin {
				pass, err = readStdinPassphrase(cmd.InOrStdin())
			} else {
				pass, err = resolveSecret(cmd.Context(), gSecret, gPassFile, cmd.ErrOrStderr())
				if err == nil {
					err = checkPassphrase(pass)
				}
			}
			if err != nil {
				return err
			}
			defer clear(pass)
			return runGuest(dir, pass, cmd.OutOrStdout())
		},
	}
	guestCmd.Flags().StringVar(&dir, "dir", "", "directory for the volumes")
	guestCmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the passphrase from the standard input (what vcmount host does)")
	guestCmd.Flags().StringVar(&gSecret, "secret", "", secretHelp)
	guestCmd.Flags().StringVar(&gPassFile, "passfile", "", "deprecated: same as --secret file:PATH")
	guestCmd.Flags().MarkDeprecated("passfile", "use --secret file:PATH")
	guestCmd.MarkFlagRequired("dir")
	guestCmd.MarkFlagsOneRequired("stdin", "secret", "passfile")
	guestCmd.MarkFlagsMutuallyExclusive("stdin", "secret", "passfile")

	var h host
	var hSecret, hPassFile string
	hostCmd := &cobra.Command{
		Use: "host", Short: "drive a Tart VM from macOS", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := gate(); err != nil {
				return err
			}
			// Resolved before the VM is touched: a refused source starts nothing.
			pass, err := resolveSecret(cmd.Context(), hSecret, hPassFile, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			defer clear(pass)
			h.pass = pass
			h.out = cmd.OutOrStdout()
			return h.runHost()
		},
	}
	hostCmd.Flags().StringVar(&h.vm, "vm", "", "name of a Tart Linux arm64 VM (Ubuntu 24.04, passwordless sudo, guest agent)")
	hostCmd.Flags().StringVar(&hSecret, "secret", "", secretHelp)
	hostCmd.Flags().StringVar(&hPassFile, "passfile", "", "deprecated: same as --secret file:PATH")
	hostCmd.Flags().MarkDeprecated("passfile", "use --secret file:PATH")
	hostCmd.Flags().StringVar(&h.guestBin, "guest-bin", "", "this program built for linux/arm64")
	hostCmd.MarkFlagRequired("vm")
	hostCmd.MarkFlagsOneRequired("secret", "passfile")
	hostCmd.MarkFlagsMutuallyExclusive("secret", "passfile")
	hostCmd.MarkFlagRequired("guest-bin")
	root.AddCommand(guestCmd, hostCmd)
	return root
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		osExit(1)
	}
}
