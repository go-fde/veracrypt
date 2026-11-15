// Command vcmount mounts volumes written by github.com/go-fde/veracrypt's
// Create, as root, inside a throwaway Linux VM, with the two programs that
// mount VeraCrypt volumes: cryptsetup (open --type tcrypt --veracrypt) and
// VeraCrypt itself (--text --mount --filesystem=none). The plaintext each
// shows is compared sector for sector with what Create wrote, and a second
// pass makes an ext4 (and, for the SHA-512 volumes, a FAT) filesystem inside
// the volume with one tool and reads a file back with the other.
//
//	vcmount host   drives a Tart VM from macOS: starts it, copies this binary
//	               and the passphrase file in, installs VeraCrypt (checksum and
//	               PGP signature verified), runs "vcmount guest", deletes the
//	               passphrase, stops the VM.
//	vcmount guest  runs inside the VM as root.
//
// The passphrase is read from a file by the program that needs it and is
// never in a command line, an environment variable or the output; it goes
// into the VM through the standard input of "tart exec -i" and is deleted
// there afterwards. Both modes need VCMOUNT=1.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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

// sh runs a command with stdin from a file (or nil) and returns its combined
// output. The passphrase file is only ever a stdin.
func sh(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		f, err := os.Open(stdin)
		if err != nil {
			return "", err
		}
		defer f.Close()
		cmd.Stdin = f
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
	dir, pass string
	out       io.Writer
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
func (g guest) vcUmount(string) { sh("", "veracrypt", "--text", "--non-interactive", "-d") }

// plainViaCryptsetup returns the plaintext cryptsetup maps, or why not.
func (g guest) plainViaCryptsetup(vol string) ([]byte, string) {
	const name = "vcmount"
	if out, err := sh(g.pass, "cryptsetup", "open", "--type", "tcrypt", "--veracrypt", fmt.Sprintf("--veracrypt-pim=%d", pim), "--readonly", vol, name); err != nil {
		return nil, "refused: " + lastLine(out)
	}
	defer sh("", "cryptsetup", "close", name)
	b, err := os.ReadFile("/dev/mapper/" + name)
	if err != nil {
		return nil, "read: " + err.Error()
	}
	return b, ""
}

func (g guest) check(c veracrypt.Cipher, k veracrypt.KDF) (failed bool) {
	name := fmt.Sprintf("%s/%s", c, k)
	vol := filepath.Join(g.dir, fmt.Sprintf("%s.%s.hc", c, k))
	os.Remove(vol)
	pass, err := os.ReadFile(g.pass)
	if err != nil {
		fmt.Fprintf(g.out, "FAIL %-42s %v\n", name, err)
		return true
	}
	want := plain(size - 2*dataOff)
	v, err := veracrypt.CreateFile(vol, size, pass, veracrypt.CreateOptions{Cipher: c, KDF: k, PIM: pim})
	clear(pass)
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
	default:
		res = append(res, "cryptsetup "+why)
	}

	// VeraCrypt: the virtual device it exposes with --filesystem=none.
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
				if r, ok := g.filesystem(vol, mp, dev, fs, cryptsetupOK); ok {
					res = append(res, r)
				} else {
					res = append(res, r)
					bad = true
				}
				// the volume was dismounted by filesystem(); mount it bare again
				if _, err := g.vcMount(vol, mp, "none", false); err != nil {
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
	if out, err := sh("", mk[0], mk[1:]...); err != nil {
		return fs + ": mkfs: " + lastLine(out), false
	}
	g.vcUmount(mp)
	if out, err := g.vcMount(vol, mp, "", false); err != nil {
		return fs + ": veracrypt mount: " + lastLine(out), false
	}
	content := []byte("vcmount " + fs + " " + filepath.Base(vol))
	werr := os.WriteFile(filepath.Join(mp, "probe.txt"), content, 0o600)
	sh("", "sync")
	g.vcUmount(mp)
	if werr != nil {
		return fs + ": write: " + werr.Error(), false
	}
	if !cryptsetupOK {
		return fs + ": written through VeraCrypt", true
	}
	const name = "vcmount-fs"
	if out, err := sh(g.pass, "cryptsetup", "open", "--type", "tcrypt", "--veracrypt", fmt.Sprintf("--veracrypt-pim=%d", pim), "--readonly", vol, name); err != nil {
		return fs + ": cryptsetup open: " + lastLine(out), false
	}
	defer sh("", "cryptsetup", "close", name)
	m2 := mp + "-ro"
	os.MkdirAll(m2, 0o700)
	if out, err := sh("", "mount", "-o", "ro", "/dev/mapper/"+name, m2); err != nil {
		return fs + ": cryptsetup mount: " + lastLine(out), false
	}
	defer sh("", "umount", m2)
	got, err := os.ReadFile(filepath.Join(m2, "probe.txt"))
	if err != nil || !bytes.Equal(got, content) {
		return fs + ": file differs through cryptsetup", false
	}
	return fs + ": VeraCrypt wrote, cryptsetup read", true
}

func runGuest(dir, pass string, out io.Writer) error {
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
	vm, passFile, guestBin string
	out                    io.Writer
}

// tart runs "tart exec" in the VM; stdin, when set, is a local file.
func (h host) exec(stdin string, args ...string) error {
	a := []string{"exec"}
	if stdin != "" {
		a = append(a, "-i")
	}
	cmd := exec.Command("tart", append(append(a, h.vm), args...)...)
	if stdin != "" {
		f, err := os.Open(stdin)
		if err != nil {
			return err
		}
		defer f.Close()
		cmd.Stdin = f
	}
	cmd.Stdout, cmd.Stderr = h.out, h.out
	return cmd.Run()
}

func (h host) runHost() error {
	run := exec.Command("tart", "run", "--no-graphics", h.vm)
	if err := run.Start(); err != nil {
		return err
	}
	defer func() { run.Process.Kill(); run.Wait(); exec.Command("tart", "stop", h.vm).Run() }()
	deadline := time.Now().Add(3 * time.Minute)
	for h.exec("", "true") != nil {
		if time.Now().After(deadline) {
			return errors.New("the VM does not answer tart exec")
		}
		time.Sleep(3 * time.Second)
	}
	// Always delete the passphrase in the VM, whatever happens.
	defer h.exec("", "sh", "-c", "rm -f ~/vcmount/pw; sudo rm -rf ~/vcmount/out")
	steps := [][]string{
		{"sh", "-c", "mkdir -p ~/vcmount && cd ~/vcmount && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q libfuse2t64 gnupg curl cryptsetup e2fsprogs dosfstools >/dev/null"},
		{"sh", "-c", "cd ~/vcmount && deb=veracrypt-console-" + vcVersion + "-Ubuntu-24.04-arm64.deb && [ -f $deb ] || (curl -fsSLO " + vcBase + "/$deb && curl -fsSLO " + vcBase + "/$deb.sig && curl -fsSLO " + vcBase + "/veracrypt-" + vcVersion + "-sha256sum.txt && curl -fsSLO https://amcrypto.jp/VeraCrypt/VeraCrypt_PGP_public_key.asc)"},
		{"sh", "-c", "cd ~/vcmount && deb=veracrypt-console-" + vcVersion + "-Ubuntu-24.04-arm64.deb && sha256sum --ignore-missing -c veracrypt-" + vcVersion + "-sha256sum.txt 2>/dev/null && export GNUPGHOME=$PWD/gnupg && mkdir -p -m 700 $GNUPGHOME && gpg -q --import VeraCrypt_PGP_public_key.asc 2>/dev/null && gpg --status-fd 1 --verify $deb.sig $deb 2>/dev/null | grep -q 'VALIDSIG " + vcFingerprint + "' && sudo apt-get install -y -q ./$deb >/dev/null && veracrypt --version"},
	}
	for _, s := range steps {
		if err := h.exec("", s...); err != nil {
			return fmt.Errorf("prepare the VM: %w", err)
		}
	}
	if err := h.exec(h.guestBin, "sh", "-c", "umask 077; cat > ~/vcmount/vcmount && chmod 700 ~/vcmount/vcmount"); err != nil {
		return err
	}
	if err := h.exec(h.passFile, "sh", "-c", "umask 077; cat > ~/vcmount/pw"); err != nil {
		return err
	}
	return h.exec("", "sh", "-c", "cd ~/vcmount && VCMOUNT=1 sudo -E ./vcmount guest --dir $PWD/out --passfile $PWD/pw")
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
	var dir, pass string
	guestCmd := &cobra.Command{
		Use: "guest", Short: "run inside the VM, as root", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := gate(); err != nil {
				return err
			}
			return runGuest(dir, pass, cmd.OutOrStdout())
		},
	}
	guestCmd.Flags().StringVar(&dir, "dir", "", "directory for the volumes")
	guestCmd.Flags().StringVar(&pass, "passfile", "", "file holding the passphrase, no newline")
	guestCmd.MarkFlagRequired("dir")
	guestCmd.MarkFlagRequired("passfile")

	var h host
	hostCmd := &cobra.Command{
		Use: "host", Short: "drive a Tart VM from macOS", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := gate(); err != nil {
				return err
			}
			h.out = cmd.OutOrStdout()
			return h.runHost()
		},
	}
	hostCmd.Flags().StringVar(&h.vm, "vm", "", "name of a Tart Linux arm64 VM (Ubuntu 24.04, passwordless sudo, guest agent)")
	hostCmd.Flags().StringVar(&h.passFile, "passfile", "", "local file holding the passphrase (at least 20 bytes, no newline)")
	hostCmd.Flags().StringVar(&h.guestBin, "guest-bin", "", "this program built for linux/arm64")
	hostCmd.MarkFlagRequired("vm")
	hostCmd.MarkFlagRequired("passfile")
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
