// Command vcoracle checks the DATA AREA of volumes written by
// github.com/go-fde/veracrypt's Create with programs that are not ours and
// without root:
//
//  1. cryptsetup (tcryptDump --veracrypt --dump-volume-key, the passphrase on
//     its standard input) unwraps the header and prints the master key;
//  2. Botan's command line (botan cipher --decrypt, XTS, the tweak being the
//     sector's number on the volume, the last link of a cascade first)
//     decrypts sectors of the data area;
//  3. the result must equal the plaintext Create's Volume was given.
//
// It needs Linux binaries of cryptsetup and botan; run it locally on Linux or
// copy it to a Linux host. The key offsets of the chains are transcribed from
// cryptsetup's lib/tcrypt/tcrypt.c (tcrypt_cipher[]), not taken from the
// package under test.
//
// Combinations neither program can judge are listed, not skipped silently:
// cryptsetup built on OpenSSL 3 has no Kuznyechik and no Streebog, and Botan
// cannot be handed the header key without the passphrase on its command line.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-fde/veracrypt"
	"github.com/spf13/cobra"
)

var osExit = os.Exit

const (
	dataOff    = 131072
	sectorSize = 512
	pim        = 1
)

// link is one cipher of a chain: Botan's name for it, and the offsets of its
// XTS data key and tweak key in the master key area (tcrypt.c: key_offset,
// iv_offset), kept as the record of the table: the key bytes themselves come
// from cryptsetup's dump.
type link struct {
	botan            string
	keyOff, tweakOff int
}

// chains is tcrypt_cipher[]'s XTS part, in cryptsetup's order of links.
var chains = []struct {
	name  veracrypt.Cipher
	links []link
}{
	{veracrypt.AES, []link{{"AES-256/XTS", 0, 32}}},
	{veracrypt.Serpent, []link{{"Serpent/XTS", 0, 32}}},
	{veracrypt.Twofish, []link{{"Twofish/XTS", 0, 32}}},
	{veracrypt.TwofishAES, []link{{"Twofish/XTS", 0, 64}, {"AES-256/XTS", 32, 96}}},
	{veracrypt.SerpentTwofishAES, []link{{"Serpent/XTS", 0, 96}, {"Twofish/XTS", 32, 128}, {"AES-256/XTS", 64, 160}}},
	{veracrypt.AESSerpent, []link{{"AES-256/XTS", 0, 64}, {"Serpent/XTS", 32, 96}}},
	{veracrypt.AESTwofishSerpent, []link{{"AES-256/XTS", 0, 96}, {"Twofish/XTS", 32, 128}, {"Serpent/XTS", 64, 160}}},
	{veracrypt.SerpentTwofish, []link{{"Serpent/XTS", 0, 64}, {"Twofish/XTS", 32, 96}}},
	{veracrypt.Camellia, []link{{"Camellia-256/XTS", 0, 32}}},
	{veracrypt.Kuznyechik, []link{{"Kuznyechik/XTS", 0, 32}}},
	{veracrypt.KuznyechikCamellia, []link{{"Kuznyechik/XTS", 0, 64}, {"Camellia-256/XTS", 32, 96}}},
	{veracrypt.TwofishKuznyechik, []link{{"Twofish/XTS", 0, 64}, {"Kuznyechik/XTS", 32, 96}}},
	{veracrypt.SerpentCamellia, []link{{"Serpent/XTS", 0, 64}, {"Camellia-256/XTS", 32, 96}}},
	{veracrypt.AESKuznyechik, []link{{"AES-256/XTS", 0, 64}, {"Kuznyechik/XTS", 32, 96}}},
	{veracrypt.CamelliaSerpentKuznyechik, []link{{"Camellia-256/XTS", 0, 96}, {"Serpent/XTS", 32, 128}, {"Kuznyechik/XTS", 64, 160}}},
}

var kdfs = []veracrypt.KDF{veracrypt.SHA512, veracrypt.SHA256, veracrypt.BLAKE2s, veracrypt.Whirlpool, veracrypt.Streebog}

// tools are the two outside programs; tests replace them.
type tools struct {
	// dump returns tcryptDump's output for the volume at path.
	dump func(path string) (string, error)
	// botan decrypts one XTS data unit.
	botan func(cipher string, key, nonce, data []byte) ([]byte, error)
}

type config struct {
	dir, passFile, cryptsetup, botan, botanLib string
}

func (c config) tools() tools {
	return tools{
		dump: func(path string) (string, error) {
			pw, err := os.Open(c.passFile)
			if err != nil {
				return "", err
			}
			defer pw.Close()
			cmd := exec.Command(c.cryptsetup, "tcryptDump", "--veracrypt", fmt.Sprintf("--veracrypt-pim=%d", pim), "--dump-volume-key", path)
			cmd.Stdin = pw
			out, err := cmd.CombinedOutput()
			return string(out), err
		},
		botan: func(cipher string, key, nonce, data []byte) ([]byte, error) {
			f, err := os.CreateTemp(c.dir, "unit-*")
			if err != nil {
				return nil, err
			}
			defer os.Remove(f.Name())
			if _, err := f.Write(data); err != nil {
				return nil, err
			}
			f.Close()
			cmd := exec.Command(c.botan, "cipher", "--decrypt", "--cipher="+cipher, "--key="+hex.EncodeToString(key), "--nonce="+hex.EncodeToString(nonce), f.Name())
			cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+c.botanLib)
			return cmd.Output()
		},
	}
}

// parseDump reads the chain name and the master key from tcryptDump
// --dump-volume-key's output.
func parseDump(s string) (chain string, mk []byte, err error) {
	inKey := false
	var hexes strings.Builder
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "Cipher chain:"):
			chain = strings.TrimSpace(strings.TrimPrefix(l, "Cipher chain:"))
		case strings.HasPrefix(l, "MK dump:"):
			inKey = true
			hexes.WriteString(strings.TrimPrefix(l, "MK dump:"))
		case inKey && strings.HasPrefix(l, "\t"):
			hexes.WriteString(l)
		default:
			inKey = false
		}
	}
	mk, err = hex.DecodeString(strings.Join(strings.Fields(hexes.String()), ""))
	if err != nil || chain == "" || len(mk) == 0 {
		return "", nil, fmt.Errorf("no chain or master key in %q", s)
	}
	return chain, mk, nil
}

// nonce is XTS's tweak for a sector: its number on the volume, 16 bytes,
// little-endian (the data area starts at sector 256).
func nonce(sector uint64) []byte {
	n := make([]byte, 16)
	binary.LittleEndian.PutUint64(n, sector)
	return n
}

// plaintext is the known pattern written into sector i.
func plaintext(i int) []byte {
	p := make([]byte, sectorSize)
	for j := range p {
		p[j] = byte(j*7 + i*13 + 1)
	}
	return p
}

// decrypt decrypts a sector with the chain's links, the last link first.
func decrypt(t tools, links []link, mk, ct []byte, sector uint64) ([]byte, error) {
	p := ct
	for i := len(links) - 1; i >= 0; i-- {
		l := links[i]
		// cryptsetup's dump (TCRYPT_get_volume_key) holds one 64-byte
		// block per link, in table order: data key then tweak key, already
		// gathered from the master key area by cryptsetup itself.
		if 64*(i+1) > len(mk) {
			return nil, fmt.Errorf("volume key of %d bytes too short", len(mk))
		}
		key := mk[64*i : 64*i+64]
		var err error
		if p, err = t.botan(l.botan, key, nonce(sector), p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

type verdict struct {
	name, status, detail string // status: OK, FAIL, UNJUDGED
}

// check creates one volume and judges its data area.
func check(t tools, dir string, pass []byte, ci int, k veracrypt.KDF) verdict {
	c := chains[ci]
	name := fmt.Sprintf("%s/%s", c.name, k)
	path := filepath.Join(dir, fmt.Sprintf("%s.%s.hc", c.name, k))
	os.Remove(path)
	const size = 1 << 20
	v, err := veracrypt.CreateFile(path, size, pass, veracrypt.CreateOptions{Cipher: c.name, KDF: k, PIM: pim})
	if err != nil {
		return verdict{name, "FAIL", "create: " + err.Error()}
	}
	last := int(v.Size()/sectorSize) - 1
	sectors := []int{0, 1, last / 2, last - 1, last}
	for _, s := range sectors {
		if _, err := v.WriteAt(plaintext(s), int64(s)*sectorSize); err != nil {
			return verdict{name, "FAIL", "write: " + err.Error()}
		}
	}
	v.Close()
	out, err := t.dump(path)
	if err != nil {
		return verdict{name, "UNJUDGED", "cryptsetup cannot unwrap the header: " + strings.TrimSpace(lastLine(out))}
	}
	chain, mk, err := parseDump(out)
	if err != nil {
		return verdict{name, "FAIL", err.Error()}
	}
	if chain != string(c.name) {
		return verdict{name, "FAIL", "cryptsetup reports chain " + chain}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return verdict{name, "FAIL", err.Error()}
	}
	for _, s := range sectors {
		off := dataOff + s*sectorSize
		got, err := decrypt(t, c.links, mk, raw[off:off+sectorSize], uint64(off/sectorSize))
		if err != nil {
			return verdict{name, "FAIL", err.Error()}
		}
		if !bytes.Equal(got, plaintext(s)) {
			return verdict{name, "FAIL", fmt.Sprintf("sector %d decrypts to something else", s)}
		}
	}
	return verdict{name, "OK", fmt.Sprintf("%d sectors (first, last, middle) decrypted by Botan with cryptsetup's key", len(sectors))}
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

func run(t tools, dir string, pass []byte, w io.Writer) error {
	ok, unjudged, failed := 0, 0, 0
	for ci := range chains {
		for _, k := range kdfs {
			v := check(t, dir, pass, ci, k)
			fmt.Fprintf(w, "%-8s %-40s %s\n", v.status, v.name, v.detail)
			switch v.status {
			case "OK":
				ok++
			case "UNJUDGED":
				unjudged++
			default:
				failed++
			}
		}
	}
	fmt.Fprintf(w, "ok %d, unjudged %d, failed %d\n", ok, unjudged, failed)
	if failed > 0 {
		return errors.New("some volumes failed")
	}
	return nil
}

// RootCmd is the command.
func RootCmd() *cobra.Command {
	var c config
	cmd := &cobra.Command{
		Use:          "vcoracle",
		Short:        "check the data area of created VeraCrypt volumes with cryptsetup and Botan",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Getenv("VCORACLE") != "1" {
				return errors.New("set VCORACLE=1: this runs outside programs and writes volumes into --dir")
			}
			pass, err := os.ReadFile(c.passFile)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(c.dir, 0o700); err != nil {
				return err
			}
			return run(c.tools(), c.dir, pass, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.dir, "dir", "", "directory for the volumes (durable, outside any repository)")
	f.StringVar(&c.passFile, "passfile", "", "file holding the passphrase, no newline")
	f.StringVar(&c.cryptsetup, "cryptsetup", "/usr/sbin/cryptsetup", "cryptsetup binary")
	f.StringVar(&c.botan, "botan", "botan", "botan binary")
	f.StringVar(&c.botanLib, "botan-lib", "", "LD_LIBRARY_PATH for botan")
	cmd.MarkFlagRequired("dir")
	cmd.MarkFlagRequired("passfile")
	return cmd
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		osExit(1)
	}
}
