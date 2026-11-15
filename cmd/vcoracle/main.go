// Command vcoracle checks volumes written by github.com/go-fde/veracrypt's
// Create with programs and libraries that are not ours, without root:
//
//  1. Botan 3 (libbotan-3.so, called through its C interface with purego, so
//     no cgo and no secret on any command line) derives the header key from
//     the passphrase and the salt on disk (PBKDF2 over the hash, or
//     Argon2id), decrypts the 448 header bytes (XTS, data unit 0, the last
//     link of a cascade first), checks the magic, the version fields, the
//     sizes and both CRC-32s, and decrypts sectors of the data area with the
//     master keys it found (XTS, tweak = the sector's number on the volume,
//     last link first). They must equal the plaintext Create was given.
//  2. cryptsetup (tcryptDump --veracrypt --dump-volume-key, passphrase on its
//     standard input), where it can open the volume, must report the same
//     chain and payload offset and hand out the same volume key as the one
//     Botan found: its key blocks are gathered from the master key area with
//     cryptsetup's own offsets.
//
// The key offsets of the chains and the KDF costs are transcribed from
// cryptsetup's lib/tcrypt/tcrypt.c and the VeraCrypt documentation, not
// taken from the package under test. Combinations neither can judge are
// listed as UNJUDGED; a failure anywhere else is a FAIL.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ebitengine/purego"
	"github.com/go-fde/veracrypt"
	"github.com/spf13/cobra"
)

var osExit = os.Exit

const (
	dataOff    = 131072
	sectorSize = 512
	pim        = 1
)

// link is one cipher of a chain: Botan's name for it and the offsets of its
// XTS data key and tweak key in the 192-byte header key or the 256-byte
// master key area (tcrypt.c tcrypt_cipher[]: key_offset, iv_offset).
type link struct {
	botan            string
	keyOff, tweakOff int
}

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

// kdf is a header key derivation as VeraCrypt's documentation specifies it
// for PIM 1: PBKDF2-HMAC with 15000 + 1000 x PIM iterations, or Argon2id
// with t = (PIM-1)/3 + 3 passes and 1024 x (64 + (PIM-1) x 32) KiB.
type kdf struct {
	name  veracrypt.KDF
	botan string // Botan's PBKDF2 PRF name; "" for Argon2id
}

var kdfs = []kdf{
	{veracrypt.SHA512, "SHA-512"},
	{veracrypt.SHA256, "SHA-256"},
	{veracrypt.BLAKE2s, "BLAKE2s"}, // Botan has BLAKE2b only: cryptsetup judges it
	{veracrypt.Whirlpool, "Whirlpool"},
	{veracrypt.Streebog, "Streebog-512"},
	{veracrypt.Argon2id, ""},
}

// tools are the outside programs; tests replace them.
type tools struct {
	// dump returns tcryptDump's output for the volume at path.
	dump func(path string) (string, error)
	// derive returns the 192-byte header key. An error means Botan cannot.
	derive func(k kdf, pass, salt []byte) ([]byte, error)
	// xts runs one XTS data unit of a Botan cipher name; nonce is the
	// 16-byte little-endian tweak.
	xts func(cipher string, key, nonce, data []byte, decrypt bool) ([]byte, error)
}

type config struct {
	dir, passFile, cryptsetup, botanLib string
}

func (c config) tools() (tools, error) {
	b, err := loadBotan(c.botanLib)
	if err != nil {
		return tools{}, err
	}
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
		derive: b.derive,
		xts:    b.xts,
	}, nil
}

// botan is libbotan-3 loaded with purego.
type botan struct {
	pwdhash func(algo string, p1, p2, p3 uintptr, out *byte, outLen uintptr, pass *byte, passLen uintptr, salt *byte, saltLen uintptr) int32
	init    func(c *uintptr, name string, flags uint32) int32
	setKey  func(c uintptr, key *byte, n uintptr) int32
	start   func(c uintptr, nonce *byte, n uintptr) int32
	update  func(c uintptr, flags uint32, out *byte, outSize uintptr, written *uintptr, in *byte, inSize uintptr, consumed *uintptr) int32
	destroy func(c uintptr) int32
}

func loadBotan(path string) (*botan, error) {
	h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	b := &botan{}
	purego.RegisterLibFunc(&b.pwdhash, h, "botan_pwdhash")
	purego.RegisterLibFunc(&b.init, h, "botan_cipher_init")
	purego.RegisterLibFunc(&b.setKey, h, "botan_cipher_set_key")
	purego.RegisterLibFunc(&b.start, h, "botan_cipher_start")
	purego.RegisterLibFunc(&b.update, h, "botan_cipher_update")
	purego.RegisterLibFunc(&b.destroy, h, "botan_cipher_destroy")
	return b, nil
}

func ptr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

// derive is botan_pwdhash: PBKDF2(<prf>) or Argon2id (param1 = KiB, param2 =
// passes, param3 = lanes).
func (b *botan) derive(k kdf, pass, salt []byte) ([]byte, error) {
	out := make([]byte, 192)
	var rc int32
	if k.name == veracrypt.Argon2id {
		rc = b.pwdhash("Argon2id", 1024*(64+(pim-1)*32), (pim-1)/3+3, 1, &out[0], 192, ptr(pass), uintptr(len(pass)), ptr(salt), uintptr(len(salt)))
	} else {
		rc = b.pwdhash("PBKDF2("+k.botan+")", 15000+1000*pim, 0, 0, &out[0], 192, ptr(pass), uintptr(len(pass)), ptr(salt), uintptr(len(salt)))
	}
	if rc != 0 {
		return nil, fmt.Errorf("botan_pwdhash(%s): %d", k.name, rc)
	}
	return out, nil
}

func (b *botan) xts(cipher string, key, nonce, data []byte, decrypt bool) ([]byte, error) {
	var c uintptr
	flags := uint32(0)
	if decrypt {
		flags = 1
	}
	if rc := b.init(&c, cipher, flags); rc != 0 {
		return nil, fmt.Errorf("botan_cipher_init(%s): %d", cipher, rc)
	}
	defer b.destroy(c)
	if rc := b.setKey(c, ptr(key), uintptr(len(key))); rc != 0 {
		return nil, fmt.Errorf("botan_cipher_set_key: %d", rc)
	}
	if rc := b.start(c, ptr(nonce), uintptr(len(nonce))); rc != 0 {
		return nil, fmt.Errorf("botan_cipher_start: %d", rc)
	}
	out := make([]byte, len(data))
	var written, consumed uintptr
	if rc := b.update(c, 1, &out[0], uintptr(len(out)), &written, &data[0], uintptr(len(data)), &consumed); rc != 0 || int(written) != len(data) {
		return nil, fmt.Errorf("botan_cipher_update: %d (%d bytes)", rc, written)
	}
	return out, nil
}

// parseDump reads the chain, the payload offset (in sectors) and the volume
// key from tcryptDump --dump-volume-key's output.
func parseDump(s string) (chain string, mk []byte, payload uint64, err error) {
	inKey := false
	var hexes strings.Builder
	for _, l := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(l, "Payload offset:"):
			payload, _ = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(l, "Payload offset:")), 10, 64)
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
	if err != nil || chain == "" || len(mk) == 0 || payload == 0 {
		return "", nil, 0, fmt.Errorf("no chain, payload offset or master key in %q", s)
	}
	return chain, mk, payload, nil
}

// nonce is XTS's tweak: a sector number, 16 bytes, little-endian.
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

// xtsChain runs the chain over one data unit: decrypting takes the last link
// first (as cryptsetup stacks its devices and VeraCrypt decrypts), keyed from
// key by the transcribed offsets.
func xtsChain(t tools, links []link, key, data, nonce []byte, decrypt bool) ([]byte, error) {
	p := data
	for n := range links {
		i := n
		if decrypt {
			i = len(links) - 1 - n
		}
		l := links[i]
		if l.tweakOff+32 > len(key) {
			return nil, fmt.Errorf("key of %d bytes too short", len(key))
		}
		k := append(append([]byte{}, key[l.keyOff:l.keyOff+32]...), key[l.tweakOff:l.tweakOff+32]...)
		var err error
		p, err = t.xts(l.botan, k, nonce, p, decrypt)
		clear(k)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

type verdict struct {
	name, status, detail string // status: OK, FAIL, UNJUDGED
}

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

// check creates one volume and judges it.
func check(t tools, dir string, pass []byte, ci int, k kdf) verdict {
	c := chains[ci]
	name := fmt.Sprintf("%s/%s", c.name, k.name)
	fail := func(f string, a ...any) verdict { return verdict{name, "FAIL", fmt.Sprintf(f, a...)} }
	path := filepath.Join(dir, fmt.Sprintf("%s.%s.hc", c.name, k.name))
	os.Remove(path)
	const size = 1 << 20
	v, err := veracrypt.CreateFile(path, size, pass, veracrypt.CreateOptions{Cipher: c.name, KDF: k.name, PIM: pim})
	if err != nil {
		return fail("create: %v", err)
	}
	if v.Size() != size-2*dataOff {
		return fail("data area of %d bytes, want %d", v.Size(), size-2*dataOff)
	}
	last := int(v.Size()/sectorSize) - 1
	sectors := []int{0, 1, last / 2, last - 1, last}
	for _, s := range sectors {
		if _, err := v.WriteAt(plaintext(s), int64(s)*sectorSize); err != nil {
			return fail("write: %v", err)
		}
	}
	if err := v.Close(); err != nil {
		return fail("close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail("%v", err)
	}
	if len(raw) != size {
		return fail("file of %d bytes, want %d", len(raw), size)
	}

	// Botan, end to end.
	var master []byte
	used := []string{}
	hk, derr := t.derive(k, pass, raw[:64])
	if derr == nil {
		master, err = openHeader(t, c.links, hk, raw[64:512], size)
		clear(hk)
		if err != nil {
			return fail("header: %v", err)
		}
		for _, s := range sectors {
			off := dataOff + s*sectorSize
			got, err := xtsChain(t, c.links, master, raw[off:off+sectorSize], nonce(uint64(off/sectorSize)), true)
			if err != nil {
				return fail("%v", err)
			}
			if !bytes.Equal(got, plaintext(s)) {
				return fail("sector %d decrypts to something else", s)
			}
		}
		used = append(used, "Botan: header and 5 sectors")
	}

	// cryptsetup, where it can.
	out, derr2 := t.dump(path)
	if derr2 == nil {
		chain, mk, payload, err := parseDump(out)
		if err != nil {
			return fail("%v", err)
		}
		if chain != string(c.name) || payload != dataOff/sectorSize || len(mk) != 64*len(c.links) {
			return fail("cryptsetup reports chain %s, payload offset %d, %d key bytes", chain, payload, len(mk))
		}
		if master == nil { // Botan could not derive: judge the data with cryptsetup's key
			for _, s := range sectors {
				off := dataOff + s*sectorSize
				got, err := dumpChain(t, c.links, mk, raw[off:off+sectorSize], nonce(uint64(off/sectorSize)))
				if err != nil {
					return fail("%v", err)
				}
				if !bytes.Equal(got, plaintext(s)) {
					return fail("sector %d decrypts to something else (cryptsetup's key)", s)
				}
			}
			used = append(used, "cryptsetup: 5 sectors")
		} else {
			// Both opened it: cryptsetup's key blocks must be the ones the
			// transcribed offsets cut out of the master keys Botan found.
			for i, l := range c.links {
				want := append(append([]byte{}, master[l.keyOff:l.keyOff+32]...), master[l.tweakOff:l.tweakOff+32]...)
				if !bytes.Equal(mk[64*i:64*i+64], want) {
					return fail("cryptsetup's key block %d differs from the master key Botan found", i)
				}
			}
			used = append(used, "cryptsetup: same chain, offset and keys")
		}
	}
	if len(used) == 0 {
		// Not judged by either. Only the stated gap may land here.
		if k.name == veracrypt.Streebog || k.name == veracrypt.Argon2id || strings.Contains(string(c.name), "kuznyechik") {
			return verdict{name, "UNJUDGED", fmt.Sprintf("botan: %v; cryptsetup: %s", derr, lastLine(out))}
		}
		return fail("nobody judged it: botan: %v; cryptsetup: %s", derr, lastLine(out))
	}
	if derr != nil && k.name != veracrypt.BLAKE2s && k.name != veracrypt.Argon2id {
		return fail("botan cannot derive the header key: %v", derr)
	}
	if derr2 != nil && !(k.name == veracrypt.Streebog || k.name == veracrypt.Argon2id || strings.Contains(string(c.name), "kuznyechik")) {
		return fail("cryptsetup refuses the volume: %s", lastLine(out))
	}
	return verdict{name, "OK", strings.Join(used, "; ")}
}

// dumpChain decrypts with cryptsetup's per-link 64-byte key blocks.
func dumpChain(t tools, links []link, mk, data, nonce []byte) ([]byte, error) {
	p := data
	for i := len(links) - 1; i >= 0; i-- {
		if 64*(i+1) > len(mk) {
			return nil, fmt.Errorf("volume key of %d bytes too short", len(mk))
		}
		var err error
		if p, err = t.xts(links[i].botan, mk[64*i:64*i+64], nonce, p, true); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// openHeader decrypts the 448 header bytes with the header key hk and checks
// them against the VeraCrypt specification's header layout; it returns the
// 256-byte master key area.
func openHeader(t tools, links []link, hk, enc []byte, size int) ([]byte, error) {
	d, err := xtsChain(t, links, hk, enc, nonce(0), true)
	if err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(d[:4]) != "VERA" {
		return nil, errors.New("no VERA magic after decrypting the header")
	}
	if be.Uint16(d[4:]) != 5 || be.Uint16(d[6:]) < 0x010b {
		return nil, fmt.Errorf("header version %d, minimum program %#x", be.Uint16(d[4:]), be.Uint16(d[6:]))
	}
	if crc32.ChecksumIEEE(d[:188]) != be.Uint32(d[188:]) {
		return nil, errors.New("header CRC-32 (bytes 64-251) does not match")
	}
	if crc32.ChecksumIEEE(d[192:448]) != be.Uint32(d[8:]) {
		return nil, errors.New("master key CRC-32 (bytes 256-511) does not match")
	}
	// The spec's reserved fields (bytes 76-91 and 132-251) must be zero.
	if !bytes.Equal(d[12:28], make([]byte, 16)) || !bytes.Equal(d[68:188], make([]byte, 120)) {
		return nil, errors.New("reserved header fields are not zero")
	}
	if be.Uint64(d[28:]) != 0 || be.Uint64(d[36:]) != uint64(size-2*dataOff) || be.Uint64(d[44:]) != dataOff ||
		be.Uint64(d[52:]) != uint64(size-2*dataOff) || be.Uint32(d[60:]) != 0 || be.Uint32(d[64:]) != sectorSize {
		return nil, errors.New("header sizes, offset, flags or sector size are not the spec's for a 1 MiB normal volume")
	}
	return d[192:448], nil
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
		Short:        "check created VeraCrypt volumes with Botan and cryptsetup",
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
			t, err := c.tools()
			if err != nil {
				return err
			}
			return run(t, c.dir, pass, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.dir, "dir", "", "directory for the volumes (durable, outside any repository)")
	f.StringVar(&c.passFile, "passfile", "", "file holding the passphrase, no newline")
	f.StringVar(&c.cryptsetup, "cryptsetup", "/usr/sbin/cryptsetup", "cryptsetup binary")
	f.StringVar(&c.botanLib, "botan-lib", "libbotan-3.so", "path of libbotan-3.so")
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
