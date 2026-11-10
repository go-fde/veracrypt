package veracrypt

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-encryptions/xts"
	"golang.org/x/crypto/twofish"
)

// Cipher names an XTS cipher or cascade, as cryptsetup names it: the
// ciphers in the order of its table, which is the REVERSE of VeraCrypt's
// display name (VeraCrypt's "AES-Twofish" is "twofish-aes" here).
type Cipher string

// The ciphers this version decrypts. Serpent, Camellia and Kuznyechik, and
// the cascades that use them, need implementations the fleet does not have
// yet (go-fde/fde#28); a volume made with them fails like a wrong password.
const (
	AES        Cipher = "aes"
	Twofish    Cipher = "twofish"
	TwofishAES Cipher = "twofish-aes"
)

type blockFunc func(key []byte) (cipher.Block, error)

func twofishBlock(key []byte) (cipher.Block, error) { return twofish.NewCipher(key) }

// chainLink is one cipher of a chain, with the offsets of its XTS data key
// and tweak key in a 192-byte header key or the 256-byte master key area
// (cryptsetup tcrypt_cipher[], key_offset and iv_offset).
type chainLink struct {
	newBlock         blockFunc
	keyOff, tweakOff int
}

type chain struct {
	name  Cipher
	links []chainLink
}

// chains is the XTS part of cryptsetup's tcrypt_cipher[] that this version
// can build, in its order.
var chains = []chain{
	{AES, []chainLink{{aes.NewCipher, 0, 32}}},
	{Twofish, []chainLink{{twofishBlock, 0, 32}}},
	{TwofishAES, []chainLink{{twofishBlock, 0, 64}, {aes.NewCipher, 32, 96}}},
}

// xtsChain is a chain keyed: one XTS cipher per link.
type xtsChain struct {
	name  Cipher
	links []*xts.Cipher
}

// newXTSChain keys every link with key[keyOff:+32] ‖ key[tweakOff:+32]
// (cryptsetup TCRYPT_copy_key, XTS). It cannot fail: every link takes two
// 32-byte keys, which AES and Twofish both accept.
func newXTSChain(c chain, key []byte) *xtsChain {
	x := &xtsChain{name: c.name}
	for _, l := range c.links {
		k := make([]byte, 0, 64)
		k = append(append(k, key[l.keyOff:l.keyOff+32]...), key[l.tweakOff:l.tweakOff+32]...)
		xc, _ := xts.NewCipher(l.newBlock, k)
		x.links = append(x.links, xc)
	}
	return x
}

// decryptSectors decrypts whole 512-byte units in place, the first with
// tweak first: the last link of the chain first, as cryptsetup stacks its
// device-mapper targets (and decrypts the header).
func (x *xtsChain) decryptSectors(p []byte, first uint64) {
	for i := len(x.links) - 1; i >= 0; i-- {
		x.links[i].DecryptSectors(p, p, sectorSize, first)
	}
}

// decryptUnit decrypts p as a single XTS data unit with tweak 0, link by
// link: how the 448 encrypted header bytes are laid out.
func (x *xtsChain) decryptUnit(p []byte) {
	for i := len(x.links) - 1; i >= 0; i-- {
		x.links[i].Decrypt(p, p, 0)
	}
}
