package veracrypt

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/go-encryptions/camellia"
	"github.com/go-encryptions/kuznyechik"
	"github.com/go-encryptions/serpent"
	"github.com/go-encryptions/twofish"
	"github.com/go-encryptions/xts"
)

// Cipher names an XTS cipher or cascade, as cryptsetup names it: the
// ciphers in the order of its table, which is the REVERSE of VeraCrypt's
// display name (VeraCrypt's "AES-Twofish" is "twofish-aes" here).
type Cipher string

// The ciphers this version decrypts: every XTS chain of cryptsetup's table.
const (
	AES                       Cipher = "aes"
	Serpent                   Cipher = "serpent"
	Twofish                   Cipher = "twofish"
	TwofishAES                Cipher = "twofish-aes"
	SerpentTwofishAES         Cipher = "serpent-twofish-aes"
	AESSerpent                Cipher = "aes-serpent"
	AESTwofishSerpent         Cipher = "aes-twofish-serpent"
	SerpentTwofish            Cipher = "serpent-twofish"
	Camellia                  Cipher = "camellia"
	Kuznyechik                Cipher = "kuznyechik"
	KuznyechikCamellia        Cipher = "kuznyechik-camellia"
	TwofishKuznyechik         Cipher = "twofish-kuznyechik"
	SerpentCamellia           Cipher = "serpent-camellia"
	AESKuznyechik             Cipher = "aes-kuznyechik"
	CamelliaSerpentKuznyechik Cipher = "camellia-serpent-kuznyechik"
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
	{Serpent, []chainLink{{serpent.NewCipher, 0, 32}}},
	{Twofish, []chainLink{{twofishBlock, 0, 32}}},
	{TwofishAES, []chainLink{{twofishBlock, 0, 64}, {aes.NewCipher, 32, 96}}},
	{SerpentTwofishAES, []chainLink{{serpent.NewCipher, 0, 96}, {twofishBlock, 32, 128}, {aes.NewCipher, 64, 160}}},
	{AESSerpent, []chainLink{{aes.NewCipher, 0, 64}, {serpent.NewCipher, 32, 96}}},
	{AESTwofishSerpent, []chainLink{{aes.NewCipher, 0, 96}, {twofishBlock, 32, 128}, {serpent.NewCipher, 64, 160}}},
	{SerpentTwofish, []chainLink{{serpent.NewCipher, 0, 64}, {twofishBlock, 32, 96}}},
	{Camellia, []chainLink{{camellia.NewCipher, 0, 32}}},
	{Kuznyechik, []chainLink{{kuznyechik.NewCipher, 0, 32}}},
	{KuznyechikCamellia, []chainLink{{kuznyechik.NewCipher, 0, 64}, {camellia.NewCipher, 32, 96}}},
	{TwofishKuznyechik, []chainLink{{twofishBlock, 0, 64}, {kuznyechik.NewCipher, 32, 96}}},
	{SerpentCamellia, []chainLink{{serpent.NewCipher, 0, 64}, {camellia.NewCipher, 32, 96}}},
	{AESKuznyechik, []chainLink{{aes.NewCipher, 0, 64}, {kuznyechik.NewCipher, 32, 96}}},
	{CamelliaSerpentKuznyechik, []chainLink{{camellia.NewCipher, 0, 96}, {serpent.NewCipher, 32, 128}, {kuznyechik.NewCipher, 64, 160}}},
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
