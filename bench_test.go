package veracrypt

import "testing"

// The block benchmarks match `botan speed <Cipher>` (1 KiB buffer, ECB
// over the block cipher): the README compares them with Botan on one core.
// The XTS benchmarks decrypt one 4 KiB run of 512-byte sectors through
// the chain, as a filesystem read does.

func benchBlock(b *testing.B, name Cipher, decrypt bool) {
	b.Helper()
	var c chain
	for _, ch := range chains {
		if ch.name == name {
			c = ch
		}
	}
	if len(c.links) == 0 {
		b.Fatalf("no chain %s", name)
	}
	blk, err := c.links[0].newBlock(testKeys[:32])
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for range b.N {
		for i := 0; i < len(buf); i += 16 {
			if decrypt {
				blk.Decrypt(buf[i:i+16], buf[i:i+16])
			} else {
				blk.Encrypt(buf[i:i+16], buf[i:i+16])
			}
		}
	}
}

func BenchmarkBlockTwofishEncrypt(b *testing.B) { benchBlock(b, Twofish, false) }
func BenchmarkBlockTwofishDecrypt(b *testing.B) { benchBlock(b, Twofish, true) }

func benchXTS(b *testing.B, name Cipher) {
	b.Helper()
	for _, c := range chains {
		if c.name == name {
			x := newXTSChain(c, testKeys[:])
			buf := make([]byte, 4096)
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for range b.N {
				x.decryptSectors(buf, 0)
			}
			return
		}
	}
	b.Fatalf("no chain %s", name)
}

func BenchmarkXTSDecryptTwofish(b *testing.B) { benchXTS(b, Twofish) }
func BenchmarkXTSDecryptAES(b *testing.B)     { benchXTS(b, AES) }
