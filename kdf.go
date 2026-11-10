package veracrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/crc32"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // TrueCrypt and VeraCrypt still use it
)

// headerKeyLen is what every KDF derives: enough for three ciphers' XTS
// keys (cryptsetup TCRYPT_HDR_KEY_LEN).
const headerKeyLen = 192

// KDF names a header key derivation, as cryptsetup names them.
type KDF string

// The KDFs this version derives with. Whirlpool and Streebog are not
// implemented yet (no Go implementation in the fleet); a volume made with
// them fails like a wrong password.
const (
	SHA512    KDF = "sha512"
	SHA256    KDF = "sha256"
	BLAKE2s   KDF = "blake2s-256"
	RIPEMD160 KDF = "ripemd160"
	Argon2id  KDF = "argon2id"
	SHA1      KDF = "sha1" // TrueCrypt legacy only
)

// kdfVariant is one row of cryptsetup's tcrypt_kdf[]: a KDF with its
// default cost and, for VeraCrypt, its PIM formula.
type kdfVariant struct {
	kdf       KDF
	veracrypt bool
	legacy    bool // TrueCrypt's oldest (SHA-1) mode
	iter      int  // PBKDF2 iterations, or Argon2id passes
	memKiB    uint32
	pimConst  int
	pimMult   int
}

// kdfVariants follows cryptsetup's tcrypt_kdf[] order, the boot-only
// variants (system encryption, not supported here) left out, Whirlpool and
// Streebog left out until they are implemented.
var kdfVariants = []kdfVariant{
	{kdf: RIPEMD160, iter: 2000},
	{kdf: RIPEMD160, iter: 1000},
	{kdf: SHA512, iter: 1000},
	{kdf: SHA1, legacy: true, iter: 2000},
	{kdf: SHA512, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: SHA256, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: Argon2id, veracrypt: true, iter: 6, memKiB: 425984},
	{kdf: BLAKE2s, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: RIPEMD160, veracrypt: true, iter: 655331, pimConst: 15000, pimMult: 1000},
}

func hashFor(k KDF) func() hash.Hash {
	switch k {
	case SHA512:
		return sha512.New
	case SHA256:
		return sha256.New
	case BLAKE2s:
		return func() hash.Hash { h, _ := blake2s.New256(nil); return h }
	case RIPEMD160:
		return ripemd160.New
	default: // SHA1
		return sha1.New
	}
}

// cost returns the PBKDF2 iterations or Argon2id (passes, memory) a variant
// costs with pim (0: the default), as cryptsetup's TCRYPT_init_hdr computes
// them.
func (v kdfVariant) cost(pim int) (iter int, memKiB uint32) {
	if pim == 0 || !v.veracrypt {
		return v.iter, v.memKiB
	}
	if v.kdf == Argon2id {
		if pim <= 31 {
			return (pim-1)/3 + 3, uint32(1024 * (64 + (pim-1)*32))
		}
		return pim - 18, 1024 * 1024
	}
	return v.pimConst + v.pimMult*pim, 0
}

func (v kdfVariant) derive(pool, salt []byte, pim int) []byte {
	iter, mem := v.cost(pim)
	if v.kdf == Argon2id {
		return argon2.IDKey(pool, salt, uint32(iter), mem, 1, headerKeyLen)
	}
	return pbkdf2.Key(pool, salt, iter, headerKeyLen, hashFor(v.kdf))
}

func (v kdfVariant) String() string {
	iter, mem := v.cost(0)
	if v.kdf == Argon2id {
		return fmt.Sprintf("argon2id-t%d-m%dKiB", iter, mem)
	}
	return fmt.Sprintf("pbkdf2-%s-%d", v.kdf, iter)
}

const (
	poolLen    = 64      // TCRYPT_KEY_POOL_LEN
	poolLenVC  = 128     // VCRYPT_KEY_POOL_LEN: VeraCrypt, password over 64 bytes
	keyfileMax = 1 << 20 // TCRYPT_KEYFILE_LEN: only the first MiB of a keyfile counts
)

// keyPool combines the password and the keyfiles the way cryptsetup's
// TCRYPT_init_hdr and TCRYPT_pool_keyfile do: each keyfile adds the four
// big-endian bytes of a running CRC-32 to the pool, byte by byte; the
// password is then added byte-wise. Without keyfiles the pool is the
// password itself. ok is false for a password longer than the pool.
func keyPool(password []byte, keyfiles [][]byte, veracrypt bool) (pool []byte, ok bool) {
	n := poolLen
	if veracrypt && len(password) > poolLen {
		n = poolLenVC
	}
	if len(password) > n {
		return nil, false
	}
	if len(keyfiles) == 0 {
		return append([]byte(nil), password...), true
	}
	pool = make([]byte, n)
	for _, kf := range keyfiles {
		if len(kf) > keyfileMax {
			kf = kf[:keyfileMax]
		}
		crc := ^uint32(0)
		j := 0
		for _, b := range kf {
			crc = crc32.Update(crc^0xffffffff, crc32.IEEETable, []byte{b}) ^ 0xffffffff
			pool[j] += byte(crc >> 24)
			pool[j+1] += byte(crc >> 16)
			pool[j+2] += byte(crc >> 8)
			pool[j+3] += byte(crc)
			j = (j + 4) % n
		}
	}
	for i, b := range password {
		pool[i] += b
	}
	return pool, true
}
