package veracrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/crc32"

	"github.com/go-encryptions/kdfbudget"
	"github.com/go-encryptions/streebog"
	"github.com/go-encryptions/whirlpool"
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

// The KDFs this version derives with: every row of cryptsetup's
// tcrypt_kdf[] (the boot rows reuse these names).
const (
	SHA512    KDF = "sha512"
	SHA256    KDF = "sha256"
	BLAKE2s   KDF = "blake2s-256"
	RIPEMD160 KDF = "ripemd160"
	Whirlpool KDF = "whirlpool"
	Streebog  KDF = "stribog512" // GOST R 34.11-2012, 512-bit
	Argon2id  KDF = "argon2id"
	SHA1      KDF = "sha1" // TrueCrypt legacy only
)

// kdfVariant is one row of cryptsetup's tcrypt_kdf[]: a KDF with its
// default cost and, for VeraCrypt, its PIM formula.
type kdfVariant struct {
	kdf       KDF
	veracrypt bool
	legacy    bool // TrueCrypt's oldest (SHA-1) mode
	boot      bool // VeraCrypt's BIOS boot loader's cheaper rows: system encryption only
	iter      int  // PBKDF2 iterations, or Argon2id passes
	memKiB    uint32
	pimConst  int
	pimMult   int
}

// kdfVariants follows cryptsetup's tcrypt_kdf[] order. The boot rows
// (tcrypt.c:38, 41, 43; the Streebog one is commented out there too) cost
// 200000 iterations for SHA-256 and BLAKE2s and 327661 for RIPEMD-160, and
// their PIM formula is 2048 * PIM; they are tried for system encryption
// only. That is a deliberate difference from cryptsetup, which tries them
// for every volume: VeraCrypt writes these costs only into the headers of
// system volumes, so trying them elsewhere adds three derivations to every
// wrong-password trial and can open nothing.
var kdfVariants = []kdfVariant{
	{kdf: RIPEMD160, iter: 2000},
	{kdf: RIPEMD160, iter: 1000},
	{kdf: SHA512, iter: 1000},
	{kdf: Whirlpool, iter: 1000},
	{kdf: SHA1, legacy: true, iter: 2000},
	{kdf: SHA512, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: Whirlpool, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: SHA256, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: SHA256, veracrypt: true, boot: true, iter: 200000, pimMult: 2048},
	{kdf: Argon2id, veracrypt: true, iter: 6, memKiB: 425984},
	{kdf: BLAKE2s, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
	{kdf: BLAKE2s, veracrypt: true, boot: true, iter: 200000, pimMult: 2048},
	{kdf: RIPEMD160, veracrypt: true, iter: 655331, pimConst: 15000, pimMult: 1000},
	{kdf: RIPEMD160, veracrypt: true, boot: true, iter: 327661, pimMult: 2048},
	{kdf: Streebog, veracrypt: true, iter: 500000, pimConst: 15000, pimMult: 1000},
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
	case Whirlpool:
		return whirlpool.New
	case Streebog:
		return streebog.New512
	default: // SHA1
		return sha1.New
	}
}

// cost returns the PBKDF2 iterations or Argon2id (passes, memory) a variant
// costs with pim (0: the default), as cryptsetup's TCRYPT_init_hdr computes
// them.
// It is computed in uint64: pimMult*pim overflows an int on a 32-bit platform
// once a caller raises Limits.MaxPIM. pim is never negative here.
func (v kdfVariant) cost(pim int) (iter uint64, memKiB uint32) {
	if pim == 0 || !v.veracrypt {
		return uint64(v.iter), v.memKiB
	}
	p := uint64(pim)
	if v.kdf == Argon2id {
		if p <= 31 {
			return (p-1)/3 + 3, uint32(1024 * (64 + (p-1)*32))
		}
		return p - 18, 1024 * 1024
	}
	return uint64(v.pimConst) + uint64(v.pimMult)*p, 0
}

// hashCost and hashSize give a PBKDF2 variant's kdfbudget cost per
// compression and its digest size, which sets how many output blocks the
// 192-byte header key takes: 3 for a 64-byte digest, 6 for 32, 10 for 20.
func hashCost(k KDF) (cost uint64, size int) {
	switch k {
	case SHA512:
		return kdfbudget.CostSHA512, 64
	case Whirlpool:
		return kdfbudget.CostWhirlpool, 64
	case Streebog:
		return kdfbudget.CostStreebog, 64
	case SHA256:
		return kdfbudget.CostSHA256, 32
	case BLAKE2s:
		return kdfbudget.CostBLAKE2s, 32
	case RIPEMD160:
		return kdfbudget.CostRIPEMD160, 20
	default: // SHA1
		return kdfbudget.CostSHA1, 20
	}
}

// charge bills b for the derivation of pim, before it runs: the PBKDF2
// blocks of the 192-byte key, or one Argon2id run. A refusal wraps ErrLimit
// and spends nothing.
func (v kdfVariant) charge(b *kdfbudget.Budget, pim int) error {
	iter, mem := v.cost(pim)
	if v.kdf == Argon2id {
		return b.ChargeArgon2(uint64(mem), iter, 1)
	}
	cost, size := hashCost(v.kdf)
	// One call for all the blocks, not one per block: the work is the same,
	// and a refusal spends nothing, where a loop would leave the blocks
	// charged before the one that did not fit.
	blocks := uint64((headerKeyLen + size - 1) / size)
	return b.ChargePBKDF2(cost*blocks, iter)
}

func (v kdfVariant) derive(pool, salt []byte, pim int) []byte {
	iter, mem := v.cost(pim)
	if v.kdf == Argon2id {
		return argon2.IDKey(pool, salt, uint32(iter), mem, 1, headerKeyLen)
	}
	return pbkdf2.Key(pool, salt, int(iter), headerKeyLen, hashFor(v.kdf))
}

// deriveKey is what unlockHeader derives with; tests replace it to count the
// derivations a refusal must prevent.
var deriveKey = kdfVariant.derive

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
