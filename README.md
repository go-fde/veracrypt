# veracrypt

Read VeraCrypt and TrueCrypt volumes in pure Go.

```go
dev, err := veracrypt.Open("volume.hc", veracrypt.Options{
	Password: []byte("password"),
	// Keyfiles: [][]byte{kf1, kf2}, PIM: 485, Hidden: true, …
})
if err != nil {
	log.Fatal(err)
}
defer dev.Close()
boot := make([]byte, 512)
_, err = dev.ReadAt(boot, 0) // the filesystem's first sector
```

`OpenFrom(r, size, opts)` reads from any `io.ReaderAt`, such as a partition
or a virtual disk.

## How a volume opens

A VeraCrypt header looks like random bytes: nothing on disk names the key
derivation or the cipher. Opening a volume therefore works by trial, as in
cryptsetup's tcrypt support:

1. Every allowed KDF derives a key from the password and keyfiles.
2. Every allowed cipher chain decrypts the header with that key.
3. The trial stops when the header starts with `VERA` (`TRUE` for
   TrueCrypt) and its two CRC-32 checks match.

A KDF costs about half a second (500,000 PBKDF2 iterations, or Argon2id at
416 MiB). Naming the KDF and the cipher in `Options` skips the others.

## What it reads

| | |
|---|---|
| Ciphers (XTS) | every XTS chain VeraCrypt offers: AES, Camellia, Kuznyechik, Serpent, Twofish, and the cascades AES-Twofish, AES-Twofish-Serpent, Camellia-Kuznyechik, Camellia-Serpent, Kuznyechik-AES, Kuznyechik-Serpent-Camellia, Kuznyechik-Twofish, Serpent-AES, Serpent-Twofish-AES, Twofish-Serpent (cryptsetup's names list them in reverse: `twofish-aes`, `kuznyechik-camellia`, …) |
| KDFs | every non-boot KDF VeraCrypt and TrueCrypt use: PBKDF2 with SHA-512, SHA-256, BLAKE2s-256, RIPEMD-160, Whirlpool or Streebog-512; Argon2id; TrueCrypt's PBKDF2-SHA-1 with `Legacy` |
| Options | PIM, keyfiles (up to 1 MiB each), passwords up to 128 bytes |
| Volumes | normal, hidden, backup headers; VeraCrypt and TrueCrypt 5.0 and later |

The following are **not supported yet**. A volume that uses them fails like
a wrong password, because nothing on disk can tell the two apart.

- TrueCrypt's LRW and CBC modes, and headers older than version 3.

These are refused with `ErrUnsupported`:

- system encryption;
- sector sizes other than 512 bytes.

Writing is not implemented: `WriteAt` returns `ErrReadOnly`.

## How it is checked

The tests open the images in cryptsetup's `tests/tcrypt-images.tar.xz`,
which VeraCrypt and TrueCrypt made, with the passwords, PIMs and keyfiles
of `tests/tcrypt-compat-test`. The FAT filesystem inside must have the
UUID that test checks: `DEAD-BABE`, or `CAFE-BABE` in a hidden volume.

- All 62 XTS volumes open and match, covering:
  - VeraCrypt and TrueCrypt;
  - SHA-512, SHA-256, BLAKE2s, RIPEMD-160, Whirlpool, Streebog-512 and
    Argon2id;
  - PIM, keyfiles, and a 72-byte password;
  - hidden volumes, including TrueCrypt 5's;
  - every cipher alone, and seven of the ten cascades.
- The 28 LRW and CBC volumes (TrueCrypt before 5.0) must be refused rather
  than misread. System-encryption images are not read.

Reversing the cascade's decryption order fails all 22 cascade volumes, so
the order is checked. Serpent's and Kuznyechik's byte orders are confirmed
by the same images.

Three cascades have no volume in the corpus: Camellia-Serpent,
Kuznyechik-AES and Kuznyechik-Twofish. They are checked only by the test
writer's round trip, with cryptsetup's key offsets.

The corpus file names do not list the ciphers in one order. Most use
VeraCrypt's display order, but the Kuznyechik cascades use cryptsetup's.
Two chains are each other's reverse (`serpent-twofish-aes` and
`aes-twofish-serpent`), so the test tries every chain a name can mean,
and the FAT UUID decides.

The archive is GPL-2.0+, so it is fetched at test time and never
committed. Pinned by commit and SHA-256, it is read through
`TCRYPT_IMAGES`:

```sh
TCRYPT_IMAGES=/path/to/tcrypt-images.tar.xz go test ./...
```

Without it the interoperability test skips, and says so. A test-only writer
builds volumes for the unit tests, which reach every refusal and every
limit. CI requires 100 % coverage.

## Untrusted images

Trial decryption is a cost an attacker controls: a large PIM multiplies
PBKDF2's iterations and Argon2id's memory. `Limits` bounds the number of
derivations, the PIM (2000 by default), the PBKDF2 iterations and the
Argon2id memory (1 GiB by default). An open is refused with `ErrLimit`
before any derivation that would exceed them.

Once decrypted, the header is checked before use:

- both CRC-32s;
- the data area lies inside the device;
- every offset is aligned to the sector size.

`FuzzParse` fuzzes those checks.

## Performance

- AES volumes decrypt through
  [go-encryptions/xts](https://github.com/go-encryptions/xts) v0.3.0
  `DecryptSectors`, which is ahead of OpenSSL on one core.
- Twofish goes through
  [go-encryptions/twofish](https://github.com/go-encryptions/twofish)
  v0.1.1, with Botan's full-key precomputed tables. xts v0.3.0 hands it a
  whole sector per call, which it runs four blocks at a time. Against the
  previous `golang.org/x/crypto/twofish`, a Twofish-XTS 4 KiB read is
  **2.4× faster** (+141 %, `BenchmarkXTSDecryptTwofish`, 6 interleaved
  rounds with `abbench`, p = 0.002), and AES is unchanged. The comparison
  with Botan's absolute speed is still to be measured on a quiet machine
  (veracrypt#3).
- Serpent goes through
  [go-encryptions/serpent](https://github.com/go-encryptions/serpent)
  v0.1.0, bitsliced pure Go, one block at a time. It is 2.1× (encryption)
  and 2.5× (decryption) slower than Botan on one core, a gap tracked in
  go-encryptions/serpent#2.
- Camellia goes through
  [go-encryptions/camellia](https://github.com/go-encryptions/camellia)
  v0.1.0, pure Go, one block at a time. On one core it is level with
  Botan's scalar build, and 1.12× faster than its default build.
- Kuznyechik goes through
  [go-encryptions/kuznyechik](https://github.com/go-encryptions/kuznyechik)
  v0.1.0, pure Go with lookup tables. On one core it is 1.14× (encryption)
  and 1.16× (decryption) faster than Botan 3.14.1.
- The KDFs cost what the format specifies; that cost is the point of the
  format. Whirlpool and Streebog come from
  [go-encryptions/whirlpool](https://github.com/go-encryptions/whirlpool)
  and [go-encryptions/streebog](https://github.com/go-encryptions/streebog)
  v0.2.0. Both save their state, so HMAC does not rehash the key on every
  PBKDF2 iteration. Streebog is 1.8× faster than Botan; Whirlpool is 1.15×
  slower (go-encryptions/whirlpool#1).
- A wrong password costs the whole trial: every KDF, Whirlpool and Streebog
  included. Opening a Streebog volume without naming its KDF, as
  `TestCorpusFullTrial` does, took 11 s on one Apple M4 Max core, and 23 s
  on the same machine under load.
  Naming the KDF in `Options` avoids it.

## References

- cryptsetup `lib/tcrypt/tcrypt.c`: the KDF and cipher tables, the key
  offsets, the header layout and the data offsets.
- The VeraCrypt documentation (veracrypt.io): *Volume Format
  Specification*, *Header Key Derivation*, *PIM*, *Encryption Algorithms*,
  *Cascades*.

## Licence

BSD-3-Clause. The test corpus is cryptsetup's (GPL-2.0+) and is not part of
this repository.
