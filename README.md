# veracrypt

Read VeraCrypt and TrueCrypt volumes, and create VeraCrypt volumes, in pure Go.

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
| KDFs | every KDF cryptsetup's tcrypt tries: PBKDF2 with SHA-512, SHA-256, BLAKE2s-256, RIPEMD-160, Whirlpool or Streebog-512; Argon2id; TrueCrypt's PBKDF2-SHA-1 with `Legacy`; with `System`, also VeraCrypt's boot rows (SHA-256 and BLAKE2s-256 at 200,000 iterations, RIPEMD-160 at 327,661, PIM multiplier 2048); not VeraCrypt's Streebog boot row (200,000 iterations), which cryptsetup comments out too (`tcrypt.c:45`) |
| Options | PIM, keyfiles (up to 1 MiB each), passwords up to 128 bytes |
| Volumes | normal, hidden, backup headers; system encryption (`System`); VeraCrypt and TrueCrypt 5.0 and later |

## System encryption

`Options{System: true}` opens an encrypted boot drive or system partition,
read-only. Give it the whole drive (or an image of it): the header is at
byte 31744 of the drive, outside the encrypted area, so an image of the
partition alone has no header to read. The system flag must be set in the
header, as cryptsetup's `--tcrypt-system` does.

`ReadAt` offsets are relative to the start of the encrypted area, which is
`Header().MKOffset` on the drive, and the area is `Header().VolumeSize`
long:

- an encrypted **partition**: offset 0 is the partition's first byte, so the
  filesystem is at 0;
- a **whole-drive** encryption: the area starts at sector 63 or later, in
  front of the first partition, so a partition starting at sector `S` is at
  offset `S*512 - MKOffset`. The MBR and the boot loader before the area are
  not encrypted and are not part of the device; read them from the drive.

The XTS tweak of each sector is its sector number on the drive, as in
cryptsetup (`iv_offset`). A hidden operating system, and `System` combined
with `Hidden` or `Backup`, are refused with `ErrUnsupported`.

The following are **not supported yet**. A volume that uses them fails like
a wrong password, because nothing on disk can tell the two apart.

- TrueCrypt's LRW and CBC modes, and headers older than version 3.

These are refused with `ErrUnsupported`:

- a hidden operating system (a system header that records a hidden size),
  and a system header opened without `System`;
- sector sizes other than 512 bytes.

A `Device` is read-only: `WriteAt` returns `ErrReadOnly`. Volumes are
written through `Create`, below.

## Creating a volume

```go
v, err := veracrypt.CreateFile("new.hc", 64<<20, []byte("a long password"),
	veracrypt.CreateOptions{
		Cipher: veracrypt.SerpentTwofishAES, // default AES
		KDF:    veracrypt.SHA512,            // default SHA512
		PIM:    0,                           // 0: the default cost
	})
if err != nil {
	log.Fatal(err)
}
defer v.Close()
_, err = v.WriteAt(data, 0) // plaintext in, ciphertext on disk
```

`Create(w, size, password, opts)` does the same on any `ReadWriterAt`
(`io.ReaderAt` and `io.WriterAt`); `CreateFile` makes a new file with mode
0600 and refuses an existing one. The `Volume` is a plaintext view of the
data area: `ReadAt`, `WriteAt` (any offset and length; partial sectors are
read, merged and re-encrypted) and `Size`. There is no filesystem inside:
the data area is `size - 262144` bytes of whatever you write.

What `Create` writes, for a container of `S` bytes (the *VeraCrypt Volume
Format Specification*, header layout table and "Embedded Backup Headers";
`Volumes.c` `CreateVolumeHeaderInMemory`; `Format.c` `FormatVolume`):

| Offset | Size | |
|---|---|---|
| 0 | 512 | primary header: 64-byte random salt, then 448 bytes in XTS under the header key (`VERA`, header version 5, minimum program version 1.11, both CRC-32s, volume size, master key offset 131072, sector size 512, the 256-byte master key area) |
| 512 | 65,024 | random (reserved) |
| 65,536 | 65,536 | random: the area of a hidden volume's header. No hidden volume is created, and the area looks as it does on VeraCrypt volumes that have none |
| 131,072 | `S - 262144` | data area: tweak of its first sector is 256 |
| `S - 131072` | 512 | backup header: the same master keys under a new salt |
| `S - 130560` | 65,024 | random (reserved) |
| `S - 65536` | 65,536 | random: the backup area of a hidden volume's header |

Salts and master keys come from `crypto/rand`, as does the fill. By default
the data area is filled with random bytes, like VeraCrypt's full format
(which encrypts random data under throw-away keys; random bytes are
indistinguishable from that and cost no cipher time). `CreateOptions.Quick`
skips the fill, like VeraCrypt's `--quick`: the data area stays as the
writer has it, a sparse file of zeros for a new file, whose ciphertext
decrypts to noise but is distinguishable from a filled volume.

Options: every cipher and cascade the reader opens; the KDFs PBKDF2 with
SHA-512, SHA-256, BLAKE2s-256, Whirlpool or Streebog-512 (not RIPEMD-160,
which VeraCrypt 1.26 no longer offers: its volumes only cryptsetup reads), and
Argon2id; PIM up to `MaxPIM` (100,000); keyfiles (`Keyfiles`, as in
`Options`). The size is a multiple of 512 from `MinSize` (299,008,
VeraCrypt's `TC_MIN_VOLUME_SIZE`) to `MaxSize` (1 PiB, `TC_MAX_VOLUME_SIZE`).
A store with a `Truncate` method (an `*os.File`) is cut to `size` first; any
other store must be empty or exactly `size` long, so that the backup header
lies at its end. The backup header is written before the primary one. Every refusal wraps `ErrOption` and nothing is written.
Not created: hidden volumes, system encryption, TrueCrypt volumes,
filesystems. A FAT or exFAT writer on top of `Volume` is a follow-up.

Key material is zeroed where Go allows it: the password pool and the header
keys right after use, the master keys on `Close` (after which reads and
writes fail with `ErrClosed`). The cipher schedules inside the cipher
libraries cannot be zeroed. A weak XTS key (equal data and tweak keys) is
refused.

### Created volumes, opened by other programs

- **Our reader:** `TestCreateRoundTripMatrix` creates and reopens every one
  of the 15 chains with each of the 6 KDFs (PIM 1), through the primary and
  through the backup header, and reads back what was written.
- **cryptsetup 2.7.0** (Linux, no root): `cryptsetup tcryptDump --veracrypt`,
  passphrase on standard input, reads the header of 40 combinations (10
  chains with PBKDF2 SHA-512, SHA-256, BLAKE2s, Whirlpool) and
  reports the version (5), the sector size (512), the MK offset (131072),
  the hash, the cipher chain, the mode (`xts-plain64`) and the key size we
  wrote; `--tcrypt-backup` reads the backup header; `--tcrypt-hidden` finds
  no hidden volume. Its OpenSSL backend has neither Kuznyechik nor
  Streebog, so the 35 combinations that use them are not checked by cryptsetup.
- **VeraCrypt 1.26.31** (console build, Linux, no root): mounting needs
  administrator rights, so the checks are the commands that do not.
  `--backup-headers` decrypts our header with the password and PIM;
  `--restore-headers` from the embedded backup decrypts our backup header,
  and the restored volume opens with our reader, with the same master keys
  and data area. The header fields of a volume VeraCrypt created itself
  (`--create`, AES, SHA-512, PIM 1) equal ours.
- **Speed:** a 64 MiB AES/SHA-512 PIM 1 container with a full fill takes
  123 ms with `Create` and 0.74 s with `veracrypt --text --create`, on one
  Ryzen 9 7950X (`BenchmarkCreate64MiB`; the VeraCrypt time includes its
  process start).

`TestWriteOracleVolumes`, `TestCryptsetupAccepts` and `TestVeraCryptRestored`
run these checks when `VERACRYPT_ORACLE_DIR` (and `VERACRYPT_CRYPTSETUP`)
are set, and skip otherwise.

## How it is checked

The tests open the images in cryptsetup's `tests/tcrypt-images.tar.xz`,
which VeraCrypt and TrueCrypt made, with the passwords, PIMs and keyfiles
of `tests/tcrypt-compat-test`. The FAT filesystem inside must have the
UUID that test checks: `DEAD-BABE`, or `CAFE-BABE` in a hidden volume.

- All 65 XTS volumes open and match, covering:
  - VeraCrypt and TrueCrypt;
  - SHA-512, SHA-256, BLAKE2s, RIPEMD-160, Whirlpool, Streebog-512 and
    Argon2id;
  - PIM, keyfiles, and a 72-byte password;
  - hidden volumes, including TrueCrypt 5's;
  - the three system-encryption images (`sys_vc_1_mbr_full`,
    `sys_vc_1_mbr_part` and `sys_vc_1_gpt_part`, up to 66 MiB), opened as
    `--tcrypt-system` does, with the same FAT UUID;
  - every cipher alone, and seven of the ten cascades.
- The 28 LRW and CBC volumes (TrueCrypt before 5.0) must be refused rather
  than misread.

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
before any derivation that would exceed them. However high `MaxPIM` is
raised, a PIM above VeraCrypt's own maxima (2147468, or 65535 for system
encryption) is refused.

`Limits.Budget` (a [kdfbudget](https://github.com/go-encryptions/kdfbudget)
`*Budget`) bounds the TOTAL derivation work of one open: every KDF tried,
and both headers of a hidden-volume open, are charged to it before they run.
Nil means a fresh `kdfbudget.Default()` per open. This is what bounds
Argon2id, whose passes `MaxIterations` does not count: a PIM of 2000 is 1982
passes over 1 GiB, four times the default budget, and is refused. A KDF the
limits or the budget refused is skipped; if nothing else opens the volume the
error is `ErrLimit`, never `ErrWrongSecret`. Pass `kdfbudget.Unlimited()` for
a volume you trust.

Once decrypted, the header is checked before use:

- both CRC-32s;
- the data area lies inside the device;
- every offset is aligned to the sector size;
- a system data area does not overlap the header at 31744.

`FuzzParse` fuzzes those checks.

## Performance

- AES volumes decrypt through
  [go-encryptions/xts](https://github.com/go-encryptions/xts) v0.3.1
  `DecryptSectors`, which is ahead of OpenSSL on one core.
- Twofish goes through
  [go-encryptions/twofish](https://github.com/go-encryptions/twofish)
  v0.1.1, with Botan's full-key precomputed tables. xts hands it a whole
  sector per call, which it runs four blocks at a time, and since v0.3.1
  it keeps the tweak in 64-bit words. A Twofish-XTS 4 KiB read runs at
  about **611 MiB/s** on one Apple M4 Max core, against 486 MiB/s for
  Botan 3.14.1's own Twofish/XTS on the same machine, and about 133 MiB/s
  with the former `golang.org/x/crypto/twofish` (the v0.5.0 side of the
  `abbench` run posted on veracrypt#3). The figures come from xts's
  `BenchmarkBatchTwofish` and this package's `BenchmarkXTSDecryptTwofish`,
  interleaved rounds with `abbench`.
- Serpent goes through
  [go-encryptions/serpent](https://github.com/go-encryptions/serpent)
  v0.2.0, bitsliced pure Go, four blocks at a time through xts's batch
  path. A Serpent-XTS 4 KiB read runs at about 289 MiB/s on one Apple M4
  Max core, against 127 MiB/s with v0.1.0's one block at a time (+127 %,
  `BenchmarkXTSDecryptSerpent`, 6 interleaved rounds with `abbench`,
  p = 0.002). serpent's own batch path is level with Botan's NEON Serpent
  for decryption and 1.28× faster for encryption. amd64, where Botan runs
  8–16 blocks with AVX2, is not measured yet (go-encryptions/serpent#2).
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
