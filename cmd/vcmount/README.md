# vcmount

Mounts volumes written by `github.com/go-fde/veracrypt`'s `Create` as root in a
throwaway Linux VM, with `cryptsetup open --type tcrypt --veracrypt` and
`veracrypt --text --mount`, and compares the plaintext sector for sector with
what `Create` wrote. A second pass makes ext4 (and FAT) inside the volume and
reads a file back. See the package comment in `main.go` for the protocol, and
the pull requests (#22 and its patch) for the results: 90 volumes, 0 failed.

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o vcmount-arm64 .
go build -o vcmount-host .
VCMOUNT=1 ./vcmount-host host --vm vcoracle-vm --passfile pw.txt --guest-bin vcmount-arm64
```

The passphrase file holds at least 20 bytes and no newline. Keep it outside
any repository; it goes into the VM through the standard input of
`tart exec -i`, onto its tmpfs, and is deleted afterwards (also on SIGINT and
SIGTERM). The volumes use PIM 1 and a test passphrase: do not reuse a real one.

## The VM: `vcoracle-vm`

`vcoracle-vm` is the judge for future runs. If it disappears, recreate it from
scratch on a Mac with [Tart](https://tart.run) (`brew install cirruslabs/cli/tart`):

```sh
tart clone ghcr.io/cirruslabs/ubuntu:latest vcoracle-vm
```

The image is Ubuntu 24.04 arm64 with the `admin` user, passwordless `sudo`, an
SSH server and the Tart guest agent (`tart exec` works). Nothing else is done
by hand: `vcmount host` starts the VM, installs `libfuse2t64`, `cryptsetup`,
`e2fsprogs`, `dosfstools`, `gnupg` and `curl`, downloads VeraCrypt console
1.26.31 (arm64 `.deb`), checks its SHA-256 and its PGP signature against the
pinned fingerprint `5069A233D55A0EEB174A5FC3821ACD02680D16DE` (a good, valid,
unexpired and unrevoked signature is required), installs it, and stops the VM
when it is done. The VM needs network access (NAT is enough) for those
downloads and needs no Tart GUI or macOS permission beyond Virtualization.framework.
Check the image with `tart exec vcoracle-vm id` once it runs.

The cryptsetup in the image is 2.7.0 on OpenSSL 3: it cannot open Kuznyechik
chains, Streebog or Argon2id volumes (it answers "No device header detected"),
and the run treats exactly that refusal, for exactly those combinations, as
expected; VeraCrypt itself judges them.

## Why not gogost

The sibling oracle `cmd/vcoracle` judges Kuznyechik and Streebog with Botan
through its C interface (purego, no cgo). `gogost`, the pure-Go GOST library, was
considered and dropped: the upstream host `go.cypherpunks.su` cannot be fetched
through the Go proxy, and the GitHub forks that are listed are GPL-3.0, which
must not be linked into this BSD-3-Clause repository.
