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
VCMOUNT=1 ./vcmount-host host --vm vcoracle-vm --secret keychain:vcmount/test --guest-bin vcmount-arm64
```

## The passphrase: `--secret`

`--secret <ref>` names where the passphrase comes from; it is resolved on the
host by [go-authn/secretsource](https://github.com/go-authn/secretsource)
v0.8.0, so the reference may sit in argv or a shell history, the secret never
does. It holds at least 20 bytes and no newline.

| Reference | Source |
|---|---|
| `systemd-creds:NAME` | a systemd credential (`$CREDENTIALS_DIRECTORY`, e.g. `LoadCredentialEncrypted=`), byte for byte |
| `keychain:SERVICE/ACCOUNT` | a macOS Keychain item |
| `keepassxc:...` | a KeePassXC entry |
| `file:PATH` | a regular file, mode 0600 or stricter, owned by you, not a symlink; one trailing newline is stripped |

A loose mode, a symlink or a secret longer than 4096 bytes is refused before
the VM is touched.

The passphrase reaches the guest on the standard input of `tart exec -i`, which
feeds `vcmount guest --stdin`: no file is written in the VM (it used to be
`/dev/shm/vcmount-pw`), and it is in no argument and no environment variable.
Inside the VM, `vcmount guest` also accepts `--secret` for a manual run.

`--passfile PATH` is deprecated on both subcommands and means
`--secret file:PATH` (same checks, plus a warning on stderr). It is mutually
exclusive with `--secret` (and, for `guest`, with `--stdin`).

If you seal a credential to a TPM with `systemd-creds encrypt`, do not pin it
to a bare `--tpm2-pcrs=7`: a firmware or shim update (or a vTPM migration)
changes the measured state and the credential becomes unreadable. Keep a
recovery path: seal with `host+tpm2` and no PCRs, or bind a signed PCR policy
(`--tpm2-public-key`), or use systemd-pcrlock, or keep a documented re-seal
procedure with the passphrase stored elsewhere.

The volumes use PIM 1 and a test passphrase: do not reuse a real one.

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
