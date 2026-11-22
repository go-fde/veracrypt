# vcoracle

Checks volumes written by `github.com/go-fde/veracrypt`'s `Create` with Botan 3
and cryptsetup (see the package comment in `main.go`). Needs `VCORACLE=1`.

```sh
VCORACLE=1 vcoracle --dir ~/vc-oracle --secret systemd-creds:vcoracle-pass
```

## The passphrase: `--secret`

`--secret <ref>` names where the passphrase comes from; it is resolved by
[go-authn/secretsource](https://github.com/go-authn/secretsource) v0.8.0, so the
reference may sit in argv or a shell history, the secret never does.

| Reference | Source |
|---|---|
| `systemd-creds:NAME` | a systemd credential (`$CREDENTIALS_DIRECTORY`, e.g. `LoadCredentialEncrypted=`), byte for byte |
| `keychain:SERVICE/ACCOUNT` | a macOS Keychain item |
| `keepassxc:...` | a KeePassXC entry |
| `file:PATH` | a regular file, mode 0600 or stricter, owned by you, not a symlink; one trailing newline is stripped |

A loose mode, a symlink or a secret longer than 4096 bytes is refused before
anything runs. The check is made when the file is opened, so a symlink at the
last component is refused for good: point `--secret file:` (or `--passfile`) at
the real file, not at a link to it (secretsource v0.9.0). The file must also be
owned by the user running the tool.

`--passfile PATH` is deprecated and means `--secret file:PATH` (same checks,
plus a warning on stderr). It is mutually exclusive with `--secret`.

If you seal a credential to a TPM with `systemd-creds encrypt`, do not pin it
to a bare `--tpm2-pcrs=7`: a firmware or shim update (or a vTPM migration)
changes the measured state and the credential becomes unreadable. Keep a
recovery path: seal with `host+tpm2` and no PCRs, or bind a signed PCR policy
(`--tpm2-public-key`), or use systemd-pcrlock, or keep a documented re-seal
procedure with the passphrase stored elsewhere.
