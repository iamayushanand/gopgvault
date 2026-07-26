# GoPass

GoPass is a CLI password manager inspired by the UNIX `pass` tool. It stores
vault metadata as CSV and encrypts each vault with GPG.

## Prerequisites

- `gpg`, with a default secret key configured for the current user (or an
  explicit recipient supplied with `--gpg`)
- `grep`, used to search key names
- `less`, used to display retrieved secrets

## Build

```sh
go build -o gopass .
```

Go source follows the standard module-root layout: Cobra commands live in
`cmd`, config persistence in `config`, and encrypted vault operations in
`vault`.

## Usage

```text
gopass create-vault <vault-name> <filepath> [--gpg <recipient>]
gopass add-key <key> [--vault <vault-name>] [--overwrite]
gopass get-key <key> [--vault <vault-name>]
gopass get-key --grep <pattern> [--vault <vault-name>]
gopass list-keys [--vault <vault-name>]
gopass import-secrets <csv-file> [--vault <vault-name>] [--overwrite]
gopass copy-secrets <source-vault> <destination-vault> [--overwrite]
```

The vault flag defaults to `default` for `add-key`, `get-key`, and `list-keys`.
For `import-secrets`, omitting it starts the new-vault prompt. Command-local
flags can appear before or after positional arguments:

```sh
gopass add-key --vault work services/example
gopass add-key services/example --vault work
```

`create-vault --gpg` accepts any recipient selector understood by GPG. GoPass
stores that selector in `~/.gopassrc` and reuses it whenever the vault is
updated. Vaults created without the flag continue to use GPG's default
self-recipient.

`get-key --grep` runs a basic regular-expression search over key names only and
displays all matching key/secret pairs with `less`. `list-keys` prints key names
directly to standard output for scripting.

Import files use the same headerless, two-column `key,secret` CSV format as the
decrypted vault data. Supplying `--vault` imports into an existing vault;
otherwise GoPass prompts for a new vault name and path. Successful imports print
a prominent reminder to delete the plaintext CSV. Duplicate keys abort imports,
copies, and additions unless `--overwrite` is supplied. Within an overwritten
import, the final row for a duplicate key wins.

`copy-secrets` copies all entries and leaves the source vault unchanged. Its two
vault arguments are configured vault names.

Run `gopass --help` or `gopass <command> --help` for Cobra-generated command
and flag documentation.

On first use, GoPass creates `~/.gopassrc` and an encrypted default vault at
`~/.gopass/default.gopass`. Creating a named vault initializes an empty
encrypted file and registers its path in `~/.gopassrc`. Existing files are
never overwritten by `create-vault`.

## Security Notes

GoPass keeps application-owned secrets in mutable byte buffers and wipes those
buffers after use. This is a best-effort reduction of plaintext lifetime, not a
guarantee of secure memory erasure: the Go compiler and runtime may make copies,
memory can be swapped or included in a core dump, and `encoding/csv` creates a
short-lived immutable string while decoding each record.

Each vault is one encrypted document. Reading or modifying an entry therefore
decrypts the vault, although buffers are cleared when the operation completes.
The GPG and pager subprocesses and their kernel pipes also temporarily handle
plaintext.

Secret display runs `less` in secure mode, disables its history, removes
user-configurable preprocessors and option variables, and does not allow raw
terminal escape rendering. A terminal emulator, multiplexer, screen recorder,
or redirected output may still capture displayed content.

CSV imports are plaintext files. Prefer tightly restricted permissions and
delete the source immediately after a successful import; deletion may not be
secure erasure on SSDs, copy-on-write filesystems, snapshots, or backups.
