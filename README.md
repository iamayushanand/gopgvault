# GoPass

GoPass is a CLI password manager inspired by the UNIX `pass` tool. It stores
vault metadata as CSV and encrypts each vault with GPG.

## Prerequisites

- `gpg`, with a default secret key configured for the current user
- `less`, used to display retrieved secrets

## Build

```sh
go build -o gopass .
```

## Usage

```text
gopass create-vault <vault-name> <filepath>
gopass add-key <key> [--vault <vault-name>]
gopass get-key <key> [--vault <vault-name>]
```

The vault flag defaults to `default` and can appear before or after the
command. Both of these forms select the same vault:

```sh
gopass --vault work add-key services/example
gopass add-key services/example --vault work
```

On first use, GoPass creates `~/.gopassrc` and an encrypted default vault at
`~/.gopass/default.gopass`. Creating a named vault initializes an empty
encrypted file and registers its path in `~/.gopassrc`. Existing files are
never overwritten by `create-vault`.
