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

Go source follows the standard module-root layout: Cobra commands live in
`cmd`, config persistence in `config`, and encrypted vault operations in
`vault`.

## Usage

```text
gopass create-vault <vault-name> <filepath>
gopass add-key <key> [--vault <vault-name>]
gopass get-key <key> [--vault <vault-name>]
```

The vault flag defaults to `default` and belongs to the `add-key` and
`get-key` commands. It can appear before or after the key:

```sh
gopass add-key --vault work services/example
gopass add-key services/example --vault work
```

Run `gopass --help` or `gopass <command> --help` for Cobra-generated command
and flag documentation.

On first use, GoPass creates `~/.gopassrc` and an encrypted default vault at
`~/.gopass/default.gopass`. Creating a named vault initializes an empty
encrypted file and registers its path in `~/.gopassrc`. Existing files are
never overwritten by `create-vault`.
