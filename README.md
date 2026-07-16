# GoPass

A cli password manager inspired by the UNIX pass tool. 

## Interface

```
gopass create-vault <vault name> <filepath>
gopass add-key <key path> [--vault <vault name>]
gopass get-key <key path> [--vault <vault name>]
gopass set-gpg-key <vault name> <gpg key>
```