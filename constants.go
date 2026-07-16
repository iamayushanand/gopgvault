package main

import "os"

const (
	commandCreateVault = "create-vault"
	commandAddKey      = "add-key"
	commandGetKey      = "get-key"

	DefaultVaultName     = "default"
	configFilename       = ".gopassrc"
	vaultDirectoryName   = ".gopass"
	vaultFileExtension   = ".gopass"
	defaultVaultFilename = DefaultVaultName + vaultFileExtension
	vaultFlagName        = "vault"

	gpgExecutable   = "gpg"
	pagerExecutable = "less"

	directoryPermissions os.FileMode = 0o700
	filePermissions      os.FileMode = 0o600
)
