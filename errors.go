package main

import "errors"

var (
	ErrMissingArguments   = errors.New("operation is missing arguments")
	ErrInvalidConfigEntry = errors.New("invalid config entry")
	ErrInvalidVaultEntry  = errors.New("invalid vault entry")
	ErrVaultExists        = errors.New("vault already exists")
	ErrVaultPathExists    = errors.New("vault path already registered")
	ErrVaultFileExists    = errors.New("vault file already exists")
	ErrVaultNotFound      = errors.New("vault not found")
	ErrVaultKeyExists     = errors.New("vault key already exists")
	ErrVaultKeyNotFound   = errors.New("vault key not found")
	ErrGPGEncryption      = errors.New("gpg encryption failed")
	ErrGPGDecryption      = errors.New("gpg decryption failed")
)
