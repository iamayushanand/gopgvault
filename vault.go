package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
)

type Vault struct {
	vaultPath string
	entries   []VaultEntry
}

type VaultEntry struct {
	key    string
	secret string
}

func getVault(vaultName string) (*Vault, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	for _, entry := range config.entries {
		if entry.vaultName == vaultName {
			return &Vault{
				vaultPath: entry.filepath,
			}, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrVaultNotFound, vaultName)
}

func (v *Vault) unlock() error {
	cmd := exec.Command(
		"gpg",
		"--quiet",
		"--decrypt",
		v.vaultPath,
	)

	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrGpgDecryptionFailure, err, stderr.String())
	}

	reader := csv.NewReader(bytes.NewReader(out))

	v.entries = nil

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) != 2 {
			return fmt.Errorf("invalid vault entry")
		}

		v.entries = append(v.entries, VaultEntry{
			key:    record[0],
			secret: record[1],
		})
	}

	return nil
}

func (v *Vault) lock() error {
	var buf bytes.Buffer

	writer := csv.NewWriter(&buf)

	for _, entry := range v.entries {
		if err := writer.Write([]string{entry.key, entry.secret}); err != nil {
			return err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	cmd := exec.Command(
		"gpg",
		"--quiet",
		"--batch",
		"--yes",
		"--encrypt",
		"--default-recipient-self",
		"--output", v.vaultPath,
	)

	cmd.Stdin = &buf

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrGpgEncryptionFailure, err, out)
	}

	return nil
}

func (v *Vault) wipe() {
	v.entries = nil
}

func (v *Vault) findEntry(key string) (*VaultEntry, bool) {
	for i := range v.entries {
		if v.entries[i].key == key {
			return &v.entries[i], true
		}
	}

	return nil, false
}

func (v *Vault) addKey(key, secret string) error {
	if err := v.unlock(); err != nil {
		return err
	}
	defer v.wipe()

	if _, found := v.findEntry(key); found {
		return ErrVaultKeyExists
	}

	v.entries = append(v.entries, VaultEntry{
		key:    key,
		secret: secret,
	})

	return v.lock()
}

func (v *Vault) getKey(key string) (string, error) {
	if err := v.unlock(); err != nil {
		return "", err
	}
	defer v.wipe()

	entry, found := v.findEntry(key)
	if !found {
		return "", ErrVaultKeyNotFound
	}

	return entry.secret, nil
}