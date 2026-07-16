package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

	vaultPath, found := config.findVault(vaultName)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrVaultNotFound, vaultName)
	}
	return &Vault{vaultPath: vaultPath}, nil
}

func createVaultFile(vaultPath string) error {
	if err := os.MkdirAll(filepath.Dir(vaultPath), directoryPermissions); err != nil {
		return err
	}
	if _, err := os.Stat(vaultPath); err == nil {
		return fmt.Errorf("%w: %q", ErrVaultFileExists, vaultPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := encrypt(vaultPath, nil, false); err != nil {
		_ = os.Remove(vaultPath)
		return err
	}
	return nil
}

func (v *Vault) unlock() error {
	cmd := exec.Command(gpgExecutable, "--quiet", "--decrypt", v.vaultPath)
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrGPGDecryption, err, stderr.String())
	}
	defer clearBytes(out)

	v.entries = nil
	reader := csv.NewReader(bytes.NewReader(out))
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record) != 2 {
			return ErrInvalidVaultEntry
		}

		v.entries = append(v.entries, VaultEntry{key: record[0], secret: record[1]})
	}
}

func (v *Vault) lock() error {
	var content bytes.Buffer
	writer := csv.NewWriter(&content)
	for _, entry := range v.entries {
		if err := writer.Write([]string{entry.key, entry.secret}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	return encrypt(v.vaultPath, content.Bytes(), true)
}

func encrypt(vaultPath string, content []byte, overwrite bool) error {
	args := []string{"--quiet", "--batch"}
	if overwrite {
		args = append(args, "--yes")
	}
	args = append(args,
		"--encrypt",
		"--default-recipient-self",
		"--output", vaultPath,
	)

	cmd := exec.Command(gpgExecutable, args...)
	cmd.Stdin = bytes.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrGPGEncryption, err, out)
	}
	return nil
}

func (v *Vault) wipe() {
	for i := range v.entries {
		v.entries[i].key = ""
		v.entries[i].secret = ""
	}
	v.entries = nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
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
		return fmt.Errorf("%w: %q", ErrVaultKeyExists, key)
	}
	v.entries = append(v.entries, VaultEntry{key: key, secret: secret})
	return v.lock()
}

func (v *Vault) getKey(key string) (string, error) {
	if err := v.unlock(); err != nil {
		return "", err
	}
	defer v.wipe()

	entry, found := v.findEntry(key)
	if !found {
		return "", fmt.Errorf("%w: %q", ErrVaultKeyNotFound, key)
	}
	return entry.secret, nil
}
