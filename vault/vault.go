package vault

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	gpgExecutable        = "gpg"
	directoryPermissions = 0o700
)

var (
	ErrInvalidEntry = errors.New("invalid vault entry")
	ErrFileExists   = errors.New("vault file already exists")
	ErrKeyExists    = errors.New("vault key already exists")
	ErrKeyNotFound  = errors.New("vault key not found")
	ErrEncryption   = errors.New("gpg encryption failed")
	ErrDecryption   = errors.New("gpg decryption failed")
)

type Vault struct {
	path    string
	entries []Entry
}

type Entry struct {
	key    string
	secret string
}

func New(path string) *Vault {
	return &Vault{path: path}
}

func Create(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), directoryPermissions); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %q", ErrFileExists, path)
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := encrypt(path, nil, false); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (v *Vault) unlock() error {
	command := exec.Command(gpgExecutable, "--quiet", "--decrypt", v.path)
	command.Stdin = os.Stdin
	command.Env = os.Environ()

	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrDecryption, err, stderr.String())
	}
	defer clear(output)

	v.entries = nil
	reader := csv.NewReader(bytes.NewReader(output))
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record) != 2 {
			return ErrInvalidEntry
		}
		v.entries = append(v.entries, Entry{key: record[0], secret: record[1]})
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
	return encrypt(v.path, content.Bytes(), true)
}

func encrypt(path string, content []byte, overwrite bool) error {
	args := []string{"--quiet", "--batch"}
	if overwrite {
		args = append(args, "--yes")
	}
	args = append(args,
		"--encrypt",
		"--default-recipient-self",
		"--output", path,
	)

	command := exec.Command(gpgExecutable, args...)
	command.Stdin = bytes.NewReader(content)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrEncryption, err, output)
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

func (v *Vault) findEntry(key string) (*Entry, bool) {
	for i := range v.entries {
		if v.entries[i].key == key {
			return &v.entries[i], true
		}
	}
	return nil, false
}

func (v *Vault) AddKey(key, secret string) error {
	if err := v.unlock(); err != nil {
		return err
	}
	defer v.wipe()

	if _, found := v.findEntry(key); found {
		return fmt.Errorf("%w: %q", ErrKeyExists, key)
	}
	v.entries = append(v.entries, Entry{key: key, secret: secret})
	return v.lock()
}

func (v *Vault) GetKey(key string) (string, error) {
	if err := v.unlock(); err != nil {
		return "", err
	}
	defer v.wipe()

	entry, found := v.findEntry(key)
	if !found {
		return "", fmt.Errorf("%w: %q", ErrKeyNotFound, key)
	}
	return entry.secret, nil
}
