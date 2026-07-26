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
	"sort"
	"strings"
)

const (
	gpgExecutable        = "gpg"
	directoryPermissions = 0o700
)

var (
	ErrInvalidEntry    = errors.New("invalid vault entry")
	ErrFileExists      = errors.New("vault file already exists")
	ErrKeyExists       = errors.New("vault key already exists")
	ErrConflictingKeys = errors.New("conflicting vault keys")
	ErrKeyNotFound     = errors.New("vault key not found")
	ErrEncryption      = errors.New("gpg encryption failed")
	ErrDecryption      = errors.New("gpg decryption failed")
)

type Vault struct {
	path         string
	gpgRecipient string
	entries      []Entry
}

type Entry struct {
	Key    string
	Secret []byte
}

func New(path, gpgRecipient string) *Vault {
	return &Vault{path: path, gpgRecipient: gpgRecipient}
}

func Create(path, gpgRecipient string) error {
	return CreateWithEntries(path, gpgRecipient, nil)
}

func CreateWithEntries(path, gpgRecipient string, entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), directoryPermissions); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %q", ErrFileExists, path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if conflicts := duplicateKeys(entries); len(conflicts) > 0 {
		return conflictError(conflicts)
	}

	content, err := marshalEntries(entries)
	if err != nil {
		return err
	}
	defer clear(content)
	return encrypt(path, content, gpgRecipient, false)
}

func (v *Vault) unlock() (returnErr error) {
	v.wipe()
	defer func() {
		if returnErr != nil {
			v.wipe()
		}
	}()

	command := exec.Command(gpgExecutable, "--quiet", "--decrypt", v.path)
	command.Stdin = os.Stdin
	command.Env = os.Environ()

	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	defer clear(output)
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrDecryption, err, stderr.String())
	}

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
		// encoding/csv exposes fields as strings, so decoding necessarily creates
		// a short-lived immutable copy. Clone the key so it cannot retain the
		// record backing string that also held the secret, and keep only a
		// mutable owned copy of the secret afterward.
		v.entries = append(v.entries, Entry{
			Key:    strings.Clone(record[0]),
			Secret: []byte(record[1]),
		})
	}
}

func (v *Vault) lock() error {
	content, err := marshalEntries(v.entries)
	if err != nil {
		return err
	}
	defer clear(content)
	return encrypt(v.path, content, v.gpgRecipient, true)
}

func marshalEntries(entries []Entry) ([]byte, error) {
	var content bytes.Buffer
	for _, entry := range entries {
		writeCSVField(&content, []byte(entry.Key))
		content.WriteByte(',')
		writeCSVField(&content, entry.Secret)
		content.WriteByte('\n')
	}
	return content.Bytes(), nil
}

func writeCSVField(writer *bytes.Buffer, field []byte) {
	if !bytes.ContainsAny(field, ",\"\r\n") {
		writer.Write(field)
		return
	}
	writer.WriteByte('"')
	for _, value := range field {
		if value == '"' {
			writer.WriteByte('"')
		}
		writer.WriteByte(value)
	}
	writer.WriteByte('"')
}

func encrypt(path string, content []byte, gpgRecipient string, overwrite bool) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".gopass-encrypted-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		return err
	}
	defer os.Remove(tempPath)

	args := []string{"--quiet", "--batch", "--encrypt"}
	if gpgRecipient == "" {
		args = append(args, "--default-recipient-self")
	} else {
		args = append(args, "--recipient", gpgRecipient)
	}
	args = append(args, "--output", tempPath)

	command := exec.Command(gpgExecutable, args...)
	command.Stdin = bytes.NewReader(content)
	output, err := command.CombinedOutput()
	defer clear(output)
	if err != nil {
		return fmt.Errorf("%w: %w: %s", ErrEncryption, err, output)
	}

	if overwrite {
		if err := os.Rename(tempPath, path); err != nil {
			return err
		}
		return nil
	}
	if err := os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %q", ErrFileExists, path)
		}
		return err
	}
	return nil
}

func (v *Vault) wipe() {
	clearEntries(v.entries)
	v.entries = nil
}

func ClearEntries(entries []Entry) {
	clearEntries(entries)
}

func clearEntries(entries []Entry) {
	for i := range entries {
		entries[i].Key = ""
		clear(entries[i].Secret)
		entries[i].Secret = nil
	}
}

func cloneSecret(secret []byte) []byte {
	return bytes.Clone(secret)
}

func replaceSecret(destination *[]byte, source []byte) {
	clear(*destination)
	*destination = cloneSecret(source)
}

func (v *Vault) findEntry(key string) (*Entry, bool) {
	for i := range v.entries {
		if v.entries[i].Key == key {
			return &v.entries[i], true
		}
	}
	return nil, false
}

func (v *Vault) AddKey(key string, secret []byte, overwrite bool) error {
	if err := v.unlock(); err != nil {
		return err
	}
	defer v.wipe()

	if entry, found := v.findEntry(key); found {
		if !overwrite {
			return fmt.Errorf("%w: %q", ErrKeyExists, key)
		}
		replaceSecret(&entry.Secret, secret)
		return v.lock()
	}
	v.entries = append(v.entries, Entry{Key: key, Secret: cloneSecret(secret)})
	return v.lock()
}

func (v *Vault) GetKey(key string) ([]byte, error) {
	if err := v.unlock(); err != nil {
		return nil, err
	}
	defer v.wipe()

	entry, found := v.findEntry(key)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, key)
	}
	return cloneSecret(entry.Secret), nil
}

func (v *Vault) Entries() ([]Entry, error) {
	if err := v.unlock(); err != nil {
		return nil, err
	}
	defer v.wipe()

	entries := make([]Entry, len(v.entries))
	for i, entry := range v.entries {
		entries[i] = Entry{Key: entry.Key, Secret: cloneSecret(entry.Secret)}
	}
	return entries, nil
}

func (v *Vault) ListKeys() ([]string, error) {
	if err := v.unlock(); err != nil {
		return nil, err
	}
	defer v.wipe()

	keys := make([]string, len(v.entries))
	for i, entry := range v.entries {
		keys[i] = entry.Key
	}
	return keys, nil
}

func (v *Vault) PutEntries(entries []Entry, overwrite bool) error {
	if err := v.unlock(); err != nil {
		return err
	}
	defer v.wipe()

	indices := make(map[string]int, len(v.entries)+len(entries))
	for i, entry := range v.entries {
		indices[entry.Key] = i
	}

	if !overwrite {
		conflicts := make(map[string]struct{})
		seen := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			if _, found := indices[entry.Key]; found {
				conflicts[entry.Key] = struct{}{}
			}
			if _, found := seen[entry.Key]; found {
				conflicts[entry.Key] = struct{}{}
			}
			seen[entry.Key] = struct{}{}
		}
		if len(conflicts) > 0 {
			return conflictError(mapKeys(conflicts))
		}
	}

	for _, incoming := range entries {
		if index, found := indices[incoming.Key]; found {
			replaceSecret(&v.entries[index].Secret, incoming.Secret)
			continue
		}
		indices[incoming.Key] = len(v.entries)
		v.entries = append(v.entries, Entry{
			Key:    incoming.Key,
			Secret: cloneSecret(incoming.Secret),
		})
	}
	return v.lock()
}

func duplicateKeys(entries []Entry) []string {
	seen := make(map[string]struct{}, len(entries))
	duplicates := make(map[string]struct{})
	for _, entry := range entries {
		if _, found := seen[entry.Key]; found {
			duplicates[entry.Key] = struct{}{}
		}
		seen[entry.Key] = struct{}{}
	}
	return mapKeys(duplicates)
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func conflictError(keys []string) error {
	sort.Strings(keys)
	return fmt.Errorf("%w: %q", ErrConflictingKeys, keys)
}
