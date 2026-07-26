package config

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	filename             = ".gopgvaultrc"
	directoryPermissions = 0o700
	filePermissions      = 0o600
)

var (
	ErrInvalidEntry    = errors.New("invalid config entry")
	ErrVaultExists     = errors.New("vault already exists")
	ErrVaultPathExists = errors.New("vault path already registered")
)

type Config struct {
	path    string
	entries []Entry
}

type Entry struct {
	Name         string
	Path         string
	GPGRecipient string
}

func Load() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return load(filepath.Join(home, filename))
}

func load(path string) (*Config, error) {
	loaded := &Config{path: path}
	if err := loaded.createIfNotExists(); err != nil {
		return nil, err
	}
	if err := loaded.loadEntries(); err != nil {
		return nil, err
	}
	return loaded, nil
}

func (c *Config) createIfNotExists() error {
	if _, err := os.Stat(c.path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.path), directoryPermissions); err != nil {
		return err
	}
	file, err := os.OpenFile(c.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	return file.Close()
}

func (c *Config) loadEntries() error {
	file, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer file.Close()

	c.entries = nil
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(record) < 2 || len(record) > 3 {
			return ErrInvalidEntry
		}
		entry := Entry{Name: record[0], Path: record[1]}
		if len(record) == 3 {
			entry.GPGRecipient = record[2]
		}
		c.entries = append(c.entries, entry)
	}
}

func (c *Config) FindVault(name string) (Entry, bool) {
	for _, entry := range c.entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return Entry{}, false
}

func (c *Config) ValidateVault(name, path string) error {
	for _, entry := range c.entries {
		if entry.Name == name {
			return fmt.Errorf("%w: %q", ErrVaultExists, name)
		}
		if entry.Path == path {
			return fmt.Errorf("%w: %q", ErrVaultPathExists, path)
		}
	}
	return nil
}

func (c *Config) RegisterVault(name, path, gpgRecipient string) error {
	if err := c.ValidateVault(name, path); err != nil {
		return err
	}

	file, err := os.OpenFile(c.path, os.O_APPEND|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{name, path, gpgRecipient}); err != nil {
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	c.entries = append(c.entries, Entry{
		Name:         name,
		Path:         path,
		GPGRecipient: gpgRecipient,
	})
	return nil
}
