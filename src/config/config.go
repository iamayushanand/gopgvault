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
	filename             = ".gopassrc"
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
	name string
	path string
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
		if len(record) != 2 {
			return ErrInvalidEntry
		}
		c.entries = append(c.entries, Entry{name: record[0], path: record[1]})
	}
}

func (c *Config) FindVault(name string) (string, bool) {
	for _, entry := range c.entries {
		if entry.name == name {
			return entry.path, true
		}
	}
	return "", false
}

func (c *Config) ValidateVault(name, path string) error {
	for _, entry := range c.entries {
		if entry.name == name {
			return fmt.Errorf("%w: %q", ErrVaultExists, name)
		}
		if entry.path == path {
			return fmt.Errorf("%w: %q", ErrVaultPathExists, path)
		}
	}
	return nil
}

func (c *Config) RegisterVault(name, path string) error {
	if err := c.ValidateVault(name, path); err != nil {
		return err
	}

	file, err := os.OpenFile(c.path, os.O_APPEND|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{name, path}); err != nil {
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	c.entries = append(c.entries, Entry{name: name, path: path})
	return nil
}
