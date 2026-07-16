package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Config struct {
	configPath string
	entries    []ConfigEntry
}

type ConfigEntry struct {
	vaultName string
	filepath  string
}

func getConfig() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	config := &Config{configPath: filepath.Join(home, configFilename)}
	if err := config.createIfNotExists(); err != nil {
		return nil, err
	}
	if err := config.load(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) createIfNotExists() error {
	if _, err := os.Stat(c.configPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.configPath), directoryPermissions); err != nil {
		return err
	}

	file, err := os.OpenFile(c.configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	return file.Close()
}

func (c *Config) load() error {
	file, err := os.Open(c.configPath)
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
			return ErrInvalidConfigEntry
		}

		c.entries = append(c.entries, ConfigEntry{
			vaultName: record[0],
			filepath:  record[1],
		})
	}
}

func (c *Config) findVault(vaultName string) (string, bool) {
	for _, entry := range c.entries {
		if entry.vaultName == vaultName {
			return entry.filepath, true
		}
	}
	return "", false
}

func (c *Config) insertEntry(entry ConfigEntry) error {
	if err := c.validateEntry(entry); err != nil {
		return err
	}

	file, err := os.OpenFile(c.configPath, os.O_APPEND|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{entry.vaultName, entry.filepath}); err != nil {
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	c.entries = append(c.entries, entry)
	return nil
}

func (c *Config) validateEntry(entry ConfigEntry) error {
	for _, existing := range c.entries {
		if existing.vaultName == entry.vaultName {
			return fmt.Errorf("%w: %q", ErrVaultExists, entry.vaultName)
		}
		if existing.filepath == entry.filepath {
			return fmt.Errorf("%w: %q", ErrVaultPathExists, entry.filepath)
		}
	}
	return nil
}
