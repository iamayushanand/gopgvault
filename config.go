package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
)

type Config struct {
	configPath string
	entries    []ConfigEntry
}

type ConfigEntry struct {
	vaultName string
	filepath  string
}

func (c *Config) createIfNotExists() error {
	// If the file already exists, nothing to do.
	if _, err := os.Stat(c.configPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	// Create parent directories if necessary.
	if err := os.MkdirAll(filepath.Dir(c.configPath), 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(c.configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

func (c *Config) loadConfigEntries() error {
	file, err := os.Open(c.configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Reload entries from scratch.
	c.entries = nil

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) != 2 {
			return fmt.Errorf("invalid config entry")
		}

		c.entries = append(c.entries, ConfigEntry{
			vaultName: record[0],
			filepath:  record[1],
		})
	}

	return nil
}

func (c *Config) insertEntry(ce *ConfigEntry) error {
	// Check for duplicate vault name or filepath.
	for _, entry := range c.entries {
		if entry.vaultName == ce.vaultName {
			return fmt.Errorf("vault %q already exists", ce.vaultName)
		}

		if entry.filepath == ce.filepath {
			return fmt.Errorf("filepath %q already exists", ce.filepath)
		}
	}

	file, err := os.OpenFile(c.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	if err := writer.Write([]string{ce.vaultName, ce.filepath}); err != nil {
		return err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}

	c.entries = append(c.entries, *ce)

	return nil
}