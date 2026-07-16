package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLifecycle(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nested", ".gopassrc")
	config := &Config{configPath: configPath}
	if err := config.createIfNotExists(); err != nil {
		t.Fatalf("createIfNotExists() error = %v", err)
	}
	if err := config.load(); err != nil {
		t.Fatalf("load() error = %v", err)
	}

	entry := ConfigEntry{vaultName: "work", filepath: "/vaults/work.gopass"}
	if err := config.insertEntry(entry); err != nil {
		t.Fatalf("insertEntry() error = %v", err)
	}

	reloaded := &Config{configPath: configPath}
	if err := reloaded.load(); err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if path, found := reloaded.findVault("work"); !found || path != entry.filepath {
		t.Fatalf("findVault() = %q, %v", path, found)
	}
	if err := reloaded.insertEntry(entry); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if err := reloaded.insertEntry(ConfigEntry{vaultName: "other", filepath: entry.filepath}); !errors.Is(err, ErrVaultPathExists) {
		t.Fatalf("duplicate path error = %v", err)
	}
}

func TestConfigRejectsMalformedEntry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".gopassrc")
	if err := os.WriteFile(configPath, []byte("only-one-column\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	config := &Config{configPath: configPath}
	if err := config.load(); !errors.Is(err, ErrInvalidConfigEntry) {
		t.Fatalf("load() error = %v", err)
	}
}
