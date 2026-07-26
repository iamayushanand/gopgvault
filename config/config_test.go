package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLifecycle(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nested", filename)
	loaded, err := load(configPath)
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if err := loaded.RegisterVault("work", "/vaults/work.gopgvault", "ABC123"); err != nil {
		t.Fatalf("RegisterVault() error = %v", err)
	}

	reloaded, err := load(configPath)
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if entry, found := reloaded.FindVault("work"); !found ||
		entry.Path != "/vaults/work.gopgvault" || entry.GPGRecipient != "ABC123" {
		t.Fatalf("FindVault() = %#v, %v", entry, found)
	}
	if err := reloaded.RegisterVault("work", "/other.gopgvault", ""); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if err := reloaded.RegisterVault("other", "/vaults/work.gopgvault", ""); !errors.Is(err, ErrVaultPathExists) {
		t.Fatalf("duplicate path error = %v", err)
	}
}

func TestConfigLoadsLegacyEntry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(configPath, []byte("legacy,/vaults/legacy.gopgvault\n"), filePermissions); err != nil {
		t.Fatal(err)
	}
	loaded, err := load(configPath)
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	entry, found := loaded.FindVault("legacy")
	if !found || entry.Path != "/vaults/legacy.gopgvault" || entry.GPGRecipient != "" {
		t.Fatalf("FindVault() = %#v, %v", entry, found)
	}
}

func TestConfigRejectsMalformedEntry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(configPath, []byte("only-one-column\n"), filePermissions); err != nil {
		t.Fatal(err)
	}
	if _, err := load(configPath); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("load() error = %v", err)
	}
}
