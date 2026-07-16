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
	if err := loaded.RegisterVault("work", "/vaults/work.gopass"); err != nil {
		t.Fatalf("RegisterVault() error = %v", err)
	}

	reloaded, err := load(configPath)
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if path, found := reloaded.FindVault("work"); !found || path != "/vaults/work.gopass" {
		t.Fatalf("FindVault() = %q, %v", path, found)
	}
	if err := reloaded.RegisterVault("work", "/other.gopass"); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("duplicate name error = %v", err)
	}
	if err := reloaded.RegisterVault("other", "/vaults/work.gopass"); !errors.Is(err, ErrVaultPathExists) {
		t.Fatalf("duplicate path error = %v", err)
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
