package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVaultWipe(t *testing.T) {
	vault := &Vault{entries: []VaultEntry{{key: "key", secret: "secret"}}}
	vault.wipe()
	if vault.entries != nil {
		t.Fatalf("wipe() left entries = %#v", vault.entries)
	}
}

func TestCreateVaultFileRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.gopass")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createVaultFile(path); !errors.Is(err, ErrVaultFileExists) {
		t.Fatalf("createVaultFile() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do not replace" {
		t.Fatalf("existing file content = %q", content)
	}
}

func TestEncryptedVaultWorkflow(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg is not installed")
	}

	home, err := os.MkdirTemp("/tmp", "gopass-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	gnupgHome := filepath.Join(home, "gnupg")
	if err := os.Mkdir(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("GNUPGHOME", gnupgHome)

	generateKey := exec.Command(
		gpg,
		"--batch",
		"--quiet",
		"--passphrase", "",
		"--quick-generate-key",
		"GoPass Test <gopass-test@example.invalid>",
		"default",
		"default",
		"never",
	)
	if output, err := generateKey.CombinedOutput(); err != nil {
		t.Fatalf("generate GPG key: %v: %s", err, output)
	}

	if err := boot(); err != nil {
		t.Fatalf("boot() error = %v", err)
	}
	if err := boot(); err != nil {
		t.Fatalf("second boot() error = %v", err)
	}
	defaultVault, err := getVault("default")
	if err != nil {
		t.Fatalf("getVault(default) error = %v", err)
	}
	if err := defaultVault.addKey("service/account", "default-secret"); err != nil {
		t.Fatalf("addKey(default) error = %v", err)
	}
	secret, err := defaultVault.getKey("service/account")
	if err != nil {
		t.Fatalf("getKey(default) error = %v", err)
	}
	if secret != "default-secret" {
		t.Fatalf("getKey(default) = %q", secret)
	}
	if err := defaultVault.addKey("service/account", "duplicate"); !errors.Is(err, ErrVaultKeyExists) {
		t.Fatalf("duplicate addKey() error = %v", err)
	}
	if _, err := defaultVault.getKey("missing"); !errors.Is(err, ErrVaultKeyNotFound) {
		t.Fatalf("missing getKey() error = %v", err)
	}

	customPath := filepath.Join(home, "vaults", "work.gopass")
	if err := executeCreateVault(&CreateVaultInput{vaultName: "work", filepath: customPath}); err != nil {
		t.Fatalf("executeCreateVault() error = %v", err)
	}
	customVault, err := getVault("work")
	if err != nil {
		t.Fatalf("getVault(work) error = %v", err)
	}
	if err := customVault.addKey("service/account", "work-secret"); err != nil {
		t.Fatalf("addKey(work) error = %v", err)
	}
	secret, err = customVault.getKey("service/account")
	if err != nil {
		t.Fatalf("getKey(work) error = %v", err)
	}
	if secret != "work-secret" {
		t.Fatalf("getKey(work) = %q", secret)
	}

	malformedPath := filepath.Join(home, "malformed.gopass")
	if err := encrypt(malformedPath, []byte("only-one-column\n"), false); err != nil {
		t.Fatalf("encrypt malformed vault: %v", err)
	}
	malformed := &Vault{vaultPath: malformedPath}
	if err := malformed.unlock(); !errors.Is(err, ErrInvalidVaultEntry) {
		t.Fatalf("malformed unlock() error = %v", err)
	}
}
