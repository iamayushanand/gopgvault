package vault

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVaultWipe(t *testing.T) {
	subject := &Vault{entries: []Entry{{Key: "key", Secret: "secret"}}}
	subject.wipe()
	if subject.entries != nil {
		t.Fatalf("wipe() left entries = %#v", subject.entries)
	}
}

func TestCreateRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.gopass")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, ""); !errors.Is(err, ErrFileExists) {
		t.Fatalf("Create() error = %v", err)
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
	gpg, err := exec.LookPath(gpgExecutable)
	if err != nil {
		t.Skip("gpg is not installed")
	}
	home, err := os.MkdirTemp("/tmp", "gopass-vault-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	gnupgHome := filepath.Join(home, "gnupg")
	if err := os.Mkdir(gnupgHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupgHome)

	generateTestKey(t, gpg)
	path := filepath.Join(home, "test.gopass")
	if err := Create(path, ""); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	selected := New(path, "")
	if err := selected.AddKey("service/account", "secret", false); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	secret, err := selected.GetKey("service/account")
	if err != nil || secret != "secret" {
		t.Fatalf("GetKey() = %q, %v", secret, err)
	}
	if err := selected.AddKey("service/account", "duplicate", false); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("duplicate AddKey() error = %v", err)
	}
	if _, err := selected.GetKey("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing GetKey() error = %v", err)
	}

	malformedPath := filepath.Join(home, "malformed.gopass")
	if err := encrypt(malformedPath, []byte("only-one-column\n"), "", false); err != nil {
		t.Fatalf("encrypt malformed vault: %v", err)
	}
	if err := New(malformedPath, "").unlock(); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("malformed unlock() error = %v", err)
	}
}

func generateTestKey(t *testing.T, gpg string) {
	t.Helper()
	command := exec.Command(
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
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate GPG key: %v: %s", err, output)
	}
}
