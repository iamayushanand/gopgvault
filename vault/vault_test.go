package vault

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestVaultBulkWorkflowAndAtomicFailure(t *testing.T) {
	installFakeVaultGPG(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "vault.gopass")
	logPath := filepath.Join(directory, "gpg.log")
	t.Setenv("GPG_ARGS_LOG", logPath)

	if err := CreateWithEntries(path, "CUSTOM-KEY", []Entry{{Key: "existing", Secret: "old"}}); err != nil {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	selected := New(path, "CUSTOM-KEY")
	if keys, err := selected.ListKeys(); err != nil || len(keys) != 1 || keys[0] != "existing" {
		t.Fatalf("ListKeys() = %#v, %v", keys, err)
	}

	incoming := []Entry{
		{Key: "existing", Secret: "replacement"},
		{Key: "new", Secret: "value"},
	}
	if err := selected.PutEntries(incoming, false); !errors.Is(err, ErrConflictingKeys) {
		t.Fatalf("PutEntries() conflict error = %v", err)
	}
	assertVaultFile(t, path, "existing,old\n")

	if err := selected.PutEntries(incoming, true); err != nil {
		t.Fatalf("PutEntries(overwrite) error = %v", err)
	}
	assertVaultFile(t, path, "existing,replacement\nnew,value\n")

	if err := selected.AddKey("existing", "again", false); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("AddKey() conflict error = %v", err)
	}
	if err := selected.AddKey("existing", "again", true); err != nil {
		t.Fatalf("AddKey(overwrite) error = %v", err)
	}
	assertVaultFile(t, path, "existing,again\nnew,value\n")

	t.Setenv("FAIL_GPG_ENCRYPT", "1")
	if err := selected.AddKey("another", "secret", false); !errors.Is(err, ErrEncryption) {
		t.Fatalf("AddKey() encryption error = %v", err)
	}
	assertVaultFile(t, path, "existing,again\nnew,value\n")

	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(logContent), "CUSTOM-KEY"); count < 3 {
		t.Fatalf("custom recipient was not reused; log = %q", logContent)
	}
}

func TestCreateWithEntriesRejectsDuplicates(t *testing.T) {
	installFakeVaultGPG(t)
	path := filepath.Join(t.TempDir(), "duplicate.gopass")
	err := CreateWithEntries(path, "", []Entry{
		{Key: "duplicate", Secret: "first"},
		{Key: "duplicate", Secret: "last"},
	})
	if !errors.Is(err, ErrConflictingKeys) {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("duplicate create wrote file: %v", statErr)
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

func installFakeVaultGPG(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
if [ -n "$GPG_ARGS_LOG" ]; then
  printf '%s\n' "$@" >> "$GPG_ARGS_LOG"
fi
last=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --decrypt) mode="decrypt" ;;
    --output) shift; output="$1" ;;
  esac
  last="$1"
  shift
done
if [ "$mode" = "decrypt" ]; then
  cat "$last"
  exit $?
fi
if [ "$FAIL_GPG_ENCRYPT" = "1" ]; then
  echo "requested encryption failure" >&2
  exit 2
fi
cat > "$output"
`
	path := filepath.Join(bin, gpgExecutable)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func assertVaultFile(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("vault content = %q, want %q", content, expected)
	}
}
