package vault

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultWipe(t *testing.T) {
	secret := []byte("secret")
	subject := &Vault{entries: []Entry{{Key: "key", Secret: secret}}}
	subject.wipe()
	if string(secret) != "\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("wipe() left secret bytes = %q", secret)
	}
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

	if err := CreateWithEntries(path, "CUSTOM-KEY", []Entry{{Key: "existing", Secret: []byte("old")}}); err != nil {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	selected := New(path, "CUSTOM-KEY")
	if keys, err := selected.ListKeys(); err != nil || len(keys) != 1 || keys[0] != "existing" {
		t.Fatalf("ListKeys() = %#v, %v", keys, err)
	}

	incoming := []Entry{
		{Key: "existing", Secret: []byte("replacement")},
		{Key: "new", Secret: []byte("value")},
	}
	if err := selected.PutEntries(incoming, false); !errors.Is(err, ErrConflictingKeys) {
		t.Fatalf("PutEntries() conflict error = %v", err)
	}
	assertVaultFile(t, path, "existing,old\n")

	if err := selected.PutEntries(incoming, true); err != nil {
		t.Fatalf("PutEntries(overwrite) error = %v", err)
	}
	assertVaultFile(t, path, "existing,replacement\nnew,value\n")

	if err := selected.AddKey("existing", []byte("again"), false); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("AddKey() conflict error = %v", err)
	}
	if err := selected.AddKey("existing", []byte("again"), true); err != nil {
		t.Fatalf("AddKey(overwrite) error = %v", err)
	}
	assertVaultFile(t, path, "existing,again\nnew,value\n")

	t.Setenv("FAIL_GPG_ENCRYPT", "1")
	if err := selected.AddKey("another", []byte("secret"), false); !errors.Is(err, ErrEncryption) {
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
		{Key: "duplicate", Secret: []byte("first")},
		{Key: "duplicate", Secret: []byte("last")},
	})
	if !errors.Is(err, ErrConflictingKeys) {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("duplicate create wrote file: %v", statErr)
	}
}

func TestSecretBufferOwnership(t *testing.T) {
	installFakeVaultGPG(t)
	path := filepath.Join(t.TempDir(), "ownership.gopass")
	input := []byte("caller-owned")
	if err := CreateWithEntries(path, "", []Entry{{Key: "key", Secret: input}}); err != nil {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	if string(input) != "caller-owned" {
		t.Fatalf("CreateWithEntries() modified caller input = %q", input)
	}

	selected := New(path, "")
	first, err := selected.GetKey("key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	second, err := selected.GetKey("key")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}
	first[0] = 'X'
	if string(second) != "caller-owned" {
		t.Fatalf("GetKey() returned aliased buffers: %q", second)
	}
	clear(first)
	clear(second)

	replacement := []byte("replacement")
	if err := selected.AddKey("key", replacement, true); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	if string(replacement) != "replacement" {
		t.Fatalf("AddKey() modified caller input = %q", replacement)
	}

	entries, err := selected.Entries()
	if err != nil {
		t.Fatalf("Entries() error = %v", err)
	}
	alias := entries[0].Secret
	ClearEntries(entries)
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatalf("ClearEntries() left secret bytes = %q", alias)
	}
}

func TestReplaceSecretWipesOldValueAndClonesInput(t *testing.T) {
	old := []byte("old-value")
	destination := old
	input := []byte("new-value")
	replaceSecret(&destination, input)

	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatalf("replaceSecret() left old bytes = %q", old)
	}
	input[0] = 'X'
	if string(destination) != "new-value" {
		t.Fatalf("replaceSecret() retained caller buffer = %q", destination)
	}
	clear(destination)
	clear(input)
}

func TestCSVSecretRoundTrip(t *testing.T) {
	installFakeVaultGPG(t)
	path := filepath.Join(t.TempDir(), "special.gopass")
	expected := []Entry{
		{Key: `key,with"quotes`, Secret: []byte("comma, quote\" and\r\nmultiple\nlines")},
	}
	if err := CreateWithEntries(path, "", expected); err != nil {
		t.Fatalf("CreateWithEntries() error = %v", err)
	}
	entries, err := New(path, "").Entries()
	if err != nil {
		t.Fatalf("Entries() error = %v", err)
	}
	defer ClearEntries(entries)
	// encoding/csv preserves the existing behavior of normalizing CRLF to LF.
	decodedSecret := []byte("comma, quote\" and\nmultiple\nlines")
	if len(entries) != 1 || entries[0].Key != expected[0].Key ||
		!bytes.Equal(entries[0].Secret, decodedSecret) {
		t.Fatalf("Entries() = %#v", entries)
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
	if err := selected.AddKey("service/account", []byte("secret"), false); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	secret, err := selected.GetKey("service/account")
	if err != nil || string(secret) != "secret" {
		t.Fatalf("GetKey() = %q, %v", secret, err)
	}
	clear(secret)
	if err := selected.AddKey("service/account", []byte("duplicate"), false); !errors.Is(err, ErrKeyExists) {
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
