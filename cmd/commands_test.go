package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamayushanand/gopass/vault"
)

func TestGrepEntriesMatchesKeysOnly(t *testing.T) {
	entries := []vault.Entry{
		{Key: "service/alpha", Secret: []byte("hidden-match")},
		{Key: "service/beta", Secret: []byte("alpha only in secret")},
	}
	matches, err := grepEntryIndexes(`^service/a`, entries)
	if err != nil {
		t.Fatalf("grepEntries() error = %v", err)
	}
	if len(matches) != 1 || matches[0] != 0 {
		t.Fatalf("grepEntries() = %#v", matches)
	}

	if _, err := grepEntryIndexes("hidden-match", entries); !errors.Is(err, ErrNoMatchingKeys) {
		t.Fatalf("secret-only grep error = %v", err)
	}
}

func TestNormalizeEntriesDuplicateBehavior(t *testing.T) {
	first := []byte("first")
	last := []byte("last")
	entries := []vault.Entry{
		{Key: "duplicate", Secret: first},
		{Key: "other", Secret: []byte("value")},
		{Key: "duplicate", Secret: last},
	}
	if _, err := normalizeEntries(entries, false); !errors.Is(err, vault.ErrConflictingKeys) {
		t.Fatalf("normalizeEntries() error = %v", err)
	}
	normalized, err := normalizeEntries(entries, true)
	if err != nil {
		t.Fatalf("normalizeEntries(overwrite) error = %v", err)
	}
	if len(normalized) != 2 || normalized[0].Key != "duplicate" || string(normalized[0].Secret) != "last" {
		t.Fatalf("normalizeEntries(overwrite) = %#v", normalized)
	}
	if !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatalf("normalizeEntries(overwrite) left replaced bytes = %q", first)
	}
	if &normalized[0].Secret[0] != &last[0] {
		t.Fatal("normalizeEntries(overwrite) copied instead of transferring ownership")
	}
	vault.ClearEntries(entries)
}

func TestListImportAndCopyCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	installFakeGPG(t)
	installFakePager(t)
	gpgLog := filepath.Join(home, "gpg-args.log")
	t.Setenv("GPG_ARGS_LOG", gpgLog)

	defaultPath := filepath.Join(home, "default.gopass")
	workPath := filepath.Join(home, "work.gopass")
	copyPath := filepath.Join(home, "copy.gopass")
	if err := os.WriteFile(defaultPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workPath, []byte("existing,old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("existing,destination\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configContent := fmt.Sprintf(
		"default,%s,\nwork,%s,WORK-KEY\ncopy,%s,COPY-KEY\n",
		defaultPath, workPath, copyPath,
	)
	if err := os.WriteFile(filepath.Join(home, configFilename), []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	importPath := filepath.Join(home, "import.csv")
	if err := os.WriteFile(importPath, []byte("new,value\nexisting,replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCommand([]string{commandImportSecrets, importPath, "--vault", "work"})
	root.SetOut(new(bytes.Buffer))
	if err := root.Execute(); !errors.Is(err, vault.ErrConflictingKeys) {
		t.Fatalf("import conflict error = %v", err)
	}
	assertFileContent(t, workPath, "existing,old\n")

	root = NewRootCommand([]string{commandImportSecrets, importPath, "--vault", "work", "--overwrite"})
	var output bytes.Buffer
	root.SetOut(&output)
	if err := root.Execute(); err != nil {
		t.Fatalf("overwrite import error = %v", err)
	}
	if !strings.Contains(output.String(), "DELETE THE PLAINTEXT CSV FILE NOW.") {
		t.Fatalf("import output = %q", output.String())
	}
	assertFileContent(t, workPath, "existing,replacement\nnew,value\n")

	root = NewRootCommand([]string{commandListKeys, "--vault", "work"})
	output.Reset()
	root.SetOut(&output)
	if err := root.Execute(); err != nil {
		t.Fatalf("list keys error = %v", err)
	}
	if output.String() != "existing\nnew\n" {
		t.Fatalf("list output = %q", output.String())
	}

	root = NewRootCommand([]string{commandCopySecrets, "work", "copy"})
	root.SetOut(new(bytes.Buffer))
	if err := root.Execute(); !errors.Is(err, vault.ErrConflictingKeys) {
		t.Fatalf("copy conflict error = %v", err)
	}
	assertFileContent(t, copyPath, "existing,destination\n")

	root = NewRootCommand([]string{commandCopySecrets, "work", "copy", "--overwrite"})
	root.SetOut(new(bytes.Buffer))
	if err := root.Execute(); err != nil {
		t.Fatalf("overwrite copy error = %v", err)
	}
	assertFileContent(t, copyPath, "existing,replacement\nnew,value\n")
	assertFileContent(t, workPath, "existing,replacement\nnew,value\n")
	gpgArgs, err := os.ReadFile(gpgLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gpgArgs), "COPY-KEY") {
		t.Fatalf("destination recipient not reused; gpg args = %q", gpgArgs)
	}

	root = NewRootCommand([]string{commandCopySecrets, "work", "work"})
	root.SetOut(new(bytes.Buffer))
	if err := root.Execute(); !errors.Is(err, ErrSameVault) {
		t.Fatalf("same-vault copy error = %v", err)
	}
}

func TestImportPromptsForNewVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	installFakeGPG(t)

	defaultPath := filepath.Join(home, "default.gopass")
	if err := os.WriteFile(defaultPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	configContent := fmt.Sprintf("default,%s,\n", defaultPath)
	if err := os.WriteFile(filepath.Join(home, configFilename), []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}
	importPath := filepath.Join(home, "import.csv")
	if err := os.WriteFile(importPath, []byte("key,secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, "new.gopass")

	root := NewRootCommand([]string{commandImportSecrets, importPath})
	root.SetIn(strings.NewReader("new-vault\n" + newPath + "\n"))
	var output bytes.Buffer
	root.SetOut(&output)
	if err := root.Execute(); err != nil {
		t.Fatalf("prompted import error = %v", err)
	}
	assertFileContent(t, newPath, "key,secret\n")
	configData, err := os.ReadFile(filepath.Join(home, configFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configData), "new-vault,"+newPath+",") {
		t.Fatalf("config = %q", configData)
	}
}

func TestCreateVaultPersistsGPGRecipient(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	installFakeGPG(t)
	logPath := filepath.Join(home, "gpg.log")
	t.Setenv("GPG_ARGS_LOG", logPath)

	path := filepath.Join(home, "custom.gopass")
	root := NewRootCommand([]string{commandCreateVault, "custom", path, "--gpg", "CUSTOM-KEY"})
	root.SetOut(new(bytes.Buffer))
	if err := root.Execute(); err != nil {
		t.Fatalf("create vault error = %v", err)
	}

	configData, err := os.ReadFile(filepath.Join(home, configFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(configData), "custom,"+path+",CUSTOM-KEY") {
		t.Fatalf("config = %q", configData)
	}
	gpgData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gpgData), "CUSTOM-KEY") {
		t.Fatalf("gpg args = %q", gpgData)
	}
}

func installFakePager(t *testing.T) {
	t.Helper()
	bin := filepath.SplitList(os.Getenv("PATH"))
	if len(bin) == 0 {
		t.Fatal("PATH is empty")
	}
	path := filepath.Join(bin[0], pagerExecutable)
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s content = %q, want %q", path, content, expected)
	}
}
