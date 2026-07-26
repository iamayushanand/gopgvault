package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamayushanand/gopass/config"
)

const configFilename = ".gopassrc"

func TestRootCommandRejectsInvalidInputBeforeBoot(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing command"},
		{name: "unknown command", args: []string{"unknown"}},
		{name: "flag before command", args: []string{"--vault", "work", commandGetKey, "key"}},
		{name: "unknown flag", args: []string{commandGetKey, "key", "--other"}},
		{name: "missing add key", args: []string{commandAddKey}},
		{name: "extra add key", args: []string{commandAddKey, "one", "two"}},
		{name: "missing get key", args: []string{commandGetKey}},
		{name: "missing create path", args: []string{commandCreateVault, "work"}},
		{name: "extra list argument", args: []string{commandListKeys, "extra"}},
		{name: "missing import file", args: []string{commandImportSecrets}},
		{name: "missing copy destination", args: []string{commandCopySecrets, "source"}},
		{name: "get key and grep", args: []string{commandGetKey, "key", "--grep", "pattern"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			root := NewRootCommand(test.args)
			root.SetOut(new(bytes.Buffer))
			root.SetErr(new(bytes.Buffer))
			if err := root.Execute(); err == nil {
				t.Fatal("Execute() error = nil")
			}
			if _, err := os.Stat(filepath.Join(home, configFilename)); !os.IsNotExist(err) {
				t.Fatalf("invalid command initialized config: %v", err)
			}
		})
	}
}

func TestRootCommandHelpDoesNotBoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := NewRootCommand([]string{"--help"})
	var output bytes.Buffer
	root.SetOut(&output)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if output.Len() == 0 {
		t.Fatal("Execute() produced no help output")
	}
	if _, err := os.Stat(filepath.Join(home, configFilename)); !os.IsNotExist(err) {
		t.Fatalf("help initialized config: %v", err)
	}
}

func TestVaultFlagIsCommandLocalAndInterspersed(t *testing.T) {
	tests := [][]string{
		{"--vault", "work", "service/account"},
		{"service/account", "--vault", "work"},
		{"service/account", "--vault=work"},
	}
	for _, args := range tests {
		command := (&application{}).newGetKeyCommand()
		if err := command.ParseFlags(args); err != nil {
			t.Fatalf("ParseFlags(%q) error = %v", args, err)
		}
		if err := command.ValidateArgs(command.Flags().Args()); err != nil {
			t.Fatalf("ValidateArgs(%q) error = %v", args, err)
		}
		selected, err := command.Flags().GetString(vaultFlagName)
		if err != nil || selected != "work" {
			t.Fatalf("vault = %q, %v", selected, err)
		}
	}
}

func TestBootRegistersExistingDefaultVaultWithoutOverwriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vaultPath := filepath.Join(home, vaultDirectoryName, defaultVaultFilename)
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("existing encrypted content")
	if err := os.WriteFile(vaultPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	app := &application{}
	if err := app.boot(); err != nil {
		t.Fatalf("boot() error = %v", err)
	}
	if err := app.boot(); err != nil {
		t.Fatalf("second boot() error = %v", err)
	}
	registered, found := app.config.FindVault(DefaultVaultName)
	if !found || registered.Path != vaultPath {
		t.Fatalf("default vault = %#v, %v", registered, found)
	}
	content, err := os.ReadFile(vaultPath)
	if err != nil || string(content) != string(original) {
		t.Fatalf("existing vault content = %q, %v", content, err)
	}
}

func TestBootDoesNotRemoveExistingVaultOnRegistrationFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vaultPath := filepath.Join(home, vaultDirectoryName, defaultVaultFilename)
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf("other,%s\n", vaultPath)
	if err := os.WriteFile(filepath.Join(home, configFilename), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := (&application{}).boot(); !errors.Is(err, config.ErrVaultPathExists) {
		t.Fatalf("boot() error = %v", err)
	}
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("existing vault was removed: %v", err)
	}
}

func TestBootRemovesNewVaultOnRegistrationFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	installFakeGPG(t)
	vaultPath := filepath.Join(home, vaultDirectoryName, defaultVaultFilename)
	content := fmt.Sprintf("other,%s\n", vaultPath)
	if err := os.WriteFile(filepath.Join(home, configFilename), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := (&application{}).boot(); !errors.Is(err, config.ErrVaultPathExists) {
		t.Fatalf("boot() error = %v", err)
	}
	if _, err := os.Stat(vaultPath); !os.IsNotExist(err) {
		t.Fatalf("new vault was not removed: %v", err)
	}
}

func TestApplicationRequiresBootAndResolvesConfiguredVault(t *testing.T) {
	app := &application{}
	if _, err := app.getVault("work"); !errors.Is(err, ErrConfigNotInitialized) {
		t.Fatalf("getVault() before boot error = %v", err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	defaultPath := filepath.Join(home, "default.gopass")
	configContent := fmt.Sprintf("%s,%s\nwork,%s\n", DefaultVaultName, defaultPath, filepath.Join(home, "work.gopass"))
	if err := os.WriteFile(filepath.Join(home, configFilename), []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.boot(); err != nil {
		t.Fatalf("boot() error = %v", err)
	}
	if _, err := app.getVault("work"); err != nil {
		t.Fatalf("getVault(work) error = %v", err)
	}
	if _, err := app.getVault("missing"); !errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("getVault(missing) error = %v", err)
	}

	configPath := filepath.Join(home, configFilename)
	if err := os.Rename(configPath, configPath+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := app.boot(); err != nil {
		t.Fatalf("idempotent boot reread config: %v", err)
	}
	if _, err := app.getVault("work"); err != nil {
		t.Fatalf("getVault() reread config after boot: %v", err)
	}
}

func installFakeGPG(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
if [ -n "$GPG_ARGS_LOG" ]; then
  {
    echo CALL
    printf '%s\n' "$@"
  } >> "$GPG_ARGS_LOG"
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
cat > "$output"
`
	path := filepath.Join(bin, "gpg")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}
