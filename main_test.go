package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRootCommandRejectsInvalidInputBeforeBoot(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing command", args: nil},
		{name: "unknown command", args: []string{"unknown"}},
		{name: "flag before command", args: []string{"--vault", "work", commandGetKey, "key"}},
		{name: "unknown flag", args: []string{commandGetKey, "key", "--other"}},
		{name: "missing add key", args: []string{commandAddKey}},
		{name: "extra add key", args: []string{commandAddKey, "one", "two"}},
		{name: "missing get key", args: []string{commandGetKey}},
		{name: "missing create path", args: []string{commandCreateVault, "work"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			config = nil
			t.Cleanup(func() { config = nil })

			root := newRootCommand(test.args)
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
	config = nil
	t.Cleanup(func() { config = nil })

	root := newRootCommand([]string{"--help"})
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
	tests := []struct {
		name string
		args []string
	}{
		{name: "before key", args: []string{"--vault", "work", "service/account"}},
		{name: "after key", args: []string{"service/account", "--vault", "work"}},
		{name: "equals form", args: []string{"service/account", "--vault=work"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := newGetKeyCommand()
			if err := command.ParseFlags(test.args); err != nil {
				t.Fatalf("ParseFlags() error = %v", err)
			}
			if err := command.ValidateArgs(command.Flags().Args()); err != nil {
				t.Fatalf("ValidateArgs() error = %v", err)
			}
			vault, err := command.Flags().GetString(vaultFlagName)
			if err != nil {
				t.Fatal(err)
			}
			if vault != "work" {
				t.Fatalf("vault = %q, want work", vault)
			}
		})
	}
}
