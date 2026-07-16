package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		command     Command
		commandArgs []string
		vault       string
		vaultSet    bool
	}{
		{
			name:        "default vault",
			args:        []string{"add-key", "service/account"},
			command:     AddKey,
			commandArgs: []string{"service/account"},
			vault:       "default",
		},
		{
			name:        "vault before command",
			args:        []string{"--vault", "work", "get-key", "service/account"},
			command:     GetKey,
			commandArgs: []string{"service/account"},
			vault:       "work",
			vaultSet:    true,
		},
		{
			name:        "vault after command",
			args:        []string{"get-key", "service/account", "--vault", "work"},
			command:     GetKey,
			commandArgs: []string{"service/account"},
			vault:       "work",
			vaultSet:    true,
		},
		{
			name:        "equals form",
			args:        []string{"get-key", "--vault=work", "service/account"},
			command:     GetKey,
			commandArgs: []string{"service/account"},
			vault:       "work",
			vaultSet:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseArgs(test.args)
			if err != nil {
				t.Fatalf("parseArgs() error = %v", err)
			}
			if got.command != test.command || got.vault != test.vault || got.vaultSet != test.vaultSet {
				t.Fatalf("parseArgs() = %#v", got)
			}
			if len(got.args) != len(test.commandArgs) {
				t.Fatalf("parseArgs() args = %q, want %q", got.args, test.commandArgs)
			}
			for i := range got.args {
				if got.args[i] != test.commandArgs[i] {
					t.Fatalf("parseArgs() args = %q, want %q", got.args, test.commandArgs)
				}
			}
		})
	}
}

func TestParseArgsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no command", args: nil},
		{name: "missing vault", args: []string{"get-key", "key", "--vault"}},
		{name: "empty vault", args: []string{"get-key", "key", "--vault="}},
		{name: "unknown option", args: []string{"get-key", "key", "--other"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseArgs(test.args); err == nil {
				t.Fatal("parseArgs() error = nil")
			}
		})
	}
}

func TestCommandParsersRejectWrongArgumentCounts(t *testing.T) {
	if _, err := parseCreateVault([]string{"only-name"}); !errors.Is(err, ErrMissingArguments) {
		t.Fatalf("parseCreateVault() error = %v", err)
	}
	if _, err := parseAddKey(nil, "default"); !errors.Is(err, ErrMissingArguments) {
		t.Fatalf("parseAddKey() error = %v", err)
	}
	if _, err := parseGetKey([]string{"one", "two"}, "default"); !errors.Is(err, ErrMissingArguments) {
		t.Fatalf("parseGetKey() error = %v", err)
	}
}

func TestRunRejectsUnknownCommandBeforeBoot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("run() error = nil")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".gopassrc")); !os.IsNotExist(err) {
		t.Fatalf("unknown command initialized config: %v", err)
	}
}
