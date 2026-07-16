package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Command string

const (
	CreateVault Command = "create-vault"
	AddKey      Command = "add-key"
	GetKey      Command = "get-key"
)

type parsedArgs struct {
	command  Command
	args     []string
	vault    string
	vaultSet bool
}

func parseArgs(args []string) (*parsedArgs, error) {
	parsed := &parsedArgs{vault: "default"}
	positionals := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--vault":
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return nil, fmt.Errorf("--vault requires a name")
			}
			parsed.vault = args[i+1]
			parsed.vaultSet = true
			i++
		case strings.HasPrefix(args[i], "--vault="):
			parsed.vault = strings.TrimPrefix(args[i], "--vault=")
			if parsed.vault == "" {
				return nil, fmt.Errorf("--vault requires a name")
			}
			parsed.vaultSet = true
		case strings.HasPrefix(args[i], "-"):
			return nil, fmt.Errorf("unknown option %q", args[i])
		default:
			positionals = append(positionals, args[i])
		}
	}

	if len(positionals) == 0 {
		return nil, ErrMissingArguments
	}
	parsed.command = Command(positionals[0])
	parsed.args = positionals[1:]
	return parsed, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	parsed, err := parseArgs(args)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, usage())
	}
	if parsed.command == CreateVault && parsed.vaultSet {
		return fmt.Errorf("--vault is not valid for create-vault")
	}
	if parsed.command != CreateVault && parsed.command != AddKey && parsed.command != GetKey {
		return fmt.Errorf("unknown command %q\n%s", parsed.command, usage())
	}

	if err := boot(); err != nil {
		return fmt.Errorf("initialize gopass: %w", err)
	}

	switch parsed.command {
	case CreateVault:
		return handleCreateVault(parsed.args)
	case AddKey:
		return handleAddKey(parsed.args, parsed.vault)
	case GetKey:
		return handleGetKey(parsed.args, parsed.vault)
	}
	return nil
}

func usage() string {
	return strings.Join([]string{
		"Usage:",
		"  gopass create-vault <vault-name> <filepath>",
		"  gopass add-key <key> [--vault <vault-name>]",
		"  gopass get-key <key> [--vault <vault-name>]",
	}, "\n")
}

func boot() error {
	config, err := getConfig()
	if err != nil {
		return err
	}
	if _, found := config.findVault("default"); found {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	defaultVaultPath := filepath.Join(home, ".gopass", "default.gopass")
	entry := ConfigEntry{vaultName: "default", filepath: defaultVaultPath}

	created := false
	if _, err := os.Stat(defaultVaultPath); os.IsNotExist(err) {
		if err := createVaultFile(defaultVaultPath); err != nil {
			return err
		}
		created = true
	} else if err != nil {
		return err
	}

	if err := config.insertEntry(entry); err != nil {
		if created {
			_ = os.Remove(defaultVaultPath)
		}
		return err
	}
	return nil
}

func usageError(command string) error {
	var commandUsage string
	switch Command(command) {
	case CreateVault:
		commandUsage = "create-vault <vault-name> <filepath>"
	case AddKey:
		commandUsage = "add-key <key> [--vault <vault-name>]"
	case GetKey:
		commandUsage = "get-key <key> [--vault <vault-name>]"
	}
	return fmt.Errorf("%w: usage: gopass %s", ErrMissingArguments, commandUsage)
}
