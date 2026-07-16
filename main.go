package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "gopass",
		Short:         "A GPG-backed command-line password manager",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args: func(_ *cobra.Command, _ []string) error {
			return ErrMissingArguments
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if err := boot(); err != nil {
				return fmt.Errorf("initialize gopass: %w", err)
			}
			return nil
		},
	}

	root.AddCommand(
		newCreateVaultCommand(),
		newAddKeyCommand(),
		newGetKeyCommand(),
	)
	return root
}

func boot() error {
	if config != nil {
		return nil
	}

	loadedConfig, err := loadConfig()
	if err != nil {
		return err
	}
	if _, found := loadedConfig.findVault(DefaultVaultName); found {
		config = loadedConfig
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	defaultVaultPath := filepath.Join(home, vaultDirectoryName, defaultVaultFilename)
	entry := ConfigEntry{vaultName: DefaultVaultName, filepath: defaultVaultPath}

	created := false
	if err := createVaultFile(defaultVaultPath); err == nil {
		created = true
	} else if !errors.Is(err, ErrVaultFileExists) {
		return err
	}

	if err := loadedConfig.insertEntry(entry); err != nil {
		if created {
			_ = os.Remove(defaultVaultPath)
		}
		return err
	}
	config = loadedConfig
	return nil
}
