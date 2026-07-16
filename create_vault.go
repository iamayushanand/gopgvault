package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type CreateVaultInput struct {
	vaultName string
	filepath  string
}

func newCreateVaultCommand() *cobra.Command {
	input := &CreateVaultInput{}
	return &cobra.Command{
		Use:   commandCreateVault + " <vault-name> <filepath>",
		Short: "Create an encrypted password vault",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input.vaultName = args[0]
			input.filepath = args[1]
			if err := executeCreateVault(input); err != nil {
				return fmt.Errorf("create vault %q: %w", input.vaultName, err)
			}
			cmd.Printf("Successfully created vault %q\n", input.vaultName)
			return nil
		},
	}
}

func executeCreateVault(input *CreateVaultInput) error {
	if config == nil {
		return ErrConfigNotInitialized
	}
	entry := ConfigEntry{vaultName: input.vaultName, filepath: input.filepath}
	if err := config.validateEntry(entry); err != nil {
		return err
	}

	if err := createVaultFile(input.filepath); err != nil {
		return err
	}
	if err := config.insertEntry(entry); err != nil {
		if removeErr := os.Remove(input.filepath); removeErr != nil {
			return fmt.Errorf("register vault: %w (cleanup failed: %v)", err, removeErr)
		}
		return fmt.Errorf("register vault: %w", err)
	}
	return nil
}
