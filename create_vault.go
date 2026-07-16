package main

import (
	"fmt"
	"os"
)

type CreateVaultInput struct {
	vaultName string
	filepath  string
}

func parseCreateVault(args []string) (*CreateVaultInput, error) {
	if len(args) != 2 {
		return nil, usageError(string(CreateVault))
	}
	return &CreateVaultInput{vaultName: args[0], filepath: args[1]}, nil
}

func executeCreateVault(input *CreateVaultInput) error {
	config, err := getConfig()
	if err != nil {
		return err
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

func handleCreateVault(args []string) error {
	input, err := parseCreateVault(args)
	if err != nil {
		return err
	}
	if err := executeCreateVault(input); err != nil {
		return fmt.Errorf("create vault %q: %w", input.vaultName, err)
	}
	fmt.Printf("Successfully created vault %q\n", input.vaultName)
	return nil
}
