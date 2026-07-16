package main

import (
	"fmt"
	"errors"
)

type CreateVaultInput struct {
	vaultName string
	filepath string
}

func handleCreateVault(args []string) {
	input, err := parseCreateVault(args)
	if err != nil {
		if errors.Is(err, ErrMissingArguments) {
			fmt.Printf("Usage: create-vault <vault-name> <path>")
			return
		}
		return
	}
	
	err = executeCreateVault(input)
	if err != nil {
		fmt.Printf("Error while creating vault: %v\n", err)
	}
}

func parseCreateVault(args []string) (*CreateVaultInput, error) {
	if len(args) != 3 {
		return nil, ErrMissingArguments
	}
	return &CreateVaultInput {
		vaultName: args[1],
		filePath: args[2]
	}, nil
}

func executeCreateVault(input *CreateVaultInput) error {
	err := create_vault(input.vaultName, input.filepath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreationError, err)
	}
	display_creation_status(err)
}

func create_vault(input *CreateVaultInput) (string, error) {
	configEntry := &ConfigEntry{
		vaultName: input.vaultName,
		filepath: input.filepath
	}
	
	err := config.insertEntry(configEntry)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVaultCreation, err)
	}
}


func display_creation_status(err error) {
	if err != nil {
		fmt.Printf("Failed to create vault: %v\n", err)
		return
	}

	fmt.Printf("Successfully created vault \n")
}
