package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

type AddKeyInput struct {
	key   string
	vault string
}

func parseAddKey(args []string, vault string) (*AddKeyInput, error) {
	if len(args) != 1 {
		return nil, usageError(string(AddKey))
	}
	return &AddKeyInput{key: args[0], vault: vault}, nil
}

func executeAddKey(input *AddKeyInput) error {
	secret, err := getSecretFromUser()
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	vault, err := getVault(input.vault)
	if err != nil {
		return err
	}
	if err := vault.addKey(input.key, secret); err != nil {
		return err
	}
	return nil
}

func getSecretFromUser() (string, error) {
	fmt.Print("Enter secret: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	defer clearBytes(secret)
	return string(secret), nil
}

func handleAddKey(args []string, vaultName string) error {
	input, err := parseAddKey(args, vaultName)
	if err != nil {
		return err
	}
	if err := executeAddKey(input); err != nil {
		return fmt.Errorf("add key %q to vault %q: %w", input.key, input.vault, err)
	}
	fmt.Printf("Successfully added key %q to vault %q\n", input.key, input.vault)
	return nil
}
