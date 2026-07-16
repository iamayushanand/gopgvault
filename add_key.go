package main

import (
	"fmt"
	"errors"
)

type AddKeyInput struct {
	key string
	vault string
}

func parseAddKey(args []string, vault string) (*AddKeyInput, error) {
	if len(args) != 2 {
		return nil, ErrMissingArguments
	}

	return &AddKeyInput{
		key: args[1],
		vault: vaultPath
	}, nil
	
}

func executeAddKey(input *AddKeyInput) error {
	secret, err := get_secret_from_user()
	if err!=nil {
		return fmt.Errorf("%w: %w", ErrGetSecret, err)
	}
	vault, err := getVault(input.vault)
	if err!=nil {
		return fmt.Errorf("%w: %w", ErrGetVault, err)
	}
	err = vault.addKey(key, secret)
	if err!=nil {
		return fmt.Errorf("%w: %w", ErrAddKey, err)
	}
}


func get_secret_from_user() (string, error) {
	fmt.Print("Enter secret: ")

	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Move to the next line after Enter is pressed.

	if err != nil {
		return "", err
	}

	return string(secret), nil
}

func handleAddKey(args []string, vault string) {
	input, err := parseAddKey(args, vault);
	if err != nil {
		fmt.Println(err);
		return;
	}
	
	err = executeAddKey(input);
	if err != nil {
		fmt.Println(err);
		return;
	}
	fmt.Println("Successfully added key %s to vault %s", input.key, input.vault)
}