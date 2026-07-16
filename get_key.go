package main

import (
	"fmt"
	"errors"
)

type GetKeyInput struct {
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
	vault, err := getVault(input.vault)
	if err!=nil {
		return fmt.Errorf("%w: %w", ErrGetVault, err)
	}
	secret, err = vault.getKey(input.key)
	if err!=nil {
		return fmt.Errorf("%w: %w", ErrGetKey, err)
	}
	
	err = displaySecret(input.key, input.secret)
	if err != nil {
		return err
	}
}

func displaySecret(key string, secret string) error {
	content := []byte(
		"Key: " + key + "\n" +
		"Secret: " + secret + "\n",
	)

	cmd := exec.Command("less", "-R")

	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func handleGetKey(args []string, vault string) {
	input, err := parseGetKey(args, vault);
	if err != nil {
		fmt.Println(err);
		return;
	}
	
	err = executeGetKey(input);
	if err != nil {
		fmt.Println(err);
		return;
	}
}