package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

type GetKeyInput struct {
	key   string
	vault string
}

func parseGetKey(args []string, vault string) (*GetKeyInput, error) {
	if len(args) != 1 {
		return nil, usageError(string(GetKey))
	}
	return &GetKeyInput{key: args[0], vault: vault}, nil
}

func executeGetKey(input *GetKeyInput) error {
	vault, err := getVault(input.vault)
	if err != nil {
		return err
	}
	secret, err := vault.getKey(input.key)
	if err != nil {
		return err
	}
	return displaySecret(input.key, secret)
}

func displaySecret(key, secret string) error {
	content := []byte("Key: " + key + "\nSecret: " + secret + "\n")
	defer clearBytes(content)

	cmd := exec.Command("less", "-R")
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func handleGetKey(args []string, vaultName string) error {
	input, err := parseGetKey(args, vaultName)
	if err != nil {
		return err
	}
	if err := executeGetKey(input); err != nil {
		return fmt.Errorf("get key %q from vault %q: %w", input.key, input.vault, err)
	}
	return nil
}
