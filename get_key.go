package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

type GetKeyInput struct {
	key   string
	vault string
}

func newGetKeyCommand() *cobra.Command {
	input := &GetKeyInput{vault: DefaultVaultName}
	command := &cobra.Command{
		Use:   commandGetKey + " <key>",
		Short: "Display a secret from a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			input.key = args[0]
			if err := executeGetKey(input); err != nil {
				return fmt.Errorf("get key %q from vault %q: %w", input.key, input.vault, err)
			}
			return nil
		},
	}
	command.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	return command
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

	cmd := exec.Command(pagerExecutable, "-R")
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
