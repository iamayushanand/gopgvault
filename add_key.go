package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type AddKeyInput struct {
	key   string
	vault string
}

func newAddKeyCommand() *cobra.Command {
	input := &AddKeyInput{vault: DefaultVaultName}
	command := &cobra.Command{
		Use:   commandAddKey + " <key>",
		Short: "Add a secret to a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input.key = args[0]
			if err := executeAddKey(input); err != nil {
				return fmt.Errorf("add key %q to vault %q: %w", input.key, input.vault, err)
			}
			cmd.Printf("Successfully added key %q to vault %q\n", input.key, input.vault)
			return nil
		},
	}
	command.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	return command
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
	return vault.addKey(input.key, secret)
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
