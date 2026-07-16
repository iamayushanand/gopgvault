package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type addKeyInput struct {
	key   string
	vault string
}

func (a *application) newAddKeyCommand() *cobra.Command {
	input := &addKeyInput{vault: DefaultVaultName}
	cmd := &cobra.Command{
		Use:   commandAddKey + " <key>",
		Short: "Add a secret to a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			input.key = args[0]
			if err := a.addKey(input); err != nil {
				return fmt.Errorf("add key %q to vault %q: %w", input.key, input.vault, err)
			}
			command.Printf("Successfully added key %q to vault %q\n", input.key, input.vault)
			return nil
		},
	}
	cmd.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	return cmd
}

func (a *application) addKey(input *addKeyInput) error {
	secret, err := readSecret()
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}
	selected, err := a.getVault(input.vault)
	if err != nil {
		return err
	}
	return selected.AddKey(input.key, secret)
}

func readSecret() (string, error) {
	fmt.Print("Enter secret: ")
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	defer clear(secret)
	return string(secret), nil
}
