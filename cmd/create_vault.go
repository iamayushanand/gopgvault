package cmd

import (
	"fmt"
	"os"

	"github.com/iamayushanand/gopass/vault"
	"github.com/spf13/cobra"
)

type createVaultInput struct {
	name         string
	path         string
	gpgRecipient string
}

func (a *application) newCreateVaultCommand() *cobra.Command {
	input := &createVaultInput{}
	cmd := &cobra.Command{
		Use:   commandCreateVault + " <vault-name> <filepath>",
		Short: "Create an encrypted password vault",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			input.name = args[0]
			input.path = args[1]
			if err := a.createVault(input); err != nil {
				return fmt.Errorf("create vault %q: %w", input.name, err)
			}
			command.Printf("Successfully created vault %q\n", input.name)
			return nil
		},
	}
	cmd.Flags().StringVar(&input.gpgRecipient, "gpg", "", "GPG recipient to encrypt the vault for")
	return cmd
}

func (a *application) createVault(input *createVaultInput) error {
	if a.config == nil {
		return ErrConfigNotInitialized
	}
	if err := a.config.ValidateVault(input.name, input.path); err != nil {
		return err
	}
	if err := vault.Create(input.path, input.gpgRecipient); err != nil {
		return err
	}
	if err := a.config.RegisterVault(input.name, input.path, input.gpgRecipient); err != nil {
		if removeErr := os.Remove(input.path); removeErr != nil {
			return fmt.Errorf("register vault: %w (cleanup failed: %v)", err, removeErr)
		}
		return fmt.Errorf("register vault: %w", err)
	}
	return nil
}
