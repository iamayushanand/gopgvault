package cmd

import (
	"fmt"

	"github.com/iamayushanand/gopgvault/vault"
	"github.com/spf13/cobra"
)

type copySecretsInput struct {
	source      string
	destination string
	overwrite   bool
}

func (a *application) newCopySecretsCommand() *cobra.Command {
	input := &copySecretsInput{}
	cmd := &cobra.Command{
		Use:   commandCopySecrets + " <source-vault> <destination-vault>",
		Short: "Copy all secrets between vaults",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			input.source = args[0]
			input.destination = args[1]
			if err := a.copySecrets(input); err != nil {
				return fmt.Errorf("copy secrets from %q to %q: %w", input.source, input.destination, err)
			}
			command.Printf("Successfully copied secrets from vault %q to vault %q\n", input.source, input.destination)
			return nil
		},
	}
	cmd.Flags().BoolVar(&input.overwrite, "overwrite", false, "Overwrite conflicting keys")
	return cmd
}

func (a *application) copySecrets(input *copySecretsInput) error {
	if input.source == input.destination {
		return ErrSameVault
	}
	source, err := a.getVault(input.source)
	if err != nil {
		return err
	}
	destination, err := a.getVault(input.destination)
	if err != nil {
		return err
	}

	entries, err := source.Entries()
	if err != nil {
		return err
	}
	defer vault.ClearEntries(entries)
	return destination.PutEntries(entries, input.overwrite)
}
