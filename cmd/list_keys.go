package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type listKeysInput struct {
	vault string
}

func (a *application) newListKeysCommand() *cobra.Command {
	input := &listKeysInput{vault: DefaultVaultName}
	cmd := &cobra.Command{
		Use:   commandListKeys,
		Short: "List keys in a vault",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			keys, err := a.listKeys(input)
			if err != nil {
				return fmt.Errorf("list keys in vault %q: %w", input.vault, err)
			}
			for _, key := range keys {
				command.Println(key)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	return cmd
}

func (a *application) listKeys(input *listKeysInput) ([]string, error) {
	selected, err := a.getVault(input.vault)
	if err != nil {
		return nil, err
	}
	return selected.ListKeys()
}
