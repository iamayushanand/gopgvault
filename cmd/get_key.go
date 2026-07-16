package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

const pagerExecutable = "less"

type getKeyInput struct {
	key   string
	vault string
}

func (a *application) newGetKeyCommand() *cobra.Command {
	input := &getKeyInput{vault: DefaultVaultName}
	cmd := &cobra.Command{
		Use:   commandGetKey + " <key>",
		Short: "Display a secret from a vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			input.key = args[0]
			if err := a.getKey(input); err != nil {
				return fmt.Errorf("get key %q from vault %q: %w", input.key, input.vault, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	return cmd
}

func (a *application) getKey(input *getKeyInput) error {
	selected, err := a.getVault(input.vault)
	if err != nil {
		return err
	}
	secret, err := selected.GetKey(input.key)
	if err != nil {
		return err
	}
	return displaySecret(input.key, secret)
}

func displaySecret(key, secret string) error {
	content := []byte("Key: " + key + "\nSecret: " + secret + "\n")
	defer clear(content)

	command := exec.Command(pagerExecutable, "-R")
	command.Stdin = bytes.NewReader(content)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
