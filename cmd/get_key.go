package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/iamayushanand/gopass/vault"
	"github.com/spf13/cobra"
)

const (
	pagerExecutable = "less"
	grepExecutable  = "grep"
)

type getKeyInput struct {
	key   string
	grep  string
	vault string
}

func (a *application) newGetKeyCommand() *cobra.Command {
	input := &getKeyInput{vault: DefaultVaultName}
	cmd := &cobra.Command{
		Use:   commandGetKey + " (<key> | --grep <pattern>)",
		Short: "Display secrets from a vault",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 && input.grep == "" {
				return nil
			}
			if len(args) == 0 && input.grep != "" {
				return nil
			}
			return fmt.Errorf("provide exactly one key or --grep pattern")
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				input.key = args[0]
			}
			if err := a.getKey(input); err != nil {
				lookup := input.key
				if input.grep != "" {
					lookup = input.grep
				}
				return fmt.Errorf("get key %q from vault %q: %w", lookup, input.vault, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&input.vault, vaultFlagName, DefaultVaultName, "Vault to use")
	cmd.Flags().StringVar(&input.grep, "grep", "", "Search key names using a regular expression")
	return cmd
}

func (a *application) getKey(input *getKeyInput) error {
	selected, err := a.getVault(input.vault)
	if err != nil {
		return err
	}
	if input.grep != "" {
		entries, err := selected.Entries()
		if err != nil {
			return err
		}
		defer vault.ClearEntries(entries)
		matches, err := grepEntries(input.grep, entries)
		if err != nil {
			return err
		}
		defer vault.ClearEntries(matches)
		return displayEntries(matches)
	}
	secret, err := selected.GetKey(input.key)
	if err != nil {
		return err
	}
	return displaySecret(input.key, secret)
}

func displaySecret(key, secret string) error {
	return displayEntries([]vault.Entry{{Key: key, Secret: secret}})
}

func grepEntries(pattern string, entries []vault.Entry) ([]vault.Entry, error) {
	var keys strings.Builder
	for _, entry := range entries {
		keys.WriteString(entry.Key)
		keys.WriteByte('\n')
	}

	command := exec.Command(grepExecutable, "--", pattern)
	command.Stdin = strings.NewReader(keys.String())
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
			return nil, fmt.Errorf("%w: %q", ErrNoMatchingKeys, pattern)
		}
		return nil, fmt.Errorf("grep keys: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	byKey := make(map[string][]vault.Entry, len(entries))
	for _, entry := range entries {
		byKey[entry.Key] = append(byKey[entry.Key], entry)
	}
	var matches []vault.Entry
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		matches = append(matches, byKey[scanner.Text()]...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoMatchingKeys, pattern)
	}
	return matches, nil
}

func displayEntries(entries []vault.Entry) error {
	var contentBuffer bytes.Buffer
	for i, entry := range entries {
		if i > 0 {
			contentBuffer.WriteByte('\n')
		}
		fmt.Fprintf(&contentBuffer, "Key: %s\nSecret: %s\n", entry.Key, entry.Secret)
	}
	content := contentBuffer.Bytes()
	defer clear(content)

	command := exec.Command(pagerExecutable, "-R")
	command.Stdin = bytes.NewReader(content)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
