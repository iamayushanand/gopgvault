package cmd

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/iamayushanand/gopgvault/vault"
	"github.com/spf13/cobra"
)

type importSecretsInput struct {
	path      string
	vault     string
	overwrite bool
}

func (a *application) newImportSecretsCommand() *cobra.Command {
	input := &importSecretsInput{}
	cmd := &cobra.Command{
		Use:   commandImportSecrets + " <csv-file>",
		Short: "Import secrets from a plaintext CSV file",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			input.path = args[0]
			if err := a.importSecrets(input, command.InOrStdin(), command.OutOrStdout()); err != nil {
				return fmt.Errorf("import secrets from %q: %w", input.path, err)
			}
			command.Println("Successfully imported secrets")
			command.Println("DELETE THE PLAINTEXT CSV FILE NOW.")
			return nil
		},
	}
	cmd.Flags().StringVar(&input.vault, vaultFlagName, "", "Existing vault to import into")
	cmd.Flags().BoolVar(&input.overwrite, "overwrite", false, "Overwrite conflicting keys")
	return cmd
}

func (a *application) importSecrets(input *importSecretsInput, promptInput io.Reader, promptOutput io.Writer) error {
	rawEntries, err := readCSVEntries(input.path)
	if err != nil {
		return err
	}
	defer vault.ClearEntries(rawEntries)

	entries, err := normalizeEntries(rawEntries, input.overwrite)
	if err != nil {
		return err
	}

	if input.vault != "" {
		selected, err := a.getVault(input.vault)
		if err != nil {
			return err
		}
		return selected.PutEntries(entries, input.overwrite)
	}

	name, path, err := promptForVault(promptInput, promptOutput)
	if err != nil {
		return err
	}
	if err := a.config.ValidateVault(name, path); err != nil {
		return err
	}
	if err := vault.CreateWithEntries(path, "", entries); err != nil {
		return err
	}
	if err := a.config.RegisterVault(name, path, ""); err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("register vault: %w (cleanup failed: %v)", err, removeErr)
		}
		return fmt.Errorf("register vault: %w", err)
	}
	return nil
}

func readCSVEntries(path string) ([]vault.Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []vault.Entry
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			vault.ClearEntries(entries)
			return nil, err
		}
		if len(record) != 2 {
			vault.ClearEntries(entries)
			return nil, vault.ErrInvalidEntry
		}
		entries = append(entries, vault.Entry{
			// Clone the key so it does not retain the CSV record backing string,
			// which also contained the immutable parse-time secret.
			Key:    strings.Clone(record[0]),
			Secret: []byte(record[1]),
		})
	}
}

func normalizeEntries(entries []vault.Entry, overwrite bool) ([]vault.Entry, error) {
	indices := make(map[string]int, len(entries))
	if !overwrite {
		conflicts := make(map[string]struct{})
		for i, entry := range entries {
			if _, found := indices[entry.Key]; found {
				conflicts[entry.Key] = struct{}{}
			} else {
				indices[entry.Key] = i
			}
		}
		if len(conflicts) == 0 {
			return entries, nil
		}
		keys := make([]string, 0, len(conflicts))
		for key := range conflicts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%w: %q", vault.ErrConflictingKeys, keys)
	}

	next := 0
	for i := range entries {
		entry := &entries[i]
		if index, found := indices[entry.Key]; found {
			clear(entries[index].Secret)
			entries[index].Secret = entry.Secret
			*entry = vault.Entry{}
			continue
		}
		indices[entry.Key] = next
		if next != i {
			entries[next] = *entry
			*entry = vault.Entry{}
		}
		next++
	}
	return entries[:next], nil
}

func promptForVault(input io.Reader, output io.Writer) (string, string, error) {
	reader := bufio.NewReader(input)
	name, err := readPromptValue(reader, output, "Enter new vault name: ")
	if err != nil {
		return "", "", err
	}
	path, err := readPromptValue(reader, output, "Enter new vault path: ")
	if err != nil {
		return "", "", err
	}
	return name, path, nil
}

func readPromptValue(reader *bufio.Reader, output io.Writer, prompt string) (string, error) {
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return "", err
	}
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("prompted vault value cannot be empty")
	}
	return value, nil
}
