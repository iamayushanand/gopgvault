package main 

import (
	"flag"
	"fmt"
	"encoding/csv"
	"os"
	"os/exec"
	"bytes"
	"strings"
	"path/filepath"
	"golang.org/x/term"
)

type Command string

const (
	CreateVault Command = "create-vault"
	AddKey Command = "add-key"
	GetKey Command = "get-key"
)

func parseArgs() []string {
	var vault string
	flag.StringVar(&vault, "vault", "default", "Vault to use")
	
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("No command provided")
		return
	}
	return args
}

func main() {
	args := parseArgs()
	boot()
	command := Command(args[0])

	switch command {
	case CreateVault:
		handleCreateVault(args)
	case AddKey:
		if len(args) != 2 {
			fmt.Println("Usage: add-key key")
			return
		}
	
		key := args[1]
		secret, err := get_secret_from_user()
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
		vaultFilePath, err := get_vault_fp(vault)
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
		err = add_key(key, secret, vaultFilePath)
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
	case GetKey:
		if len(args) != 2 {
			fmt.Println("Usage: get-key key")
			return
		}
	
		key := args[1]
		vaultFilePath, err := get_vault_fp(vault)
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
		secret, err := get_secret_from_vault(vaultFilePath, key)
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
		err = display_secret(key, secret)
		if err!=nil {
			fmt.Printf("err: %v", err)
		}
		
	}
}

func boot() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, ".gopassrc")
	vaultDir := filepath.Join(home, ".gopass")
	defaultVault := filepath.Join(vaultDir, "default.gopass")

	// If the config already exists, assume we're already initialized.
	if _, err := os.Stat(configPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	// Create ~/.gopass/
	if err := os.MkdirAll(vaultDir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(defaultVault); os.IsNotExist(err) {
			if err := lock(defaultVault, []byte{}); err != nil {
				return err
			}
	} else if err != nil {
			return err
	}

	// Create ~/.gopassrc
	configFile, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer configFile.Close()

	writer := csv.NewWriter(configFile)
	if err := writer.Write([]string{"default", defaultVault}); err != nil {
		return err
	}
	writer.Flush()

	return writer.Error()
}

func get_secret_from_vault(vaultFilePath string, key string) (string, error) {
	unlockedVault, err := unlock(vaultFilePath)
	if err != nil {
		return "", err
	}
	defer func() {
		// Zero the plaintext when we're done with it.
		for i := range unlockedVault {
			unlockedVault[i] = 0
		}
	}()

	reader := csv.NewReader(bytes.NewReader(unlockedVault))
	records, err := reader.ReadAll()
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if len(record) != 2 {
			continue
		}

		if record[0] == key {
			return record[1], nil
		}
	}

	return "", fmt.Errorf("key %q not found", key)
}

func display_secret(key, secret string) error {
	content := []byte(
		"Key: " + key + "\n" +
		"Secret: " + secret + "\n",
	)

	cmd := exec.Command("less", "-R")

	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func add_key(key string, secret string, vaultFilePath string) error {
	unlockedVault, err := unlock(vaultFilePath)
	if err != nil {
		return err
	}

	reader := csv.NewReader(bytes.NewReader(unlockedVault))
	records, err := reader.ReadAll()
	if err != nil && err.Error() != "EOF" {
		return err
	}

	// Check for duplicate key.
	for _, record := range records {
		if len(record) < 2 {
			continue
		}

		if record[0] == key {
			return fmt.Errorf("key %q already exists", key)
		}
	}

	// Append the new entry.
	var builder strings.Builder

	// Preserve existing contents.
	builder.Write(unlockedVault)
	if len(unlockedVault) > 0 && unlockedVault[len(unlockedVault)-1] != '\n' {
		builder.WriteByte('\n')
	}

	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{key, secret}); err != nil {
		return err
	}
	writer.Flush()

	if err := writer.Error(); err != nil {
		return err
	}

	return lock(vaultFilePath, []byte(builder.String()))
}

func unlock(vaultFilePath string) ([]byte, error) {
	cmd := exec.Command(
		"gpg",
		"--quiet",
		"--decrypt",
		vaultFilePath,
	)

	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		fmt.Println(stderr.String()) // Print stderr
		return nil, fmt.Errorf("gpg decrypt failed: %w", err)
	}

	return out, nil
}

func lock(vaultFilePath string, content []byte) error {
	cmd := exec.Command(
		"gpg",
		"--quiet",
		"--batch",
		"--yes",
		"--encrypt",
		"--default-recipient-self",
		"--output", vaultFilePath,
	)

	cmd.Stdin = bytes.NewReader(content)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gpg encrypt failed: %v\n%s", err, out)
	}

	return nil
}

func get_vault_fp(vaultName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(home, ".gopassrc")

	file, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if len(record) != 2 {
			continue
		}

		if record[0] == vaultName {
			return record[1], nil
		}
	}

	return "", fmt.Errorf("vault %q not found", vaultName)
}

func get_secret_from_user() (string, error) {
	fmt.Print("Enter secret: ")

	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Move to the next line after Enter is pressed.

	if err != nil {
		return "", err
	}

	return string(secret), nil
}

func create_vault(vaultName string, vaultPath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(home, ".gopassrc")

	// Open (or create) the config file.
	file, err := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil && err.Error() != "EOF" {
		return "", err
	}

	// Check for duplicate vault name or path.
	for _, record := range records {
		if len(record) != 2 {
			continue
		}

		if record[0] == vaultName {
			return "", fmt.Errorf("vault %q already exists", vaultName)
		}

		if record[1] == vaultPath {
			return "", fmt.Errorf("path %q is already registered", vaultPath)
		}
	}

	// Append the new vault.
	writer := csv.NewWriter(file)
	if _, err := file.Seek(0, os.SEEK_END); err != nil {
		return "", err
	}

	if err := writer.Write([]string{vaultName, vaultPath}); err != nil {
		return "", err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}

	return vaultName, nil
}

func display_creation_status(vaultName string, err error) {
	if err != nil {
		fmt.Printf("Failed to create vault %q: %v\n", vaultName, err)
		return
	}

	fmt.Printf("Successfully created vault %q\n", vaultName)
}

// func add_key(vault_name, key, secret) {
// 	vault_file = get_file_from_vault()
// 	decryptionStatus/fd := decrypt(key, vault_file)
// 	insert_key(fd, key, secret)
// 	encrypt(fd, vault_file)
// }
