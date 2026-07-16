package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/iamayushanand/gopass/src/config"
	"github.com/iamayushanand/gopass/src/vault"
	"github.com/spf13/cobra"
)

const (
	commandCreateVault   = "create-vault"
	commandAddKey        = "add-key"
	commandGetKey        = "get-key"
	DefaultVaultName     = "default"
	vaultDirectoryName   = ".gopass"
	vaultFileExtension   = ".gopass"
	defaultVaultFilename = DefaultVaultName + vaultFileExtension
	vaultFlagName        = "vault"
)

var (
	ErrMissingArguments     = errors.New("operation is missing arguments")
	ErrConfigNotInitialized = errors.New("config is not initialized")
	ErrVaultNotFound        = errors.New("vault not found")
)

type application struct {
	config *config.Config
}

func NewRootCommand(args []string) *cobra.Command {
	app := &application{}
	root := &cobra.Command{
		Use:           "gopass",
		Short:         "A GPG-backed command-line password manager",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args: func(_ *cobra.Command, _ []string) error {
			return ErrMissingArguments
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if len(args) > 0 && strings.HasPrefix(args[0], "-") {
				return fmt.Errorf("flags must follow a command")
			}
			if err := app.boot(); err != nil {
				return fmt.Errorf("initialize gopass: %w", err)
			}
			return nil
		},
	}
	root.SetArgs(args)
	root.AddCommand(
		app.newCreateVaultCommand(),
		app.newAddKeyCommand(),
		app.newGetKeyCommand(),
	)
	return root
}

func (a *application) boot() error {
	if a.config != nil {
		return nil
	}

	loaded, err := config.Load()
	if err != nil {
		return err
	}
	if _, found := loaded.FindVault(DefaultVaultName); found {
		a.config = loaded
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	defaultPath := filepath.Join(home, vaultDirectoryName, defaultVaultFilename)
	created := false
	if err := vault.Create(defaultPath); err == nil {
		created = true
	} else if !errors.Is(err, vault.ErrFileExists) {
		return err
	}

	if err := loaded.RegisterVault(DefaultVaultName, defaultPath); err != nil {
		if created {
			_ = os.Remove(defaultPath)
		}
		return err
	}
	a.config = loaded
	return nil
}

func (a *application) getVault(name string) (*vault.Vault, error) {
	if a.config == nil {
		return nil, ErrConfigNotInitialized
	}
	path, found := a.config.FindVault(name)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrVaultNotFound, name)
	}
	return vault.New(path), nil
}
