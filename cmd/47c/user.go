package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bamit99/47certificates/internal/auth"
	"github.com/bamit99/47certificates/internal/store"
)

func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("user: expected add or list")
	}
	switch args[0] {
	case "add":
		return userAdd(args[1:])
	case "list":
		return userList(args[1:])
	default:
		return fmt.Errorf("user: unknown subcommand %q", args[0])
	}
}

func userAdd(args []string) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOr("47C_DATA_DIR", "./data"), "directory for the database")
	username := fs.String("username", "", "username")
	password := fs.String("password", os.Getenv("ADMIN_PASSWORD"), "password (defaults to $ADMIN_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || *password == "" {
		return errors.New("user add: --username and --password are required")
	}
	hash, err := auth.HashPassword(*password)
	if err != nil {
		return err
	}
	st, err := openStoreCLI(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.CreateUser(ctx, *username, hash); err != nil {
		if errors.Is(err, store.ErrUserExists) {
			return fmt.Errorf("user add: user %q already exists", *username)
		}
		return err
	}
	fmt.Printf("created user %s\n", *username)
	return nil
}

func userList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOr("47C_DATA_DIR", "./data"), "directory for the database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStoreCLI(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	users, err := st.ListUsers(context.Background())
	if err != nil {
		return err
	}
	for _, u := range users {
		state := "enabled"
		if u.Disabled {
			state = "disabled"
		}
		fmt.Printf("%d\t%s\t%s\n", u.ID, u.Username, state)
	}
	return nil
}

func openStoreCLI(dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(dataDir, "47c.db"))
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}
