package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bamit99/47certificates/internal/store"
	_ "modernc.org/sqlite"
)

func healthCheck(path string) error {
	if st, err := os.Stat(path); err != nil {
		return fmt.Errorf("health: database at %s is missing: %w", path, err)
	} else if st.IsDir() {
		return fmt.Errorf("health: %s is a directory", path)
	}

	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", path))
	if err != nil {
		return fmt.Errorf("health: open: %w", err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("health: schema check (expected schema version %d): %w", store.LatestSchemaVersion(), err)
	}
	if version != store.LatestSchemaVersion() {
		return fmt.Errorf("health: schema version %d, binary expects %d", version, store.LatestSchemaVersion())
	}
	return nil
}

func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOr("47C_DATA_DIR", "./data"), "directory for the database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return healthCheck(filepath.Join(*dataDir, "47c.db"))
}
