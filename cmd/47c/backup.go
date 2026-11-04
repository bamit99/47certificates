package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// backupDB copies the database to dst using VACUUM INTO. It refuses to
// overwrite an existing file.
func backupDB(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("backup: %s already exists", dst)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s", src))
	if err != nil {
		return err
	}
	defer db.Close()
	// VACUUM INTO does not accept a bound parameter, so escape the path by
	// doubling single quotes.
	escaped := strings.ReplaceAll(dst, "'", "''")
	if _, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", escaped)); err != nil {
		return fmt.Errorf("backup: VACUUM INTO: %w", err)
	}
	return nil
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dataDir := fs.String("data-dir", envOr("47C_DATA_DIR", "./data"), "directory for the database")
	out := fs.String("out", "", "backup destination path (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("backup: --out is required")
	}
	return backupDB(filepath.Join(*dataDir, "47c.db"), *out)
}
