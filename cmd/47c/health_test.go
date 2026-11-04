package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bamit99/47certificates/internal/store"
)

func TestHealthFailsOnMissingDB(t *testing.T) {
	if err := healthCheck(filepath.Join(t.TempDir(), "absent.db")); err == nil {
		t.Fatal("expected error")
	}
}

func TestHealthFailsOnNonDBFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notadb.db")
	if err := os.WriteFile(path, []byte("this is not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := healthCheck(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestHealthOKOnFreshDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := healthCheck(path); err != nil {
		t.Fatalf("health: %v", err)
	}
}

func TestBackupRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "47c.db")
	bootstrap(t, src)
	out := filepath.Join(dir, "backup.db")
	if err := os.WriteFile(out, []byte("already here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backupDB(src, out); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestBackupCreatesCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "47c.db")
	dst := filepath.Join(dir, "sub", "copy.db")
	bootstrap(t, src)
	if err := backupDB(src, dst); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("backup is empty")
	}
}

func bootstrap(t *testing.T, path string) {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	st.Close()
}
