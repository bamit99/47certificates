package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bamit99/47certificates/internal/store"
)

func TestScanCLIRefusesWhenLockHeld(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "47c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	lock, err := st.AcquireScanLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("include:example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runScan([]string{"--data-dir", dir, "--scope", scopeFile, "--ports", "443"})
	if !errors.Is(err, store.ErrScanInProgress) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadScopeRejectsOutOfScopeSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(path, []byte("include:example.com\nseed:other.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScope(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("443, 8443")
	if err != nil || len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := parsePorts("0"); err == nil {
		t.Fatal("port 0 must be rejected")
	}
	if _, err := parsePorts("443,abc"); err == nil {
		t.Fatal("non-numeric port must be rejected")
	}
}
