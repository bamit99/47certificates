package main

import (
	"path/filepath"
	"testing"

	"github.com/bamit99/47certificates/internal/auth"
	"github.com/bamit99/47certificates/internal/store"
)

func TestUserAddTwiceFailsClearly(t *testing.T) {
	dir := t.TempDir()
	if err := runUser([]string{"add", "--data-dir", dir, "--username", "admin", "--password", "pw"}); err != nil {
		t.Fatal(err)
	}
	err := runUser([]string{"add", "--data-dir", dir, "--username", "admin", "--password", "pw"})
	if err == nil {
		t.Fatal("second add must fail")
	}
	st, err := store.Open(filepath.Join(dir, "47c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UserByUsername(t.Context(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.CheckPassword(u.PasswordHash, "pw") {
		t.Fatal("stored hash does not verify")
	}
}

func TestUserAddRequiresCredentials(t *testing.T) {
	if err := runUser([]string{"add", "--data-dir", t.TempDir()}); err == nil {
		t.Fatal("expected error")
	}
}
