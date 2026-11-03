package auth

import (
	"regexp"
	"strings"
	"testing"
)

func TestHashAndCheck(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") {
		t.Fatal("should match")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("must not match")
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash = %q", h)
	}
	if !regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`).MatchString(h) {
		t.Fatalf("unexpected encoding: %q", h)
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
	if !CheckPassword(a, "same") || !CheckPassword(b, "same") {
		t.Fatal("both hashes should verify")
	}
}

func TestCheckPasswordRejectsMalformedHashes(t *testing.T) {
	cases := []string{
		"",
		"plaintext",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyonepart",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=65536,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=bad,t=3,p=2$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!!$aGFzaA",
	}
	for _, h := range cases {
		if CheckPassword(h, "anything") {
			t.Errorf("%q must not verify", h)
		}
	}
}
