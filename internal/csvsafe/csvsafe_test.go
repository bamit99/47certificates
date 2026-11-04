package csvsafe

import "testing"

func TestCellNeutralisesFormulas(t *testing.T) {
	bad := []string{
		"=1+1",
		"+1",
		"-1",
		"@SUM(A1)",
		"\tcmd",
		"\rcmd",
	}
	for _, s := range bad {
		got := Cell(s)
		if got == s {
			t.Errorf("Cell(%q) = %q; a formula must be neutralised", s, got)
		}
		if got[0] != '\'' {
			t.Errorf("Cell(%q) = %q; the first character must be an apostrophe", s, got)
		}
	}
	good := []string{"", "CN=example.com", "a.example.com", "ECDSA", "398"}
	for _, s := range good {
		if got := Cell(s); got != s {
			t.Errorf("Cell(%q) = %q; a safe value must be unchanged", s, got)
		}
	}
}

func TestRowAppliesCell(t *testing.T) {
	got := Row([]string{"=cmd", "safe"})
	if got[0] != "'=cmd" {
		t.Errorf("row = %v", got)
	}
	if got[1] != "safe" {
		t.Errorf("row = %v", got)
	}
}
