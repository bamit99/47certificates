package phase

import (
	"testing"
	"time"
)

func TestForBoundaries(t *testing.T) {
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), "P0"},
		{time.Date(2026, 3, 14, 23, 59, 59, 0, time.UTC), "P0"},
		{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), "P1"},
		{time.Date(2027, 3, 14, 23, 59, 59, 0, time.UTC), "P1"},
		{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), "P2"},
		{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), "P3"},
	}
	for _, c := range cases {
		if got := For(c.at).Name; got != c.want {
			t.Errorf("%s: got %s, want %s", c.at, got, c.want)
		}
	}
}

func TestMaxValues(t *testing.T) {
	r := For(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if r.MaxLifetimeDays != 200 || r.MaxDVReuseDays != 200 {
		t.Fatalf("%+v", r)
	}
	if p3 := For(time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC)); p3.MaxLifetimeDays != 47 || p3.MaxDVReuseDays != 10 {
		t.Fatalf("%+v", p3)
	}
}

func TestLifetimeDaysUsesArithmetic(t *testing.T) {
	nb := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	na := nb.Add(397*24*time.Hour + 23*time.Hour)
	if got := LifetimeDays(nb, na); got != 397 {
		t.Fatalf("got %d", got)
	}
}
