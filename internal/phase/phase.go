// Package phase encodes the CA/Browser Forum TLS lifetime schedule.
//
// A certificate is judged by the phase in force at its notBefore date, so a
// certificate issued before a boundary keeps its longer lifetime for the rest
// of its life.
package phase

import (
	"sort"
	"time"
)

// Rules describes one phase of the CA/B Forum schedule.
type Rules struct {
	Name            string
	StartsAt        time.Time
	MaxLifetimeDays int
	MaxDVReuseDays  int
}

// Schedule is ordered by StartsAt.
var Schedule = []Rules{
	{Name: "P0", StartsAt: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC), MaxLifetimeDays: 398, MaxDVReuseDays: 398},
	{Name: "P1", StartsAt: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), MaxLifetimeDays: 200, MaxDVReuseDays: 200},
	{Name: "P2", StartsAt: time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), MaxLifetimeDays: 100, MaxDVReuseDays: 100},
	{Name: "P3", StartsAt: time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), MaxLifetimeDays: 47, MaxDVReuseDays: 10},
}

// For returns the phase in force at t. Times before the first entry return P0.
func For(t time.Time) Rules {
	idx := sort.Search(len(Schedule), func(i int) bool {
		return Schedule[i].StartsAt.After(t)
	}) - 1
	if idx < 0 {
		return Schedule[0]
	}
	return Schedule[idx]
}

// Next returns the phase that follows the one in force at t. It returns the
// zero Rules after the last phase, when there is no further step.
func Next(t time.Time) Rules {
	idx := sort.Search(len(Schedule), func(i int) bool {
		return Schedule[i].StartsAt.After(t)
	})
	if idx >= len(Schedule) {
		return Rules{}
	}
	return Schedule[idx]
}

// LifetimeDays returns the whole days between notBefore and notAfter. This is
// arithmetic, not the ordered validity span: a backdated notBefore still
// shortens the measured lifetime.
func LifetimeDays(notBefore, notAfter time.Time) int {
	return int(notAfter.Sub(notBefore) / (24 * time.Hour))
}
