package scan

import (
	"context"
	"testing"
	"time"
)

// The per-host limiter spaces the probes of one hostname apart, so a scan
// cannot open a burst of connections to one server.
func TestHostLimiterSpacesProbes(t *testing.T) {
	l := newHostLimiter(2) // two per second
	start := time.Now()
	var waits []time.Duration
	for i := 0; i < 4; i++ {
		waits = append(waits, l.reserve("a.example.com"))
	}
	// The first probe is immediate, the second waits half a second, the third
	// a second, the fourth a second and a half.
	if waits[0] != 0 {
		t.Errorf("first wait = %v, want 0", waits[0])
	}
	if waits[1] < 400*time.Millisecond || waits[1] > 600*time.Millisecond {
		t.Errorf("second wait = %v, want ~500ms", waits[1])
	}
	if waits[3] < 1400*time.Millisecond || waits[3] > 1600*time.Millisecond {
		t.Errorf("fourth wait = %v, want ~1500ms", waits[3])
	}
	_ = start
}

// Different hostnames do not wait for each other.
func TestHostLimiterIsPerHost(t *testing.T) {
	l := newHostLimiter(1)
	if got := l.reserve("a.example.com"); got != 0 {
		t.Errorf("first wait = %v, want 0", got)
	}
	if got := l.reserve("b.example.com"); got != 0 {
		t.Errorf("a different host must not wait, got %v", got)
	}
	if got := l.reserve("a.example.com"); got < 900*time.Millisecond {
		t.Errorf("the same host must wait, got %v", got)
	}
}

// The wait channel becomes ready after the delay and gives up when the
// context is cancelled.
func TestHostLimiterWaitRespectsContext(t *testing.T) {
	l := newHostLimiter(1)
	l.reserve("a.example.com")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	select {
	case <-l.wait(ctx, "a.example.com"):
		// The channel may be closed on cancellation; either way it must not
		// block forever.
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not return after the context was cancelled")
	}
}
