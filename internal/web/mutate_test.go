package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amit/47certificates/internal/auth"
	"github.com/amit/47certificates/internal/jobs"
	"github.com/amit/47certificates/internal/scan"
	"github.com/amit/47certificates/internal/store"
)

type fakeJobs struct {
	scanID    int64
	trigger   error
	cancelErr error
	// domain is the domain the last trigger asked for.
	domain string
}

func (f *fakeJobs) TriggerScan(context.Context, string, *int64) (int64, error) {
	return f.TriggerDomainScan(context.Background(), "manual", nil, "")
}

func (f *fakeJobs) TriggerDomainScan(_ context.Context, _ string, _ *int64, domain string) (int64, error) {
	if f.trigger != nil {
		return 0, f.trigger
	}
	f.domain = domain
	if f.scanID == 0 {
		f.scanID = 42
	}
	return f.scanID, nil
}

func (f *fakeJobs) Cancel(scanID int64) error { return f.cancelErr }

func (f *fakeJobs) Subscribe(scanID int64) (<-chan scan.Progress, func()) {
	ch := make(chan scan.Progress)
	close(ch)
	return ch, func() {}
}

func newMutateTestServer(t *testing.T, fj *fakeJobs) (*Server, *store.Store, *http.Cookie, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.CreateUser(ctx, "admin", hash); err != nil {
		t.Fatal(err)
	}
	u, err := st.UserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Store: st, Jobs: fj, Now: time.Now}).(*Server)
	cookie := login(t, s)
	return s, st, cookie, u.ID
}

func csrfPost(t *testing.T, s *Server, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return post(s, path, form, cookie, s.csrfToken(cookie.Value))
}

func TestScopeRejectsOutOfScopeSeed(t *testing.T) {
	s, st, cookie, _ := newMutateTestServer(t, &fakeJobs{})
	rec := csrfPost(t, s, "/scope", url.Values{"entries": {"include:example.com\nseed:other.net\n"}}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "seed") || !strings.Contains(rec.Body.String(), "must be inside") {
		t.Fatalf("body should mention the seed constraint: %s", rec.Body.String())
	}
	_ = st
}

func TestEveryMutationIsAudited(t *testing.T) {
	s, st, cookie, userID := newMutateTestServer(t, &fakeJobs{})

	rec := csrfPost(t, s, "/scope", url.Values{"entries": {"include:example.com\n"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("scope status = %d", rec.Code)
	}

	rec = csrfPost(t, s, "/settings", url.Values{"ports": {"443,8443"}, "timeout": {"5s"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("settings status = %d", rec.Code)
	}

	rec = csrfPost(t, s, "/scans", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("scan trigger status = %d", rec.Code)
	}

	entries, err := st.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, a := range entries {
		if a.UserID == nil || *a.UserID != userID {
			t.Fatalf("audit entry %+v does not carry user id %d", a, userID)
		}
		got[a.Action]++
	}
	for _, want := range []string{"scope.replace", "settings.update", "scan.trigger"} {
		if got[want] != 1 {
			t.Fatalf("want exactly one %q audit row, got actions %v", want, got)
		}
	}
}

func TestScanTriggerBusyReturns409(t *testing.T) {
	s, _, cookie, _ := newMutateTestServer(t, &fakeJobs{trigger: jobs.ErrBusy})
	rec := csrfPost(t, s, "/scans", url.Values{}, cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSettingsRejectsBadTimeout(t *testing.T) {
	s, _, cookie, _ := newMutateTestServer(t, &fakeJobs{})
	rec := csrfPost(t, s, "/settings", url.Values{"timeout": {"not-a-duration"}}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSettingsIgnoresUnknownKeys(t *testing.T) {
	s, st, cookie, _ := newMutateTestServer(t, &fakeJobs{})
	rec := csrfPost(t, s, "/settings", url.Values{"evil": {"x"}, "ports": {"443"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, err := st.GetSetting(context.Background(), "evil"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown key must not be persisted")
	}
}
