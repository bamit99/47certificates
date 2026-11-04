package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bamit99/47certificates/internal/auth"

	"github.com/bamit99/47certificates/internal/config"
	"github.com/bamit99/47certificates/internal/discover"
	"github.com/bamit99/47certificates/internal/jobs"
	"github.com/bamit99/47certificates/internal/notify"
	"github.com/bamit99/47certificates/internal/roots"
	"github.com/bamit99/47certificates/internal/scan"
	"github.com/bamit99/47certificates/internal/schedule"
	"github.com/bamit99/47certificates/internal/store"
	"github.com/bamit99/47certificates/internal/web"
)

func runServe(args []string) error {
	cfg, err := config.Load(args, os.Getenv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "47c.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		return err
	}

	// First-boot provisioning: when ADMIN_PASSWORD is set and no user exists,
	// create the initial admin account.
	if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" {
		if users, err := st.ListUsers(context.Background()); err == nil && len(users) == 0 {
			hash, err := auth.HashPassword(pw)
			if err != nil {
				return err
			}
			if err := st.CreateUser(context.Background(), "admin", hash); err != nil {
				return err
			}
			log.Printf("47c: created initial admin user from ADMIN_PASSWORD")
		}
	}

	engine := &scan.Engine{
		Store:       st,
		Source:      discover.NewCRTSource(nil),
		Fallback:    discover.NewCertSpotterSource(nil),
		Resolver:    discover.NetResolver{},
		Roots:       roots.Pool(),
		Now:         time.Now,
		Concurrency: 32,
		QPS:         25,
		Timeout:     10 * time.Second,
	}
	runner := jobs.New(st, engine, time.Now)
	startScheduler(st, cfg, runner)

	handler := web.New(web.Deps{Store: st, Jobs: runner, Now: time.Now, DataDir: cfg.DataDir})
	srv := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	log.Printf("47c serving on %s (data dir %s)", cfg.Listen, cfg.DataDir)
	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			serveErr <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			serveErr <- srv.ListenAndServe()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serveErr:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case s := <-sig:
		log.Printf("47c: received %s, shutting down", s)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func startScheduler(st *store.Store, cfg config.Config, runner *jobs.Runner) {
	loc := time.Local
	settings := func(key, def string) string {
		if v, err := st.GetSetting(context.Background(), key); err == nil && strings.TrimSpace(v) != "" {
			return v
		}
		return def
	}

	reportsDir := filepath.Join(cfg.DataDir, "reports")

	// Nightly inventory scan.
	scans, err := schedule.New(settings("schedule", "17 3 * * *"), loc)
	if err != nil {
		log.Printf("schedule: %v; scan scheduler disabled", err)
	} else {
		if _, err := scans.AddFunc(settings("schedule", "17 3 * * *"), func() {
			time.Sleep(schedule.Jitter())
			ctx := context.Background()
			id, err := runner.TriggerScan(ctx, "schedule", nil)
			if err != nil {
				log.Printf("schedule: trigger scan: %v", err)
				return
			}
			waitForTerminalScan(ctx, st, id, 4*time.Hour)
			keep := schedule.ParseRetention(settings("retention", "90"), 90)
			if err := st.PruneObservations(ctx, keep); err != nil {
				log.Printf("schedule: retention: %v", err)
			}
		}); err != nil {
			log.Printf("schedule: add scan job: %v", err)
		}
		scans.Start()
	}

	// Monthly reports + webhook.
	reports, err := schedule.New(settings("report.schedule", "7 4 1 * *"), loc)
	if err != nil {
		log.Printf("schedule: %v; report scheduler disabled", err)
		return
	}
	if _, err := reports.AddFunc(settings("report.schedule", "7 4 1 * *"), func() {
		time.Sleep(schedule.Jitter())
		ctx := context.Background()
		var wh *notify.Webhook
		if url := settings("report.webhook_url", ""); url != "" {
			secret, err := ensureWebhookSecret(ctx, st)
			if err != nil {
				log.Printf("schedule: webhook secret: %v", err)
				return
			}
			wh = &notify.Webhook{URL: url, Secret: secret}
		}
		_, err := schedule.ScheduledReport(ctx, st, reportsDir, wh, time.Now())
		if err != nil {
			log.Printf("schedule: report: %v", err)
		}
	}); err != nil {
		log.Printf("schedule: add report job: %v", err)
	}
	reports.Start()
}

func waitForTerminalScan(ctx context.Context, st *store.Store, scanID int64, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		sc, err := st.ScanByID(ctx, scanID)
		if err == nil && (sc.Status == "done" || sc.Status == "failed" || sc.Status == "cancelled") {
			log.Printf("schedule: scan #%d finished status=%s", scanID, sc.Status)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

// ensureWebhookSecret returns the HMAC key for outbound webhooks, generating
// one on first use.
//
// It returns an error rather than a fallback when the system random source
// fails: a predictable key would let anyone forge a delivery.
func ensureWebhookSecret(ctx context.Context, st *store.Store) (string, error) {
	const key = "webhook_secret"
	if v, err := st.GetSetting(ctx, key); err == nil && v != "" {
		return v, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("webhook secret: %w", err)
	}
	v := base64.RawStdEncoding.EncodeToString(b)
	if err := st.SetSetting(ctx, key, v); err != nil {
		return "", err
	}
	return v, nil
}

// webhookClient verifies HTTPS against the embedded Mozilla bundle so the
// scratch image works without a CA directory.
func webhookClient() *http.Client {
	return roots.HTTPClient(10 * time.Second)
}
