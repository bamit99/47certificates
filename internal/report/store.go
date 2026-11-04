package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"context"

	"github.com/bamit99/47certificates/internal/store"
)

// GenerateAndStore creates the report row, generates the artifacts, and saves
// them under reportsDir. It is the shared path used by the CLI, the web UI,
// and the scheduler.
func GenerateAndStore(ctx context.Context, st *store.Store, reportsDir string, kind Kind, scanID int64, domain string, userID *int64, now time.Time) (store.Report, error) {
	params, err := json.Marshal(map[string]string{"domain": domain})
	if err != nil {
		return store.Report{}, err
	}
	sc, err := st.ScanByID(ctx, scanID)
	if err != nil {
		return store.Report{}, err
	}
	reportID, err := st.CreateDomainReport(ctx, scanID, string(kind), userID, sc.OwnerDomainID(), params)
	if err != nil {
		return store.Report{}, fmt.Errorf("report: create row: %w", err)
	}

	artifacts, genErr := Generate(ctx, st, reportID, scanID, kind, domain, now)
	if genErr != nil {
		_ = st.FailReport(ctx, reportID, genErr.Error())
		return store.Report{}, genErr
	}

	// The snapshot is the delta baseline for a later report of the same kind.
	// It survives retention pruning the observations it was built from.
	if err := st.SaveReportSnapshot(ctx, reportID, artifacts.Snapshot); err != nil {
		_ = st.FailReport(ctx, reportID, err.Error())
		return store.Report{}, err
	}

	dir := filepath.Join(reportsDir, strconv.FormatInt(reportID, 10))
	if err := writeArtifacts(dir, artifacts); err != nil {
		_ = st.FailReport(ctx, reportID, err.Error())
		return store.Report{}, err
	}
	paths := []string{
		filepath.Join(dir, "report.html"),
		filepath.Join(dir, "report.csv"),
		filepath.Join(dir, "report.json"),
		filepath.Join(dir, "report.md"),
		filepath.Join(dir, "report.pdf"),
	}
	sizeTotal, shaJSON, err := hashFiles(paths)
	if err != nil {
		_ = st.FailReport(ctx, reportID, err.Error())
		return store.Report{}, err
	}
	if err := st.SaveReportFiles(ctx, reportID, paths[0], paths[1], paths[2], paths[3], paths[4], sizeTotal, shaJSON); err != nil {
		_ = st.FailReport(ctx, reportID, err.Error())
		return store.Report{}, err
	}
	return st.ReportByID(ctx, reportID)
}

func writeArtifacts(dir string, a Artifacts) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"report.html": a.HTML,
		"report.csv":  a.CSV,
		"report.json": a.JSON,
		"report.md":   a.Markdown,
		"report.pdf":  a.PDF,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func hashFiles(paths []string) (int64, string, error) {
	hashes := make([]string, 0, len(paths))
	var total int64
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return 0, "", err
		}
		sum := sha256.Sum256(data)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		total += int64(len(data))
	}
	combined := sha256.Sum256([]byte(strings.Join(hashes, " ")))
	object, err := json.Marshal(map[string]string{
		"combined": hex.EncodeToString(combined[:]),
		"html":     hashes[0],
		"csv":      hashes[1],
		"json":     hashes[2],
		"md":       hashes[3],
		"pdf":      hashes[4],
	})
	if err != nil {
		return 0, "", err
	}
	return total, string(object), nil
}
