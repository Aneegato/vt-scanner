package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Global DB handle used by main.go
var db *sql.DB

// Scan is the lightweight record persisted to Postgres.
type Scan struct {
	SHA256         string
	FileName       string
	SizeBytes      int64
	MIME           string
	VTAnalysisID   string
	VTVerdict      string
	DetectionRatio float64
	VTJSON         []byte
	Explanation    sql.NullString
	StoredPath     sql.NullString
	CreatedAt      time.Time
	LastSeen       time.Time
	ScanCount      int
}

// initDB connects using DATABASE_URL and applies the schema (idempotent).
func initDB(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is empty")
	}

	d, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	// pool tuning (modest defaults)
	d.SetMaxOpenConns(10)
	d.SetMaxIdleConns(5)
	d.SetConnMaxLifetime(30 * time.Minute)

	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return err
	}

	// Apply base schema from embedFS if present; else use built-in fallback.
	schema, err := embedFS.ReadFile("schema.sql")
	if err != nil {
		schema = []byte(defaultSchemaSQL)
	}
	if _, err := d.ExecContext(ctx, string(schema)); err != nil {
		_ = d.Close()
		return err
	}

	// Apply small, idempotent hardening/migrations (safe to re-run).
	hardenSchema(ctx, d)

	db = d
	return nil
}

// getScanByHash returns a scan by sha256 (or error if not found).
func getScanByHash(ctx context.Context, sha string) (*Scan, error) {
	const q = `
SELECT
  sha256, filename, COALESCE(size_bytes,0), COALESCE(mime,''),
  COALESCE(vt_analysis_id,''), COALESCE(vt_verdict,''), COALESCE(detection_ratio,0),
  COALESCE(vt_json,'{}'::jsonb), explanation, stored_path, created_at,
  COALESCE(last_seen, created_at), COALESCE(scan_count, 1)
FROM scans
WHERE sha256 = $1`
	var s Scan
	if err := db.QueryRowContext(ctx, q, sha).Scan(
		&s.SHA256, &s.FileName, &s.SizeBytes, &s.MIME,
		&s.VTAnalysisID, &s.VTVerdict, &s.DetectionRatio,
		&s.VTJSON, &s.Explanation, &s.StoredPath, &s.CreatedAt,
		&s.LastSeen, &s.ScanCount,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

// getRecentScans returns last N entries for history/sidebar.
func getRecentScans(ctx context.Context, n int) ([]Scan, error) {
	const q = `
SELECT sha256, filename, COALESCE(size_bytes,0), COALESCE(mime,''), created_at
FROM scans
ORDER BY created_at DESC
LIMIT $1`
	rows, err := db.QueryContext(ctx, q, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.SHA256, &s.FileName, &s.SizeBytes, &s.MIME, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// insertScan upserts a record keyed by sha256.
func insertScan(ctx context.Context, s *Scan) error {
	const q = `
INSERT INTO scans (
  sha256, filename, size_bytes, mime,
  vt_analysis_id, vt_verdict, detection_ratio, vt_json, stored_path,
  last_seen, scan_count
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), 1)
ON CONFLICT (sha256) DO UPDATE SET
  filename        = EXCLUDED.filename,
  size_bytes      = EXCLUDED.size_bytes,
  mime            = EXCLUDED.mime,
  vt_analysis_id  = EXCLUDED.vt_analysis_id,
  vt_verdict      = EXCLUDED.vt_verdict,
  detection_ratio = EXCLUDED.detection_ratio,
  vt_json         = EXCLUDED.vt_json,
  stored_path     = COALESCE(EXCLUDED.stored_path, scans.stored_path),
  last_seen       = now(),
  scan_count      = scans.scan_count + 1`
	// Pass JSON as text so Postgres can cast to jsonb
	_, err := db.ExecContext(ctx, q,
		s.SHA256, s.FileName, s.SizeBytes, s.MIME,
		s.VTAnalysisID, s.VTVerdict, s.DetectionRatio, string(s.VTJSON), s.StoredPath,
	)
	return err
}

// saveExplanation stores/updates the human-readable explanation.
func saveExplanation(ctx context.Context, sha, expl string) error {
	const q = `UPDATE scans SET explanation=$1 WHERE sha256=$2`
	_, err := db.ExecContext(ctx, q, expl, sha)
	return err
}

// Apply small idempotent “migrations” that harden the table.
// Errors are ignored on purpose (e.g., constraint already exists).
func hardenSchema(ctx context.Context, d *sql.DB) {
	stmts := []string{
		// new columns for UX/analytics
		`ALTER TABLE scans ADD COLUMN IF NOT EXISTS last_seen  TIMESTAMPTZ DEFAULT now();`,
		`ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_count INTEGER     DEFAULT 1;`,

		// lightweight constraints (harmless if they already exist; may fail on old PG without IF NOT EXISTS — safe to ignore)
		`ALTER TABLE scans ADD CONSTRAINT scans_detection_ratio_chk CHECK (detection_ratio BETWEEN 0.0 AND 1.0);`,
		`ALTER TABLE scans ADD CONSTRAINT scans_sha256_hex_chk CHECK (sha256 ~ '^[0-9a-f]{64}$');`,

		// helpful index for “malicious only” feeds
		`CREATE INDEX IF NOT EXISTS scans_malicious_idx ON scans (created_at DESC) WHERE vt_verdict = 'malicious';`,
	}
	for _, s := range stmts {
		_, _ = d.ExecContext(ctx, s)
	}
}

// Fallback schema if schema.sql isn't embedded.
const defaultSchemaSQL = `
CREATE TABLE IF NOT EXISTS scans (
  id BIGSERIAL PRIMARY KEY,
  sha256 TEXT UNIQUE NOT NULL,
  filename TEXT,
  size_bytes BIGINT,
  mime TEXT,
  vt_analysis_id TEXT,
  vt_verdict TEXT,
  detection_ratio DOUBLE PRECISION,
  vt_json JSONB,
  explanation TEXT,
  stored_path TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now(),
  scan_count INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at DESC);

-- helpful filtered index
CREATE INDEX IF NOT EXISTS scans_malicious_idx ON scans (created_at DESC) WHERE vt_verdict = 'malicious';

-- basic integrity checks
DO $$
BEGIN
  BEGIN
    ALTER TABLE scans ADD CONSTRAINT scans_detection_ratio_chk CHECK (detection_ratio BETWEEN 0.0 AND 1.0);
  EXCEPTION WHEN duplicate_object THEN NULL;
  END;
  BEGIN
    ALTER TABLE scans ADD CONSTRAINT scans_sha256_hex_chk CHECK (sha256 ~ '^[0-9a-f]{64}$');
  EXCEPTION WHEN duplicate_object THEN NULL;
  END;
END$$;
`
