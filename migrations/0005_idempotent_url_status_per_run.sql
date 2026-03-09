-- ============================================================================
-- Migration: Idempotent url_status per run (one row per run_id + final_domain)
-- ============================================================================
-- DATABASE.md and README state that including the same domain multiple times
-- in one input file should store only one record. The previous uniqueness
-- was (final_domain, observed_at_ms), so two scans in the same run got
-- different observed_at_ms and inserted duplicate rows.
-- This migration adds UNIQUE(run_id, final_domain) so that within a run,
-- the same final_domain upserts to a single row (last write wins).
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_url_status_run_final_domain
ON url_status(run_id, final_domain);
