#!/usr/bin/env bash
# Comprehensive test: run url-list.txt through domain_status with --enable-whois and
# --status-port, then validate every table/column, all export formats, and monitoring endpoints.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- Configuration ---
SAMPLE_FILE="${1:-$REPO_ROOT/url-list.txt}"
STATUS_PORT="${STATUS_PORT:-19999}"
TIMEOUT_SCAN=600
export RUST_LOG="${RUST_LOG:-warn}"

if [[ ! -f "$SAMPLE_FILE" ]]; then
  echo "Error: Sample file not found: $SAMPLE_FILE"
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
DB="$TMPDIR/domain_status.db"
EXPORT_DIR="$TMPDIR/export"
mkdir -p "$EXPORT_DIR"

BIN="$REPO_ROOT/target/release/domain_status"
if [[ ! -x "$BIN" ]]; then
  echo "Building release binary..."
  cargo build --release -q
fi

echo "=== Comprehensive domain_status test ==="
echo "Sample file: $SAMPLE_FILE"
echo "Database: $DB"
echo "Status port: $STATUS_PORT"
echo ""

# --- 1. Run scan with --enable-whois and --status-port ---
echo "[1/5] Running scan (--enable-whois, --status-port $STATUS_PORT)..."
"$BIN" scan "$SAMPLE_FILE" \
  --enable-whois \
  --status-port "$STATUS_PORT" \
  --db-path "$DB" \
  --log-file "$TMPDIR/domain_status.log" \
  --log-level warn \
  --timeout-seconds 20 \
  --max-concurrency 10 \
  --rate-limit-rps 10 &

SCAN_PID=$!

# --- 2. Wait for status server and hit monitoring endpoints ---
echo "[2/5] Waiting for status server and validating monitoring endpoints..."
for i in $(seq 1 30); do
  if curl -sSf --connect-timeout 1 "http://127.0.0.1:$STATUS_PORT/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$SCAN_PID" 2>/dev/null; then
    echo "Scan process exited before status server became ready."
    wait "$SCAN_PID" || true
    exit 1
  fi
  sleep 1
done

# Health
curl -sSf "http://127.0.0.1:$STATUS_PORT/health" >/dev/null || { echo "FAIL: /health"; exit 1; }
echo "  /health: OK"

# Status (JSON): required top-level keys
STATUS_JSON=$(curl -sS "http://127.0.0.1:$STATUS_PORT/status")
for key in total_urls completed_urls failed_urls percentage_complete elapsed_seconds rate_per_second errors; do
  if ! echo "$STATUS_JSON" | grep -q "\"$key\""; then
    echo "FAIL: /status missing key: $key"
    exit 1
  fi
done
echo "  /status: OK (required keys present)"

# Metrics (Prometheus): must include domain_status_ prefix metrics
METRICS=$(curl -sS "http://127.0.0.1:$STATUS_PORT/metrics")
if ! echo "$METRICS" | grep -q "domain_status_"; then
  echo "FAIL: /metrics missing domain_status_* metrics"
  exit 1
fi
# When timing is available, these appear (optional after some URLs complete)
echo "  /metrics: OK (Prometheus format, domain_status_* present)"

# Optional: poll /status until scan completes (or timeout)
echo "  Waiting for scan to complete..."
for _ in $(seq 1 "$TIMEOUT_SCAN"); do
  if ! kill -0 "$SCAN_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "$SCAN_PID" 2>/dev/null; then
  echo "WARN: Scan did not finish within ${TIMEOUT_SCAN}s; killing."
  kill "$SCAN_PID" 2>/dev/null || true
fi
wait "$SCAN_PID" 2>/dev/null || true
echo "  Scan finished."

# --- 3. Validate every table and every column ---
echo "[3/5] Validating database schema (every table, every column)..."

# Expected tables and their columns (from migrations/0001_initial_schema.sql). Format: table|col1|col2|...
check_table_columns() {
  local table="$1"
  local expected="$2"
  if ! sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';" | grep -q .; then
    echo "FAIL: Table missing: $table"
    exit 1
  fi
  actual=$(sqlite3 "$DB" "PRAGMA table_info($table);" | cut -d'|' -f2 | sort | tr '\n' '|' | sed 's/|$//')
  expected_sorted=$(echo "$expected" | tr '|' '\n' | sort | tr '\n' '|' | sed 's/|$//')
  if [[ "$actual" != "$expected_sorted" ]]; then
    echo "FAIL: Column mismatch for $table"
    echo "  expected: $expected_sorted"
    echo "  actual:   $actual"
    exit 1
  fi
}

check_table_columns runs "run_id|version|fingerprints_source|fingerprints_version|geoip_version|start_time_ms|end_time_ms|elapsed_seconds|total_urls|successful_urls|failed_urls"
check_table_columns url_status "id|initial_domain|final_domain|ip_address|reverse_dns_name|http_status|http_status_text|response_time_seconds|title|keywords|description|is_mobile_friendly|tls_version|cipher_suite|key_algorithm|ssl_cert_subject|ssl_cert_issuer|ssl_cert_valid_from_ms|ssl_cert_valid_to_ms|spf_record|dmarc_record|observed_at_ms|run_id"
check_table_columns url_failures "id|attempted_url|final_url|initial_domain|final_domain|error_type|error_message|http_status|retry_count|elapsed_time_seconds|observed_at_ms|run_id"
check_table_columns url_partial_failures "id|url_status_id|error_type|error_message|observed_at_ms|run_id"
check_table_columns url_technologies "id|url_status_id|technology_name|technology_version|technology_category"
check_table_columns url_redirect_chain "id|url_status_id|sequence_order|redirect_url"
check_table_columns url_nameservers "id|url_status_id|nameserver"
check_table_columns url_txt_records "id|url_status_id|record_type|record_value"
check_table_columns url_mx_records "id|url_status_id|priority|mail_exchange"
check_table_columns url_security_headers "id|url_status_id|header_name|header_value"
check_table_columns url_http_headers "id|url_status_id|header_name|header_value"
check_table_columns url_certificate_oids "id|url_status_id|oid"
check_table_columns url_certificate_sans "id|url_status_id|san_value"
check_table_columns url_geoip "id|url_status_id|country_code|country_name|region|city|latitude|longitude|postal_code|timezone|asn|asn_org"
check_table_columns url_whois "id|url_status_id|creation_date_ms|expiration_date_ms|updated_date_ms|registrar|registrant_country|registrant_org|whois_statuses|nameservers_json|raw_response"
check_table_columns url_structured_data "id|url_status_id|data_type|property_name|property_value"
check_table_columns url_social_media_links "id|url_status_id|platform|profile_url|identifier"
check_table_columns url_analytics_ids "id|url_status_id|provider|tracking_id"
check_table_columns url_security_warnings "id|url_status_id|warning_code|warning_description"
check_table_columns url_failure_redirect_chain "id|url_failure_id|sequence_order|redirect_url"
check_table_columns url_failure_response_headers "id|url_failure_id|header_name|header_value"
check_table_columns url_failure_request_headers "id|url_failure_id|header_name|header_value"
check_table_columns url_favicons "id|url_status_id|favicon_url|hash|base64_data"
check_table_columns url_contact_links "id|url_status_id|contact_type|contact_value|raw_href"
check_table_columns url_exposed_secrets "id|url_status_id|secret_type|matched_value|severity|location|context"
echo "  All 25 tables and columns: OK"

# Runs row and run_id
RUN_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM runs;")
if [[ "${RUN_COUNT:-0}" -lt 1 ]]; then
  echo "FAIL: runs table has no row"
  exit 1
fi
RUN_ID=$(sqlite3 "$DB" "SELECT run_id FROM runs ORDER BY start_time_ms DESC LIMIT 1;")
echo "  Run ID: $RUN_ID"

# WHOIS: with --enable-whois we expect some url_whois rows (may be 0 if all lookups failed)
WHOIS_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM url_whois;")
echo "  url_whois rows: $WHOIS_COUNT (enabled with --enable-whois)"

# --- 4. Export functionality: csv, jsonl, parquet ---
echo "[4/5] Testing export (csv, jsonl, parquet)..."

URL_STATUS_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM url_status WHERE run_id='$RUN_ID';")

for fmt in csv jsonl parquet; do
  out="$EXPORT_DIR/out.$fmt"
  "$BIN" export --db-path "$DB" --format "$fmt" --run-id "$RUN_ID" --output "$out" 2>/dev/null
  if [[ ! -f "$out" ]]; then
    echo "FAIL: Export $fmt did not create $out"
    exit 1
  fi
  if [[ "$fmt" == "csv" ]]; then
    # CSV: header + N data rows
    lines=$(wc -l < "$out")
    if [[ "$lines" -lt 2 ]]; then
      echo "FAIL: CSV has too few lines (expected at least 2: header + data)"
      exit 1
    fi
    data_lines=$((lines - 1))
    if [[ $data_lines -ne "$URL_STATUS_COUNT" ]]; then
      echo "FAIL: CSV data row count $data_lines != url_status count $URL_STATUS_COUNT"
      exit 1
    fi
  elif [[ "$fmt" == "jsonl" ]]; then
    lines=$(wc -l < "$out")
    if [[ "$lines" -ne "$URL_STATUS_COUNT" ]]; then
      echo "FAIL: JSONL line count $lines != url_status count $URL_STATUS_COUNT"
      exit 1
    fi
  fi
  # Parquet: binary; just check file size and that export reported count
  if [[ "$fmt" == "parquet" ]]; then
    if [[ ! -s "$out" ]]; then
      echo "FAIL: Parquet file empty or missing"
      exit 1
    fi
  fi
  echo "  export --format $fmt: OK (rows: $URL_STATUS_COUNT)"
done

# Export with filter (smoke test)
"$BIN" export --db-path "$DB" --format csv --status 200 --output "$EXPORT_DIR/filtered.csv" 2>/dev/null
if [[ ! -f "$EXPORT_DIR/filtered.csv" ]]; then
  echo "FAIL: Filtered export did not create file"
  exit 1
fi
echo "  export with --status 200: OK"

# --- 5. Sanity: core data present ---
echo "[5/5] Sanity: core data..."
SUCCESS=$(sqlite3 "$DB" "SELECT successful_urls FROM runs WHERE run_id='$RUN_ID';")
FAILED=$(sqlite3 "$DB" "SELECT failed_urls FROM runs WHERE run_id='$RUN_ID';")
TOTAL=$(sqlite3 "$DB" "SELECT total_urls FROM runs WHERE run_id='$RUN_ID';")
echo "  runs.total_urls=$TOTAL, successful_urls=$SUCCESS, failed_urls=$FAILED"
if [[ "${TOTAL:-0}" -eq 0 ]]; then
  echo "FAIL: total_urls is 0"
  exit 1
fi

echo ""
echo "=== All checks passed ==="
