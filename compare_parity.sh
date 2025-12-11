#!/bin/bash
# Compare technology detection between domain_status and wappalyzergo

set -uo pipefail  # Remove -e to allow error handling

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if wappalyzergo comparison tool exists
COMPARE_TOOL="./compare_detection"
if [ ! -f "$COMPARE_TOOL" ]; then
    echo "Building wappalyzergo comparison tool..."
    go mod edit -replace github.com/projectdiscovery/wappalyzergo=./wappalyzergo 2>/dev/null || true
    go build -o compare_detection compare_detection.go
fi

# Check if domain_status is built
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found"
    exit 1
fi

# Sample size (first N domains)
SAMPLE_SIZE=${1:-20}
INPUT_FILE="url-list.txt"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found"
    exit 1
fi

echo "Comparing technology detection for first $SAMPLE_SIZE domains..."
echo ""

# Create temp file with sample domains
TEMP_INPUT=$(mktemp /tmp/domains_XXXXXX.txt)
head -n $SAMPLE_SIZE "$INPUT_FILE" > "$TEMP_INPUT"
trap "rm -f $TEMP_INPUT" EXIT

# Create temporary database for domain_status
TEMP_DB=$(mktemp /tmp/domain_status_compare_XXXXXX.db)
trap "rm -f $TEMP_DB $TEMP_INPUT" EXIT

# Run domain_status scan (quiet mode)
echo "Running domain_status scan..."
cargo run --release --quiet -- scan "$TEMP_INPUT" \
    --db-path "$TEMP_DB" \
    --log-level error \
    --max-concurrency 10 \
    --rate-limit-rps 10 \
    --timeout-seconds 15 \
    > /dev/null 2>&1 || true

# Show scan summary
TOTAL_SCANNED=$(sqlite3 "$TEMP_DB" "SELECT COUNT(*) FROM url_status;" 2>/dev/null || echo "0")
SUCCESSFUL=$(sqlite3 "$TEMP_DB" "SELECT COUNT(*) FROM url_status WHERE status BETWEEN 200 AND 299;" 2>/dev/null || echo "0")
echo "Scan complete: $SUCCESSFUL successful out of $TOTAL_SCANNED total"

# Extract results from database
echo "Extracting domain_status results..."
sqlite3 "$TEMP_DB" <<EOF > /tmp/domain_status_results.txt
.mode tabs
SELECT
    us.final_domain,
    COALESCE(GROUP_CONCAT(ut.technology_name, ','), '')
FROM url_status us
LEFT JOIN url_technologies ut ON us.id = ut.url_status_id
WHERE us.status BETWEEN 200 AND 299
GROUP BY us.final_domain
ORDER BY us.final_domain;
EOF

# Compare results
echo ""
echo "=== COMPARISON RESULTS ==="
echo ""

DISCREPANCIES=0
MATCHES=0
TOTAL=0

# Count total domains first
TOTAL_DOMAINS=$(wc -l < /tmp/domain_status_results.txt | tr -d ' ')
echo "Comparing $TOTAL_DOMAINS domains..."

while IFS=$'\t' read -r DOMAIN DOMAIN_STATUS_TECHS; do
    # Skip empty lines
    [ -z "${DOMAIN:-}" ] && continue

    TOTAL=$((TOTAL + 1))

    # Normalize domain_status technologies
    if [ -n "$DOMAIN_STATUS_TECHS" ]; then
        DOMAIN_STATUS_TECHS=$(echo "$DOMAIN_STATUS_TECHS" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -v '^$' | sort | tr '\n' ',' | sed 's/,$//')
    fi
    [ -z "$DOMAIN_STATUS_TECHS" ] && DOMAIN_STATUS_TECHS=""

    # Run wappalyzergo on the domain
    TEST_URL="https://$DOMAIN"
    WAPPALYZER_OUTPUT="[]"
    WAPPALYZER_TECHS=""

    # Try to get wappalyzergo results, but don't fail if it errors
    if WAPPALYZER_OUTPUT_RAW=$(./compare_detection "$TEST_URL" 2>/dev/null); then
        WAPPALYZER_OUTPUT="$WAPPALYZER_OUTPUT_RAW"
    fi

    # Parse JSON output
    if [ -n "$WAPPALYZER_OUTPUT" ] && [ "$WAPPALYZER_OUTPUT" != "[]" ]; then
        WAPPALYZER_TECHS=$(echo "$WAPPALYZER_OUTPUT" | jq -r '.[]' 2>/dev/null | sort | tr '\n' ',' | sed 's/,$//' || echo "")
    fi

    # Normalize empty
    [ -z "$WAPPALYZER_TECHS" ] && WAPPALYZER_TECHS=""

    # Normalize empty results - ensure both are truly empty strings
    [ -z "$DOMAIN_STATUS_TECHS" ] && DOMAIN_STATUS_TECHS=""
    [ -z "$WAPPALYZER_TECHS" ] && WAPPALYZER_TECHS=""

    # Compare (handle both empty as match)
    if [ "$DOMAIN_STATUS_TECHS" = "$WAPPALYZER_TECHS" ]; then
        MATCHES=$((MATCHES + 1))
        if [ -n "$DOMAIN_STATUS_TECHS" ]; then
            echo -e "${GREEN}✓${NC} $DOMAIN: MATCH (${DOMAIN_STATUS_TECHS})"
        else
            echo -e "${YELLOW}○${NC} $DOMAIN: MATCH (no technologies detected)"
        fi
    else
        DISCREPANCIES=$((DISCREPANCIES + 1))
        echo -e "${RED}✗${NC} $DOMAIN: MISMATCH"
        echo "  domain_status: [$DOMAIN_STATUS_TECHS]"
        echo "  wappalyzergo:  [$WAPPALYZER_TECHS]"

        # Show differences
        if [ -n "$DOMAIN_STATUS_TECHS" ] || [ -n "$WAPPALYZER_TECHS" ]; then
            DS_LIST=$(echo "$DOMAIN_STATUS_TECHS" | tr ',' '\n' | sort)
            WA_LIST=$(echo "$WAPPALYZER_TECHS" | tr ',' '\n' | sort)

            MISSING=$(comm -23 <(echo "$WA_LIST") <(echo "$DS_LIST") | grep -v '^$')
            EXTRA=$(comm -13 <(echo "$WA_LIST") <(echo "$DS_LIST") | grep -v '^$')

            if [ -n "$MISSING" ]; then
                echo -e "  ${RED}Missing in domain_status:${NC}"
                echo "$MISSING" | sed 's/^/    - /'
            fi
            if [ -n "$EXTRA" ]; then
                echo -e "  ${YELLOW}Extra in domain_status:${NC}"
                echo "$EXTRA" | sed 's/^/    + /'
            fi
        fi
        echo ""
    fi

    # Small delay to avoid rate limiting (but not on every domain to speed up)
    if [ $((TOTAL % 5)) -eq 0 ]; then
        sleep 0.5
        echo -e "${BLUE}Progress: $TOTAL/$TOTAL_DOMAINS domains compared...${NC}" >&2
    else
        sleep 0.1
    fi
done < /tmp/domain_status_results.txt

echo ""
echo "=== SUMMARY ==="
echo "Total domains compared: $TOTAL"
echo -e "${GREEN}Matches: $MATCHES${NC}"
echo -e "${RED}Discrepancies: $DISCREPANCIES${NC}"
if [ $TOTAL -gt 0 ]; then
    MATCH_RATE=$(echo "scale=1; $MATCHES * 100 / $TOTAL" | bc)
    echo "Match rate: ${MATCH_RATE}%"

    if (( $(echo "$MATCH_RATE < 80" | bc -l) )); then
        echo -e "${RED}WARNING: Match rate is below 80% - significant discrepancies detected!${NC}"
        exit 1
    fi
fi
