# Parity Analysis Findings

## Fingerprint Sources

Both `domain_status` and `wappalyzergo` use the **same fingerprint sources**:
1. `https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies`
2. `https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies`

Both have **7223 technologies** with identical names (no differences).

## Key Differences Found

### 1. Pattern Normalization ✅ FIXED
- **wappalyzergo**: Normalizes `scriptSrc`, `HTML`, and `Script` patterns to lowercase during update (in `update-fingerprints/main.go`)
- **domain_status**: Was loading patterns as-is, now normalizes them during loading
- **Impact**: Match rate improved from 37.6% to 43.5%

### 2. Fingerprint Version Difference ⚠️ POTENTIAL ISSUE
- **wappalyzergo**: Uses embedded `fingerprints_data.json` (static, specific version generated at a point in time)
- **domain_status**: Fetches latest from GitHub (dynamic, may have newer patterns)
- **Impact**: Could explain remaining discrepancies if GitHub has newer/different patterns than wappalyzergo's embedded version

### 3. HTML Pattern Matching ✅ FIXED
- **wappalyzergo**: Matches HTML patterns against entire normalized body (`bytes.ToLower(body)`)
- **domain_status**: Was matching against extracted text, now matches against full normalized body
- **Impact**: Match rate improved from 20% to 37.6%

## Current Status

- **Match Rate**: 43.5% (17/39 domains)
- **Remaining Issues**: 22 discrepancies
- **Next Steps**: Consider using wappalyzergo's `fingerprints_data.json` directly to ensure exact same fingerprints
