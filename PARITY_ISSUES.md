# Technology Detection Parity Issues

## Current Status
- **Match Rate**: 5.1% (2/39 domains)
- **Total Discrepancies**: 37/39 domains

## Key Patterns Identified

### 1. Implied Technologies Issue
**Problem**: We're detecting Next.js, React, Webpack, Node.js when wappalyzergo only detects Vercel.

**Examples**:
- `10xgenomics.com`: We detect `[Next.js,Node.js,React,Vercel,Webpack]`, wappalyzergo detects `[Vercel]`
- `aberdeeninvestments.com`: We detect `[Next.js,Node.js,React,Vercel,Webpack]`, wappalyzergo detects `[Vercel]`

**Root Cause**: Next.js implies React, Webpack, and Node.js. We're detecting Next.js (possibly via x-powered-by header) when wappalyzergo doesn't, or we're adding implied technologies incorrectly.

### 2. Missing Technologies
**Common missing technologies**:
- Google Analytics (frequently missing)
- Cloudflare (detected by wappalyzergo but not us)
- jQuery Migrate (detected by wappalyzergo but not us)
- WordPress plugins (Yoast SEO, Elementor, etc.)
- Version numbers (wappalyzergo includes versions like "jQuery:3.6.0", "WordPress:6.8.3")

### 3. Extra Technologies
**Common extra technologies**:
- Generic "jQuery" when wappalyzergo detects "jQuery:3.6.0" (version-specific)
- Generic "WordPress" when wappalyzergo detects "WordPress:6.8.3"
- Technologies we detect but wappalyzergo doesn't (e.g., 3m.com, 53.com, abercrombie.com)

### 4. Version Detection
**Problem**: wappalyzergo includes version numbers in technology names (e.g., "jQuery:3.6.0", "WordPress:6.8.3"), but we don't extract or include versions.

## Next Steps

1. **Investigate Next.js detection**: Why are we detecting Next.js when wappalyzergo doesn't?
2. **Fix implied technology logic**: Ensure we match wappalyzergo's behavior
3. **Add missing pattern matching**: Investigate why we're missing Google Analytics, Cloudflare, etc.
4. **Version extraction**: Implement version detection to match wappalyzergo's output format
5. **Pattern matching differences**: Verify regex and pattern matching works identically
