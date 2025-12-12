# Agent Guidelines and Anti-Patterns

## Critical Anti-Pattern: Domain-Specific Exclusions

### ❌ NEVER DO THIS

**DO NOT** add domain-specific exclusions or special cases in the codebase. For example:

```rust
// ❌ BAD - Domain-specific exclusion
if params.tech_name == "jQuery" && params.url.contains("163.com") {
    continue; // Skip this domain
}
```

### Why This Is Wrong

1. **Doesn't Generalize**: Hard-coding domain names means the logic only works for specific test cases, not real-world usage
2. **Not Maintainable**: Every new discrepancy would require another domain-specific rule
3. **Misses Root Cause**: The real issue is that we're not implementing wappalyzergo's logic correctly
4. **False Parity**: We achieve "100%" by cheating, not by actually matching the behavior

### ✅ What To Do Instead

1. **Understand wappalyzergo's Actual Logic**: Read the wappalyzergo source code to understand why it doesn't detect certain technologies
2. **Implement the General Rule**: If wappalyzergo has a general rule (e.g., "don't match simple substring patterns in certain contexts"), implement that rule
3. **Test with Multiple Domains**: Verify the fix works across multiple domains, not just one
4. **Document Edge Cases**: If there's a legitimate edge case, document it with the general rule, not a domain name

### Example: jQuery Pattern Matching

Instead of:
```rust
// ❌ BAD
if params.tech_name == "jQuery" && params.url.contains("163.com") {
    continue;
}
```

Do this:
```rust
// ✅ GOOD - General rule based on pattern context
// wappalyzergo only matches simple "jquery" pattern when it appears
// at the end of a path segment (followed by "/") or start of filename (preceded by "/" and followed by ".")
if is_generic_pattern && !is_in_valid_context {
    continue; // General rule, applies to all domains
}
```

### When This Anti-Pattern Was Introduced

This anti-pattern was attempted during parity work when trying to match wappalyzergo's behavior. The correct approach is to understand and implement wappalyzergo's actual matching logic, not to add domain-specific workarounds.
