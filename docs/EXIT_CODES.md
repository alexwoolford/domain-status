# Exit Code Reference

`domain_status` produces two kinds of non-zero exits:

- command/runtime failures, which return `1`
- policy failures from `evaluate_exit_code()`, which return `2` or `3`

The policy-based codes apply to the `scan` subcommand only.

## Exit Codes

| Code | Meaning | When it happens |
|------|---------|-----------------|
| `0` | Success | The command completed successfully, or scan failures were ignored by `--fail-on never` |
| `1` | Command/runtime error | CLI parsing failed, configuration was invalid, initialization failed, or the command returned an error before policy evaluation |
| `2` | Failure policy exceeded | `--fail-on any-failure` saw at least one failed URL, or `--fail-on pct>` saw a failure rate greater than `--fail-on-pct-threshold` |
| `3` | Percentage policy could not be evaluated | `--fail-on pct>` was selected, but `report.total_urls == 0` |

## `--fail-on` Semantics

The accepted values are:

- `never`
- `any-failure`
- `pct>`

`pct>` does not embed the numeric threshold in the enum value. The percentage comes from the separate `--fail-on-pct-threshold` flag.

Examples:

```bash
# Always exit 0 after a successful scan command, even if some URLs failed
domain_status scan urls.txt --fail-on never

# Exit 2 if any URL failed
domain_status scan urls.txt --fail-on any-failure

# Exit 2 if failures are greater than 10%
domain_status scan urls.txt --fail-on pct> --fail-on-pct-threshold 10
```

## Decision Rules

### `never`

- Returns `0`
- Ignores `report.failed`

### `any-failure`

- Returns `2` when `report.failed > 0`
- Returns `0` otherwise

### `pct>`

- Returns `3` when `report.total_urls == 0`
- Otherwise computes `(report.failed / report.total_urls) * 100`
- Returns `2` when that percentage is strictly greater than `--fail-on-pct-threshold`
- Returns `0` otherwise

The comparison is strictly greater-than, not greater-than-or-equal.

## Concrete Examples

```bash
# One failed URL is enough to fail the scan
domain_status scan urls.txt --fail-on any-failure
echo $?  # 0 or 2

# Allow up to 10% failures
domain_status scan urls.txt --fail-on pct> --fail-on-pct-threshold 10
echo $?  # 0, 2, or 3

# Invalid input file or another command-level error
domain_status scan missing.txt
echo $?  # 1
```

## Notes

- The `export` subcommand returns `0` on success and `1` on failure.
- `main.rs` maps any error returned by the library CLI runner to exit code `1`.
- For the exact implementation, see `src/cli.rs` and `evaluate_exit_code()`.
