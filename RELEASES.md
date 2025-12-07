# Release Process

This document describes the release process for `domain_status`.

## Versioning

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backwards compatible manner
- **PATCH** version for backwards compatible bug fixes

## Release Checklist

Before creating a release:

- [ ] All tests pass (`cargo test --all-features --all-targets`)
- [ ] Clippy passes with no warnings (`cargo clippy --all-targets --all-features -- -D warnings`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] Security audit passes (`cargo audit`)
- [ ] CHANGELOG.md is updated with all changes
- [ ] Version in `Cargo.toml` matches the release version
- [ ] README.md is up to date

## Creating a Release

### 1. Update Version and Changelog

```bash
# Update version in Cargo.toml
# Update CHANGELOG.md with release notes
# Commit changes
git add Cargo.toml CHANGELOG.md
git commit -m "Prepare release v0.1.0"
```

### 2. Create and Push Tag

```bash
# Create annotated tag
git tag -a v0.1.0 -m "Release v0.1.0"

# Push tag (this triggers the release workflow)
git push origin v0.1.0
```

### 3. GitHub Actions Will Automatically

- Build binaries for all platforms (Linux, macOS Intel, macOS ARM, Windows)
- Create a GitHub release with the binaries attached
- Generate release notes from CHANGELOG.md

### 4. Verify Release

- Check [GitHub Releases](https://github.com/alexwoolford/domain_status/releases)
- Verify all platform binaries are present
- Test downloading and running a binary

## Manual Release (If Needed)

If the automated workflow fails, you can create a release manually:

1. Go to [GitHub Releases](https://github.com/alexwoolford/domain_status/releases)
2. Click "Draft a new release"
3. Choose the tag (or create a new one)
4. Fill in release title and description (copy from CHANGELOG.md)
5. Attach pre-built binaries if available
6. Publish release

## Building Binaries Locally

To build binaries for all platforms locally (requires cross-compilation setup):

```bash
# Install cross-compilation targets
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
rustup target add x86_64-pc-windows-msvc

# Build for each platform
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-pc-windows-msvc
```

Note: Cross-compilation from macOS to Linux requires additional setup. The GitHub Actions workflow handles this automatically.

## macOS Code Signing and Notarization (Future)

Currently, macOS binaries are unsigned, which triggers Gatekeeper warnings. To eliminate these warnings:

1. **Requires Apple Developer Account** ($99/year)
2. **Code Sign the Binary**:
   ```bash
   codesign --force --deep --sign "Developer ID Application: Your Name" domain_status
   ```
3. **Notarize with Apple**:
   ```bash
   xcrun notarytool submit domain_status --keychain-profile "AC_PASSWORD" --wait
   ```
4. **Staple the Ticket**:
   ```bash
   xcrun stapler staple domain_status
   ```

**Current Workaround**: Users can bypass Gatekeeper by:
- Right-clicking → Open (first time only)
- Or running: `xattr -d com.apple.quarantine domain_status`

**Note**: For open-source projects, code signing is optional but improves user experience. Many projects skip it due to the cost and complexity.

## Future: Publishing to crates.io

When ready to publish to crates.io:

1. Ensure `Cargo.toml` has all required metadata:
   - `name`, `version`, `description`, `license`, `authors`
   - `repository`, `homepage`, `documentation` (optional but recommended)
   - `keywords`, `categories` (optional but helpful)

2. Run checks:
   ```bash
   cargo publish --dry-run
   ```

3. Publish:
   ```bash
   cargo publish
   ```

4. Update README.md with installation instructions:
   ```bash
   cargo install domain_status
   ```
