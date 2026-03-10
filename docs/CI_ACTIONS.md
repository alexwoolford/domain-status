# GitHub Actions: Pinned Versions

All workflows pin actions by **full commit SHA** for supply-chain reproducibility (see [SUPPLY_CHAIN_POSTURE.md](SUPPLY_CHAIN_POSTURE.md)). This file maps each action to its SHA so you can read workflows without decoding hashes.

When upgrading an action: update the SHA in the workflow(s) and in this table. Prefer a tagged release commit from the action’s repo.

| Action | SHA (full) | Used in |
|--------|------------|---------|
| `actions/checkout` | `34e114876b0b11c390a56381ad16ebd13914f8d5` | ci.yml, release.yml |
| `dtolnay/rust-toolchain` | `efa25f7f19611383d5b0ccf2d1c8914531636bf9` | ci.yml, release.yml |
| `Swatinem/rust-cache` | `v2` | ci.yml, release.yml |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | release.yml |
| `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | release.yml |
| `softprops/action-gh-release` | `de2c0eb89ae2a093876385947365aca7b0e5f844` | release.yml |
| `codecov/codecov-action` | `0561704f0f02c16a585d4c7555e57fa2e44cf909` | ci.yml |
| `gitleaks/gitleaks-action` | `ff98106e4c7b2bc287b24eaf42907196329070c7` | ci.yml |
