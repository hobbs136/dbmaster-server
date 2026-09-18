# Contributing to DbMaster Server

Thanks for your interest in improving DbMaster Server. This guide is intentionally short.

## Environment

- **Rust stable** (`rustup install stable`) — that's it. The dependency tree is pure Rust (no OpenSSL / pkg-config / native libraries), so Windows, macOS, and Linux all work out of the box.
- Docker is optional, for containerized runs only.

## Verification ladder (required for every change)

Run the ladder top-down; don't move to the next level until the current one is clean:

```bash
cargo clippy                      # 1. no new warnings
cargo test -p <crate>             # 2. tests of every crate you touched,
                                  #    e.g. cargo test -p dbmaster-gateway
cargo test                        # 3. full workspace regression
```

## End-to-end tests (optional, real databases)

The default `cargo test` suite is fully offline. Some e2e tests additionally hit **real databases** and are gated behind environment variables (`DS_E2E_*`, `GW_E2E_*`, `NC_E2E_*`, `QS_E2E_*`, and script-level variables) — the complete list with URL formats and per-suite run commands lives in [.env.example](.env.example).

- Bring your **own test databases**; the repository carries no real deployment addresses or credentials, and none should ever be committed.
- Unset variables are not an error: the corresponding tests print `SKIP: <VAR> not set` and pass, so the suite stays green offline.

## Submitting

- Please open or comment on a **GitHub Issue** first for anything beyond small fixes, so we can align on scope before you invest time.
- By submitting a pull request, you agree that your contribution is licensed under the repository's license (**AGPL-3.0-only**, see [LICENSE](LICENSE)). There is no CLA or DO to sign — your PR statement is enough.
- Security issues do **not** go through issues or PRs — see [SECURITY.md](SECURITY.md).
