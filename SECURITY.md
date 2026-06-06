# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security issue in AnalysisLoom, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email **security@ysf.studio** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment (if known)
   - Suggested fix (optional)

We aim to acknowledge reports within **72 hours** and provide a remediation plan within **14 days** for confirmed issues.

## Security Model

AnalysisLoom is designed as a **100% offline** forensic workstation:

- No telemetry, analytics, or external network calls during normal operation
- Evidence processing runs locally via the Tauri/Rust backend
- Case data is stored in a local SQLite database under the user's home directory
- File access is mediated through Tauri IPC commands, not arbitrary frontend filesystem APIs

## Dependency Management

- Rust dependencies are audited via `cargo audit` in CI
- npm dependencies are audited via `npm audit` in CI
- Dependabot opens weekly update PRs for Cargo, npm, and GitHub Actions

## Secure Development

Contributors should:

- Never commit secrets, API keys, or case evidence files
- Run `cargo clippy` and `cargo fmt --check` before pushing
- Keep Tauri capabilities scoped to minimum required paths
