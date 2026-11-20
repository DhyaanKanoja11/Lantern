# Changelog

All notable changes to Lantern are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.2.0] - 2026-11-20

### Added
- **Native Linux Docker Attribution Fallback**: Enables correlation of unprivileged Linux listeners (PID 0 / uninspected root docker-proxy sockets) using Docker published port metadata with strict canonical IP, wildcard family, and container running state validation.
- **Attribution Confidence Classification**: Explicitly distinguishes `DIRECT` socket ownership verification from `INFERRED` published port attribution across explanation, exposure paths, and scan summaries.
- **Fail-Closed Tentative Remediation**: Added `RemediationTentative` status. Inferred container attribution permits strictly read-only dry-run diff previews (`lantern fix <port> --dry-run`) while blocking live modifications until direct socket ownership is verified.
- **Doctor Privilege Diagnostic**: `lantern doctor` inspects process EUID on Linux, reporting when unprivileged execution will rely on Docker metadata fallback and advising when root/sudo is appropriate for direct process attribution.
- **Release Automation**: Added GoReleaser configuration (`.goreleaser.yaml`) and GitHub Actions release workflow (`.github/workflows/release.yml`) for automated multi-architecture release packaging on version tags.
- **POSIX Installation Script**: Added `install.sh` for one-liner installation, version resolution, SHA-256 checksum verification, PATH detection, and uninstallation on Linux and macOS.
- **Build Metadata Injection**: Injected dynamic `Version`, `Commit`, and `Date` variables via `-ldflags` into binary outputs.
- **Pull Request Template**: Added `.github/pull_request_template.md` standardizing testing, security, and documentation checklists.
- **Reproducible Demonstration**: Added `scripts/demo.sh` for automated, reproducible terminal demonstrations against the example Docker Compose environment.

### Changed
- Case-insensitive process name comparisons (`strings.EqualFold`) for `docker-proxy` and `unknown` process names.
- Expanded test coverage across Docker client, doctor checks, explanation engine, and remediation pipeline.

---

## [v0.1.2] - 2026-10-16

### Fixed
- Aligned runtime version reporting in `internal/cli/version.go` with git release tags.
- Corrected Quick Start documentation in `README.md` to include `export PATH="$(go env GOPATH)/bin:$PATH"`.
- Aligned documentation output blocks with actual CLI text formatting.

### Added
- Minimal GitHub Actions continuous integration workflow (`.github/workflows/ci.yml`) matrix-testing across Go 1.22 and Go 1.23.

---

## [v0.1.1] - 2026-10-06

### Fixed
- Fixed runtime version alignment in CLI commands.
- Standardized documentation references and public repository URLs.

---

## [v0.1.0] - 2026-10-03

### Added
- Initial public release of Lantern.
- Core commands:
  - `lantern scan`: Tabular discovery of local TCP listening sockets with reachability classification.
  - `lantern why <port>`: Five-section exposure explanation tracing configuration causality from network interfaces back to Docker Compose lines.
  - `lantern fix <port> [--dry-run]`: Safe, deterministic remediation for Docker Compose wildcard bindings.
  - `lantern doctor`: Diagnostic environment probes checking OS, `ss`, `/proc`, Docker CLI/daemon, interfaces, and listener collector.
  - `lantern version`: Semantic version output.
- 10-layer fail-closed remediation safety pipeline featuring cryptographic TOCTOU SHA-256 fingerprinting, byte-verified backups, YAML AST-guided precision line replacement, and post-fix on-disk verification.
- Local-first architecture with zero external network telemetry, zero background daemons, and hermetic unit testing.
