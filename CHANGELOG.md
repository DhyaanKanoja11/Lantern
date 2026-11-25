# Changelog

All notable changes to Lantern are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.4.0] - 2026-11-26

### Added
- **Native Shell Auto-Completion (`lantern completion`)**: Added shell completion generator supporting `bash`, `zsh`, `fish`, and `powershell` with hermetic unit tests.
- **Compose Override File Auto-Merging (`lantern preflight`)**: Added automatic discovery and merge of sibling Compose override files (`docker-compose.override.yml`, `compose.override.yml`), support for multiple file path arguments, and accurate collision source attribution.
- **Official GitHub Marketplace Composite Action (`action.yml`)**: Added reusable GitHub Action enabling 1-step Compose preflight checks and wildcard security audits in CI workflows.
- **Enhanced Reachability Explanation Diagnostics**: Improved socket attribution and causal explanation lineage in `lantern why`.

---

## [v0.3.0] - 2026-11-25

### Added
- **Native Model Context Protocol (MCP) Server**: Added `lantern mcp` stdio command implementing the JSON-RPC 2.0 / MCP stdio protocol standard. Allows autonomous AI coding agents (Claude Code, Cursor, Windsurf, Claude Desktop) to natively invoke `lantern_scan`, `lantern_why`, `lantern_free`, and `lantern_doctor`.
- **Smithery Registry Support**: Added `smithery.yaml` configuration for 1-click MCP server indexing and deployment via `@smithery/cli`.
- **Context-Aware Port Reclaiming (`lantern free` / `lantern kill`)**: Safe port reclaimer that checks if an occupied port is published by a Docker container and cleanly stops it via Docker Engine API before falling back to native host process termination.
- **Cross-Platform Native Socket Discovery (macOS & Windows)**: Added zero-dependency native socket and process discovery for Windows (`netstat -ano` + `tasklist` CSV parsing) and macOS (`lsof -iTCP -sTCP:LISTEN` + `ps` attribution).
- **Environment Diagnostics Upgrade (`lantern doctor`)**: Upgraded doctor probes to dynamically validate platform-native socket inspection utilities across Linux (`ss`), macOS (`lsof`), and Windows (`netstat`).

---

## [v0.2.3] - 2026-11-24

### Added
- **Automated Remediation Diff Patch Generator**: Added `--diff` flag to `lantern fix <port>` to generate standard unified Git diffs with 3 lines of surrounding context. Output is piped cleanly to stdout for direct consumption by `git apply` in CI workflows, enabling automated fix pull request generation.
- **Fail-Closed Patch Protection**: Blocks diff generation for non-existent sockets or unsupported exposure types with non-zero exit codes, ensuring CI automation never creates malformed or empty patches.

---

## [v0.2.2] - 2026-11-24

### Added
- **OASIS SARIF v2.1.0 Engine**: Added native `--format sarif` to `lantern scan` and `lantern why` for automated ingestion into GitHub's native Security → Code scanning alerts tab (`ruleId: LANTERN001`).
- **Structured JSON Engine**: Added `--format json` and `--json` flag alias across `lantern scan` and `lantern why <port>` for automated CI and script parsing.
- **Live Terminal Watch Mode**: Added `-w, --watch` and `--interval <duration>` to `lantern scan` for real-time ANSI dashboard monitoring with live `[ALERT]` banners on wildcard exposure.
- **Team Policy Engine**: Added `internal/policy` package auto-discovering `.lantern.yaml` / `.lantern.yml` configuration files with CLI flag override merging.
- **CI Security Guardrails**: Added `--fail-on-wildcard` and `--ignore-ports` flags with native GitHub Actions inline annotations (`::error::`).
- **Rich GitHub Step Summaries**: Generates formatted Markdown audit tables into `$GITHUB_STEP_SUMMARY` during GitHub Actions CI runs.
- **Pre-Commit Hook Definition**: Added `.pre-commit-hooks.yaml` (`id: lantern-scan`) for local git commit validation.
- **Automated Packaging Synchronizer**: Added `scripts/sync_packaging.py` and GitHub Actions hook to automatically sync Homebrew formula and Scoop bucket manifests on release.

### Changed
- Migrated canonical Go module path to `github.com/DhyaanKanoja11/Lantern`.
- Updated documentation with GitHub Marketplace integration and architectural deep dive link.

---

## [v0.2.1] - 2026-11-21

### Added
- **Package Manager Manifests**: Dedicated distribution manifests for Homebrew (`packaging/homebrew/lantern.rb`), Scoop (`packaging/scoop/lantern.json`), WinGet (`packaging/winget/DhyaanKanoja11.Lantern.yaml`), and Arch Linux AUR (`packaging/aur/PKGBUILD`, `packaging/aur/.SRCINFO`).
- **Debian & RPM Packaging**: Integrated NFPMs packaging into GoReleaser generating native `.deb` and `.rpm` packages for `amd64` and `arm64`.
- **External Tester Programme**: Documented 6-step testing workflow in `docs/TESTER_PROGRAMME.md` and added structured GitHub issue template `.github/ISSUE_TEMPLATE/tester_feedback.md`.
- **Shell Profile Detection**: Enhanced `install.sh` with automatic user shell detection (`zsh`, `bash`, `fish`) and exact copy-pasteable PATH persistence instructions.
- **Docker Daemon Health Diagnostics**: Added `CheckDaemon` with typed sentinel errors (`ErrDaemonStopped`, `ErrDockerSocketMissing`, `ErrDockerPermissionDenied`).
- **Unattributed Docker Attribution Notice**: Gracefully degrades to `Docker (unattributed)` with clear explanatory notices when Docker daemon is unreachable.

### Fixed
- **Bare `lantern why` Guidance**: Displays actionable usage guidance (`Port required. Run 'lantern scan' to see active listening ports, then run 'lantern why <port>'`) instead of an unhelpful error.
- **Fail-Closed Remediation Non-Modification Assertion**: Added explicit regression assertion confirming files remain unmodified after rejected `Apply` attempts.
- **Installer CRLF Line-Ending Protection**: Added `.gitattributes` to enforce LF endings across shell scripts and Go sources.

### Changed
- Reorganized `README.md` into tiered installation architecture (Package Managers, Universal Installer, Pre-Built Archives, Source).
- Updated internal version constants and default fallbacks to `v0.2.1`.

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
