# Lantern Architecture

This document describes the architectural principles, layering, package boundaries, data flows, and safety guarantees of Lantern v0.1.

---

## 1. Core Architectural Principles

1. **Domain Purity**: Domain entities and explanation logic remain completely independent of operating-system syscalls, third-party libraries, network sockets, or Docker clients.
2. **Causal Explanation over Port Scanning**: Lantern answers *why* a service is reachable, identifying the source-line declaration that caused the host exposure.
3. **Platform Isolation via Build Tags**: Platform-specific collection logic (e.g. Linux `/proc/net/tcp` parsing) is strictly isolated using Go build tags (`//go:build linux` and `//go:build !linux`).
4. **Hermetic Testability via Dependency Injection**: All higher-level use cases accept interfaces, enabling 100% deterministic unit testing without requiring root permissions, active network interfaces, or live Docker daemons.
5. **Fail-Closed Safety**: In the automated remediation engine, any uncertainty, ambiguity, file modification, or verification mismatch immediately halts the operation without touching original files.

---

## 2. Layered Architecture

Lantern follows a strict directional dependency model:

```text
               CLI Layer (internal/cli)
                          ↓
         Application Use Cases (internal/exposure)
                          ↓
               Domain (internal/domain)
                          ↓
     Explanation & Remediation (internal/explain, internal/remediation)
                          ↓
 Infrastructure & Collectors (internal/collector, process, docker, compose, network)
```

No lower layer ever imports from a higher layer. The domain holds pure data types and has zero imports outside the Go standard library.

---

## 3. Package Responsibilities

### `cmd/lantern`
- **Entry point**: Contains `main.go`. Minimal bootstrap that invokes `cli.Execute()`.

### `internal/cli`
- **Responsibilities**: CLI flag parsing, argument validation, exit code handling, and terminal output coordination via Cobra.
- **Invariants**: Contains zero YAML parsing, direct socket reading, or `/proc` walking. Delegates analysis to `internal/exposure` and formatting to `internal/output`.
- **Commands**:
  - `lantern scan`
  - `lantern why <port>`
  - `lantern doctor`
  - `lantern version`
  - `lantern fix <port> [--dry-run]`

### `internal/domain`
- **Responsibilities**: Defines the foundational data models and aggregates:
  - `Listener`: TCP socket address, port, protocol, PID, inode.
  - `Process`: PID, name, command line, executable path.
  - `Container`: Container ID, name, image, host PID, port mappings.
  - `ConfigEvidence`: File path, line number, service name, raw evidence.
  - `Reachability`: Local, LAN, Internet, State classification.
  - `Exposure`: Aggregate root linking listener, process, container, config, reachability, recommendation.
  - `ExposureSummary`: Tabular scan entry.
  - `Recommendation`: Remediation guidance (`bind_localhost`).
  - `Remediation` & `FileFingerprint`: Remediation plan with SHA-256 fingerprint.
  - `FixResult`: Outcome of an applied remediation.
- **Invariants**: Zero external dependencies.

### `internal/exposure`
- **Responsibilities**: Application orchestration layer. Implements `exposure.Analyzer`.
- **Flow**: Coordinates `collector`, `process`, `docker`, `compose`, `network`, and `explain` to construct complete `domain.Exposure` and `domain.ExposureSummary` instances.
- **Interface**: Provides `NewAnalyzerWithDeps` for hermetic dependency injection in tests.

### `internal/explain`
- **Responsibilities**: Core explanation engine. Implements `ClassifyRootCause`, `Explain`, and `FormatPath`.
- **Precedence Rules**:
  1. Docker Compose published port (with strict multi-constraint validation).
  2. Docker published port (without Compose configuration).
  3. Native process socket binding (wildcard, specific interface, or loopback).
  4. Unresolved evidence (insufficient data).
- **Invariants**: Pure mathematical classification; never touches disk or network.

### `internal/collector`
- **Responsibilities**: TCP listening socket discovery.
- **Platform Separation**:
  - `collector_linux.go` (`//go:build linux`): Uses `ss` utility with fallback to `/proc/net/tcp` and `/proc/net/tcp6`.
  - `collector_other.go` (`//go:build !linux`): Graceful stub returning a clean platform error explaining Linux/WSL2 requirement.

### `internal/process`
- **Responsibilities**: Process attribution.
- **Platform Separation**:
  - `inspector_linux.go` (`//go:build linux`): Correlates socket inodes with PIDs by scanning `/proc/[pid]/fd/` and reads `/proc/[pid]/comm`, `/proc/[pid]/cmdline`, and `/proc/[pid]/stat`.
  - `inspector_other.go` (`//go:build !linux`): Graceful fallback.

### `internal/docker`
- **Responsibilities**: Docker container correlation.
- **Mechanism**: Calls `docker inspect` via exec or uses the Docker daemon client to correlate host published ports and PIDs with container IDs, names, images, and port mappings.

### `internal/compose`
- **Responsibilities**: Docker Compose configuration discovery and AST parsing.
- **Discovery**: Searches container labels (`com.docker.compose.project.config_files`, `com.docker.compose.project.working_dir`), current working directory, and parent directories for `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml`.
- **Parser**: Uses `gopkg.in/yaml.v3` `yaml.Node` to parse YAML ASTs, capturing 1-indexed source line numbers for `ports:` declarations.

### `internal/network`
- **Responsibilities**: Host network interface enumeration and reachability classification.
- **Classification**:
  - `LOOPBACK`: `127.0.0.0/8`, `::1`.
  - `LAN`: RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC4193 (`fc00::/7`), Link-Local (`fe80::/10`).
  - `VPN`: Interfaces matching `tun`, `tap`, `wg`, `utun`, `tailscale`.
  - `OTHER`: Public or unclassified IP addresses.

### `internal/output`
- **Responsibilities**: Terminal text rendering.
- **Invariants**: Strictly converts domain objects (`Exposure`, `ExposureSummary`) into human-readable text and tabwriter tables. Performs zero causal inference.

### `internal/remediation`
- **Responsibilities**: Automated, safe remediation for supported exposures (`lantern fix`).
- **Components**:
  - `planner.go`: Evaluates exposure and creates a `domain.Remediation` plan with a SHA-256 `FileFingerprint`.
  - `fingerprint.go`: Computes and verifies cryptographic file fingerprints for TOCTOU protection.
  - `backup.go`: Creates sequenced, byte-verified backups (`.lantern.bak`, `.lantern.bak.<N>`).
  - `editor.go`: AST-guided line replacement targeting the exact YAML node while preserving comments, formatting, and unrelated services.
  - `atomic.go`: Atomic file replacement via temporary file and rename.
  - `remediator.go`: End-to-end remediation pipeline with post-fix on-disk verification.

---

## 4. End-to-End Data Flow

```text
[TCP Socket]
     ↓
ListenerCollector (ss / /proc/net/tcp)
     ↓ domain.Listener
ProcessInspector (/proc/<pid>/)
     ↓ domain.Process
DockerCorrelator (docker inspect)
     ↓ domain.Container + domain.PortMapping
ComposeResolver (AST search on docker-compose.yml)
     ↓ domain.ConfigEvidence
InterfaceClassifier (net.Interfaces())
     ↓ domain.Reachability
Explainer (ClassifyRootCause)
     ↓ domain.Explanation (ROOT CAUSE / LIKELY SOURCE)
Recommendation (GenerateRecommendation)
     ↓ domain.Exposure
TextFormatter (RenderWhy)
     ↓
Terminal Output
```

---

## 5. Remediation Safety Pipeline

The `lantern fix` remediation workflow follows a strict 10-stage fail-closed sequence:

```text
1. Exposure Analysis (analyzer.Why)
       ↓
2. Deterministic Plan Creation + SHA-256 Fingerprint Capture (planner.Plan)
       ↓
3. Interactive Confirmation Prompt ([y/N] - default No)
       ↓
4. Pre-Modification Fingerprint Re-Verification (TOCTOU check)
   (If file was edited, replaced, or deleted -> ABORT immediately; zero writes)
       ↓
5. Sequenced Byte-Verified Backup (<file>.lantern.bak)
   (Existing backups are never overwritten; byte equality verified before proceeding)
       ↓
6. AST-Guided YAML Modification in Memory
   (Targets exact service and line; preserves sibling services and comments)
       ↓
7. AST Invariant Verification
   (Verifies YAML syntax validity and re-parses Compose structure before writing)
       ↓
8. Atomic File Replacement (Write temp file -> sync -> close -> rename)
       ↓
9. Post-Fix Verification on Disk
   (Re-reads file from disk and parses with Compose parser to verify localhost binding)
       ↓
10. Truthful Status Report (Reports before/after state and backup path)
```

---

## 6. Exit Codes

Lantern follows POSIX-compliant, deterministic CLI exit codes:

- `0`: Successful operation (e.g. `scan`, `why` with or without listener, `doctor`, `version`, `fix --dry-run`, user cancellation).
- `1`: User, input, platform, or runtime error (e.g. invalid port number, missing argument, unsupported platform condition, failed remediation).
