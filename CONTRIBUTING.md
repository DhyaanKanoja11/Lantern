# Contributing to Lantern

Thank you for your interest in contributing to Lantern!

Lantern is a local-first developer security CLI designed to explain *why* local network services are reachable and provide safe, deterministic remediation.

---

## Core Engineering Principles

Before contributing code, please keep our design principles in mind:

1. **Causal Explanation over Port Scanning**: Lantern does not just list open sockets; it traces from the network interface back to the exact source line in configuration.
2. **Standard Library First**: We prioritize standard library primitives over third-party dependencies. Avoid introducing new external dependencies unless strictly necessary.
3. **Domain Purity**: `internal/domain` contains pure data types with zero external dependencies and zero operating system syscalls.
4. **Platform Isolation via Build Tags**: Platform-dependent logic (e.g. Linux `/proc` parsing) must be isolated with Go build tags (`//go:build linux` and `//go:build !linux`).
5. **Fail-Closed Safety**: Any ambiguity, file modification, or verification mismatch in remediation must immediately halt without touching user files.
6. **No Telemetry or Background Daemons**: Lantern does not make outbound network requests, collect analytics, or run background processes.

---

## Finding Something to Work On

We welcome contributions of all levels. To protect user safety and code maintainability, we classify tasks into two tracks:

### Beginner-Friendly Contributions ("Good First Issues")
These areas have minimal blast radius and do not touch security-critical file modification logic:
- **Diagnostic Probes**: Adding or improving probes in `lantern doctor` (e.g. checking specific container runtime sockets or permissions).
- **CLI Output Ergonomics**: Improving formatting, table alignment, or help text descriptions.
- **Documentation & Guides**: Clarifying README examples, platform limitations, or adding troubleshooting scenarios.
- **Test Scenarios**: Writing hermetic unit tests for edge-case Compose configurations or socket parsing.

Look for the [`good first issue`](https://github.com/DhyaanKanoja11/Lantern/labels/good%20first%20issue) label on GitHub.

### Security-Critical & Core Architecture Areas
The following areas enforce safety invariants and require architectural review prior to implementation:
- **YAML AST Modification (`internal/remediation`)**: TOCTOU hash verification, AST line targeting, byte-verified backups, and atomic writes.
- **Reachability Analysis (`internal/analyzer`)**: Interface classification and cross-family socket attribution.
- **Platform Syscalls & Collectors (`internal/collector`)**: Low-level `/proc/net` parsers and socket table handling.

---

## External Tester Programme

If you are a developer using Docker Compose, we invite you to participate in our [External Tester Programme](docs/TESTER_PROGRAMME.md). Your structured feedback on installation friction, diagnostic clarity, and remediation safety directly drives our product roadmap. Submit feedback using our [Tester Feedback Issue Template](.github/ISSUE_TEMPLATE/tester_feedback.md).

---

## Development Setup

### Prerequisites

- **Go 1.22+**: Required for building and testing.
- **Operating System**: Linux (kernel 3.10+) or WSL2 (Windows Subsystem for Linux 2) for full socket and process inspection features. Windows and macOS compile cleanly with stub collectors for diagnostic commands.
- **Docker & Docker Compose** (Optional): Useful for running and testing container and Compose correlation.

### Building from Source

```bash
git clone https://github.com/DhyaanKanoja11/Lantern.git
cd Lantern
go build ./cmd/lantern
```

To install the binary to `$GOPATH/bin`:
```bash
go install ./cmd/lantern
```

Or install directly via Go module:
```bash
go install github.com/DhyaanKanoja11/Lantern/cmd/lantern@latest
```

---

## Testing & Validation

All contributions must pass the test suite, race detector, and static analysis:

```bash
# Run unit and integration tests
go test -count=1 -v ./...

# Run race condition detector
go test -race ./...

# Verify static analysis and formatting
go vet ./...
gofmt -s -l .

# Verify multi-platform compilation
GOOS=linux GOARCH=amd64 go build ./cmd/lantern
GOOS=linux GOARCH=arm64 go build ./cmd/lantern
GOOS=windows GOARCH=amd64 go build ./cmd/lantern
GOOS=darwin GOARCH=arm64 go build ./cmd/lantern
```

---

## Submitting Pull Requests

1. **Open an Issue First**: For non-trivial features or architectural changes, please open an issue to discuss the approach before writing code.
2. **Keep PRs Focused**: Address one bug or feature per pull request. Avoid mixing refactoring with behavioral changes.
3. **Include Tests**: Add unit tests in the appropriate package. Maintain hermetic testability by injecting interfaces rather than invoking live system commands in tests.
4. **Preserve Compatibility**: Ensure POSIX exit code consistency (0 for success, non-zero for error) and conservative reachability semantics (`Internet: UNKNOWN`).

---

## Code of Conduct

Please maintain a respectful, constructive, and collaborative environment. We value clear communication, technical rigor, and kindness.
