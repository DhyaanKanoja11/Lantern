# Lantern

> See exactly why your development machine exposes a service — and fix it.

[![Release](https://img.shields.io/badge/release-v0.1.2-blue.svg)](https://github.com/DhyaanKanoja11/Lantern/releases)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey.svg)](#platform-support)
[![Tests](https://img.shields.io/badge/tests-223%20passed-success.svg)](#testing)

Lantern is a local-first security CLI for developers. Rather than merely listing open ports, Lantern traces **configuration causality**—identifying the exact source line in your configuration, container mapping, process, and network interface that causes a service to be exposed, and providing safe, deterministic remediation.

```text
$ lantern why 5432
postgres :5432

EXPOSURE PATH

docker-compose.yml
       ↓
5432:5432
       ↓
Docker container: postgres
       ↓
0.0.0.0:5432
       ↓
eth0 (192.168.1.50)
       ↓
LAN reachable

ROOT CAUSE

/home/user/app/docker-compose.yml:18

    5432:5432

REACHABILITY

Local machine: YES
LAN:           YES
Internet:      UNKNOWN

RECOMMENDED CHANGE

    127.0.0.1:5432:5432

Bind published port to localhost (127.0.0.1) in /home/user/app/docker-compose.yml to prevent local network exposure.
```

---

## Why Not `ss`, `lsof`, or `nmap`?

| Capability | `ss` / `lsof` / `netstat` | `nmap` | **Lantern** |
| :--- | :---: | :---: | :---: |
| **Inspects local listening sockets** | :white_check_mark: | :x: (remote probes) | :white_check_mark: |
| **Correlates sockets to Docker containers** | :x: | :x: | :white_check_mark: |
| **Pinpoints source line in Docker Compose** | :x: | :x: | :white_check_mark: (`ROOT CAUSE`) |
| **Classifies interface reachability (LAN/VPN)** | :x: | Partial | :white_check_mark: |
| **Zero external network traffic (passive inside-out)** | :white_check_mark: | :x: (sends packets) | :white_check_mark: |
| **Safe, atomic 1-command remediation** | :x: | :x: | :white_check_mark: (`lantern fix`) |

Existing tools answer *"Which ports are open?"* but cannot answer:

> **"Why is this service reachable, what line in which file caused it, and how do I restrict it to localhost?"**

---

## Questions Lantern Answers

- **Why is port 5432 exposed to my local network?**
  `lantern why 5432` inspects the active socket, attributes it to its owning process or container (`docker-proxy`), and maps the listening address against your local network interfaces to explain why it is reachable.

- **Which Docker Compose file or line caused this port to be exposed?**
  Lantern inspects container labels, resolves the relevant Compose file via YAML AST parsing, and identifies the exact declaration line (e.g., `docker-compose.yml:18: 5432:5432`).

- **Is this service reachable from localhost, LAN, or VPN?**
  Lantern enumerates local network interfaces to evaluate reachability conservatively: loopback addresses (`127.0.0.1`) are classified as `localhost only`, while wildcard bindings (`0.0.0.0`) on active interfaces are classified as `LAN reachable` (with Internet exposure remaining `UNKNOWN` unless external evidence exists).

- **How can I safely restrict a supported Docker Compose binding to localhost?**
  `lantern fix 5432` generates a deterministic change to `127.0.0.1:5432:5432`. It verifies file SHA-256 fingerprints before and after writing, creates a byte-verified backup, prompts for interactive confirmation, and applies an atomic write.

---

## Quick Start (30 Seconds)

### 1. Install

Requires Go 1.22+:

```bash
git clone https://github.com/DhyaanKanoja11/Lantern.git
cd Lantern
go install ./cmd/lantern
```

Ensure your Go bin directory is in your `PATH` (if not already set):
```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

*(Alternatively, to build locally without installing: `go build -o lantern ./cmd/lantern` and invoke as `./lantern` or `../lantern` from subdirectories).*

### 2. Verify Your Environment

```bash
lantern doctor
```

### 3. Try the Included Demo

We include an isolated, reproducible demo setup in [`examples/`](examples/):

```bash
# Start a sample database with a deliberately exposed wildcard demo port (0.0.0.0:5432)
cd examples && docker compose up -d

# 1. Discover all active listening services
lantern scan

# 2. Trace the exact cause of exposure
lantern why 5432

# 3. Preview safe remediation without modifying files (zero writes)
lantern fix 5432 --dry-run

# 4. Safely apply the fix (prompts for confirmation, creates backup, and updates YAML)
lantern fix 5432

# Cleanup
docker compose down
```

---

## Core Commands

### `lantern scan`
Discovers active TCP listening sockets, attributes each listener to a process or container, classifies reachability, and renders a 5-column tabular summary.

```text
PORT    ADDRESS    PROCESS         CONTAINER    REACHABILITY
5432    0.0.0.0    docker-proxy    postgres     LAN reachable
8080    127.0.0.1  node            -            localhost only
```

### `lantern why <port>`
Investigates the complete exposure path and root cause for a specific TCP port (1–65535). Renders five structured sections: `SERVICE`, `EXPOSURE PATH`, `ROOT CAUSE` (or `LIKELY SOURCE`), `REACHABILITY`, and `RECOMMENDED CHANGE`.

### `lantern fix <port> [--dry-run]`
Applies automated, safe remediation to a supported exposure. Currently supports Docker Compose wildcard port publications by restricting host bindings to `127.0.0.1`.

- `--dry-run`: Performs complete analysis, previews the exact before/after change, reports the backup path that would be used, and makes zero writes.

```yaml
# Before:
services:
  db:
    ports:
      - "5432:5432"

# After:
services:
  db:
    ports:
      - "127.0.0.1:5432:5432"
```

### `lantern doctor`
Runs diagnostic probes against the runtime environment to report operational capabilities:
- Operating system detection (Linux/WSL2 vs non-Linux).
- `ss` utility availability.
- `/proc` filesystem accessibility.
- Docker CLI and daemon availability.
- Network interface enumeration.
- Listener collector readiness.

### `lantern version`
Prints the semantic version of the binary:
```text
lantern v0.1.2
```

### `lantern [command] --help`
Displays detailed help, usage patterns, and available flags for any command.

---

## What Lantern Does & Does NOT Do

### What Lantern Does
- **Discovers Active Listeners**: Inspects local TCP listening sockets on Linux and WSL2.
- **Correlates Processes**: Inspects `/proc` to attribute sockets to process IDs, executable paths, and command lines.
- **Correlates Containers**: Maps host listening sockets to Docker containers via the Docker daemon and container inspect metadata.
- **Locates Configuration Evidence**: Parses Docker Compose files (`docker-compose.yml`, `compose.yaml`, etc.) with AST precision to find the exact source line and service responsible for port publication.
- **Classifies Reachability**: Analyzes local network interfaces (`net.Interfaces()`) to classify exposure as `Local machine only`, `LAN reachable`, `VPN reachable`, or `Multi-interface`.
- **Explains Root Causes**: Constructs an end-to-end causal exposure path distinguishing verified certainty (`ROOT CAUSE`) from heuristic inference (`LIKELY SOURCE`).
- **Remediates Safely**: Interactively remedies wildcard Docker Compose exposures (`lantern fix <port>`) with cryptographic TOCTOU protection, byte-verified backups, and atomic writes.

### What Lantern Does NOT Do
- **NOT a Port Scanner**: Lantern does not send SYN packets across external subnets or scan remote targets. It inspects the local machine from the inside.
- **NOT an Nmap Replacement**: Lantern focuses on local developer workstation security and causal attribution, not network discovery.
- **NOT a Vulnerability Scanner**: Lantern does not check CVE databases, probe application endpoints, or perform fuzzing.
- **NOT a Silent Mutator**: Lantern never modifies firewall rules, system configurations, or source files without explicit confirmation.
- **Does NOT Guess Configuration**: Lantern does not infer configuration files for arbitrary native processes without deterministic file evidence.
- **Does NOT Make False Internet Claims**: A service listening on `0.0.0.0` is classified as `LAN reachable` with `Internet: UNKNOWN`. Lantern never claims a service is accessible over the public Internet without external proof.
- **No Background Daemon or Telemetry**: Zero network calls, zero analytics, zero external dependencies.

---

## How Lantern Determines Exposure

1. **Listener Collection**: Collects active TCP listening sockets via `ss` (or `/proc/net/tcp` and `/proc/net/tcp6`).
2. **Process Attribution**: Reads socket inode links in `/proc/<pid>/fd/` and correlates process metadata (`comm`, `cmdline`, `stat`) from `/proc/<pid>/`.
3. **Docker Correlation**: Inspects container network settings via the Docker API, mapping host port publish bindings (`HostIp:HostPort -> ContainerPort`) to discovered host listeners.
4. **Compose Discovery**: Discovers relevant Compose files using bounded, evidence-driven discovery rather than unrestricted filesystem traversal. Uses YAML AST nodes (`gopkg.in/yaml.v3`) to locate the exact service declaration and 1-indexed line number.
5. **Network Interface Classification**: Enumerates local interfaces via `net.Interfaces()`. Classifies addresses into `LOOPBACK`, `LAN` (RFC1918, RFC4193), `VPN` (tun, tap, wg, tailscale), or `OTHER`.
6. **Reachability Evaluation**:
   - `127.0.0.1` / `::1` -> `Local machine only` (LAN: NO, Internet: UNKNOWN).
   - `0.0.0.0` / `::` -> `LAN reachable` (LAN: YES, Internet: UNKNOWN).
   - Specific LAN IP -> `LAN reachable` (Local: YES, LAN: YES, Internet: UNKNOWN).

---

## Root Cause Model

Lantern applies strict deterministic precedence to identify the root cause:

1. **Docker Compose Published Port**: Accepted only when the Compose declaration strictly matches the observed runtime Docker port mapping (`HostPort`, `ContainerPort`, `HostIP`, `Protocol`, and container/service identity). Labeled `ROOT CAUSE` (`Certain: true`).
2. **Docker Published Port (No Compose)**: When published by Docker without a matching Compose declaration. Labeled `ROOT CAUSE` if direct container correlation is established.
3. **Native Process Wildcard Bind**: Native socket bound to `0.0.0.0` or `::`. Labeled `ROOT CAUSE` with PID/process evidence.
4. **Native Process Loopback Bind**: Native socket bound strictly to `127.0.0.1` or `::1`. Labeled `ROOT CAUSE`.
5. **Unresolved**: When evidence is missing, conflicting, or ambiguous. Labeled `LIKELY SOURCE` (`Certain: false`).

---

## 10-Layer Safety Model

`lantern fix` is engineered around a 10-layer safety system:

1. **Read-Only by Default**: Discovery and explanation commands (`scan`, `why`, `doctor`) perform zero writes.
2. **Explicit Confirmation**: The default response to the interactive prompt is `No` (`[y/N]`). Only an explicit affirmative response proceeds.
3. **Dry-Run Support**: `--dry-run` performs full analysis and previews changes with zero filesystem writes.
4. **Cryptographic TOCTOU Protection**: Computes a SHA-256 fingerprint of the configuration file during analysis. Re-verifies the fingerprint immediately before modification. If the file was edited, replaced, or deleted, Lantern aborts cleanly without touching the file.
5. **No Automatic Replanning**: If a file changes after analysis, Lantern never silently updates or applies a stale plan; it instructs the user to re-run the command.
6. **Byte-Verified Backup**: Creates a deterministic backup (`<file>.lantern.bak` or `<file>.lantern.bak.<N>`) and verifies byte equality before touching the original file. Existing backups are never overwritten.
7. **AST-Guided Precision**: Targets the exact YAML AST node for the specific service and line. Unrelated services, other ports, comments, indentation, and environment variables are preserved.
8. **AST Invariant Verification**: Verifies YAML syntax validity and re-parses with the Compose parser before writing to disk, ensuring only the target port was modified.
9. **Atomic Replacement**: Writes modified content to a temporary file in the same directory, flushes to disk, and atomically replaces the original via `rename`.
10. **Post-Fix Verification**: Re-reads the file from disk after writing and verifies that the configuration reflects loopback binding. If verification fails, Lantern reports the error and preserves the backup.

---

## Platform Support

| Operating System | Support Level | Behavior |
| :--- | :--- | :--- |
| **Linux (kernel 3.10+)** | **Primary** | Full functionality (`scan`, `why`, `doctor`, `fix`). |
| **WSL2** | **Primary** | Full functionality inside WSL2 Linux environments. |
| **Windows** | **Build & Diagnostic** | Compiles cleanly. `doctor` and `version` work. `scan`, `why`, and `fix` notify that socket inspection requires Linux/WSL2. |
| **macOS** | **Build & Diagnostic** | Compiles cleanly. Socket inspection requires Linux/WSL2. |

---

## Limitations

- **Linux-Specific Listener Discovery**: Native socket inspection directly parses Linux `/proc/net/tcp` and `ss` output. On macOS and Windows, running inside a WSL2 or Linux VM is required.
- **Docker CLI Dependency**: Correlating published ports to containers relies on the Docker CLI and daemon being accessible.
- **Rootless / Host Networking**: Containers using `--net=host` share the host network stack; Lantern attributes them to the container only when PID correlation is established.
- **Native Process Configuration**: Automatic remediation is not supported for arbitrary native processes because application configuration formats vary widely.
- **Standalone Containers**: Containers created via raw `docker run` without a Compose file cannot be remediated via Compose editing.
- **Docker Desktop with WSL2 Networking**: When running Docker Desktop on Windows with the WSL2 backend, published container ports may be forwarded through a virtualized networking layer (or utility distribution) that is not directly visible as a host listening socket or process inside the user's WSL2 distribution. This networking indirection can prevent deterministic listener-to-container attribution. Consistent with Lantern's conservative reachability model, Lantern does not claim that such ports are Internet-exposed and maintains its standard conservative semantics (treating external reachability as UNKNOWN without direct evidence).
- **Conservative Reachability**: Lantern never claims public Internet exposure without external verification. Wildcard bindings are classified as `LAN reachable` with `Internet: UNKNOWN`.

---

## Architecture & Codebase

For an in-depth explanation of Lantern's internal layering, package boundaries, data flows, and design decisions, see:

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Architectural principles and data pipeline.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Guidelines for local development and pull requests.
- [`SECURITY.md`](SECURITY.md) — Security policy and vulnerability disclosure procedures.

---

## Development & Testing

### Building
```bash
go build ./cmd/lantern
```

### Linux Cross-Compilation
```bash
GOOS=linux GOARCH=amd64 go build ./cmd/lantern
GOOS=linux GOARCH=arm64 go build ./cmd/lantern
```

### Testing
Run unit and integration test suites:
```bash
go test -count=1 -v ./...
```

Run race condition detection:
```bash
go test -race ./...
```

Verify formatting and linting:
```bash
gofmt -s -l .
go vet ./...
```

---

## Roadmap

- **v0.2**: Machine-readable JSON output (`--json`) for CI/CD and automation pipelines.
- **v0.3**: Continuous exposure watch mode (`lantern watch`) with file and socket diffing.
- **v0.4**: Security policy engine and compliance rule evaluation.
- **v0.5**: Native configuration parsers for popular developer servers (PostgreSQL, Redis, Vite).

---

## License

MIT License. See [LICENSE](LICENSE) for details.
