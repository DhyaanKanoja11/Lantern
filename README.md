# Lantern

> Explain exactly why a development-machine service is exposed.

Lantern is a local-first security tool designed for developers. Rather than merely listing open ports, Lantern traces and explains **configuration causality**—identifying the exact configuration declaration, container mapping, process, and network interface that causes a service to be exposed, and providing safe, deterministic remediation.

---

## What Lantern Does

- **Discovers Active Listeners**: Inspects local TCP listening sockets on Linux and WSL2.
- **Correlates Processes**: Inspects `/proc` to attribute sockets to process IDs, executable paths, and command lines.
- **Correlates Containers**: Maps host listening sockets to Docker containers via the Docker daemon and container inspect metadata.
- **Locates Configuration Evidence**: Parses Docker Compose files (`docker-compose.yml`, `compose.yaml`) with AST precision to find the exact source line and service responsible for port publication.
- **Classifies Reachability**: Analyzes local network interfaces (`net.Interfaces()`) to classify exposure as `Local machine only`, `LAN reachable`, `VPN reachable`, or `Multi-interface`.
- **Explains Root Causes**: Constructs an end-to-end causal exposure path distinguishing verified certainty (`ROOT CAUSE`) from heuristic inference (`LIKELY SOURCE`).
- **Remediates Safely**: Interactively remedies wildcard Docker Compose exposures (`lantern fix <port>`) with cryptographic TOCTOU protection, byte-verified backups, and atomic writes.

---

## What Lantern Does NOT Do

- **NOT a Port Scanner**: Lantern does not send SYN packets across external subnets or scan remote targets. It inspects the local machine from the inside.
- **NOT an Nmap Replacement**: Lantern focuses on local developer workstation security and causal attribution, not network discovery.
- **NOT a Vulnerability Scanner**: Lantern does not check CVE databases, probe application endpoints, or perform fuzzing.
- **NOT a Silent Mutator**: Lantern never modifies firewall rules, system configurations, or source files without explicit confirmation.
- **Does NOT Guess Configuration**: Lantern does not infer configuration files for arbitrary native processes without deterministic file evidence.
- **Does NOT Make False Internet Claims**: A service listening on `0.0.0.0` is classified as `LAN reachable` with `Internet: UNKNOWN`. Lantern never claims a service is accessible over the public Internet without external proof.
- **No Background Daemon or Telemetry**: Zero network calls, zero analytics, zero external dependencies.

---

## Why Lantern Exists

Modern developers routinely run microservices, databases, caches, and AI models locally (PostgreSQL, Redis, Vite, Node, Ollama, Docker containers). By default:

- Docker publishes ports to `0.0.0.0` (all host interfaces) unless explicitly prefixed with `127.0.0.1`.
- Dev servers and frameworks frequently bind to `0.0.0.0` to support containerization or mobile testing.
- Laptops switch across home Wi-Fi, office LANs, coffee shops, and public networks.

Existing tools like `netstat`, `lsof`, or `ss` answer **"Which ports are open?"** but cannot answer:

> **"Why is this service reachable, what line in which file caused it, and how do I restrict it to localhost?"**

Lantern traces the entire causal chain:

```text
configuration declaration (docker-compose.yml:18)
       ↓
container / process (docker-proxy / postgres)
       ↓
listening socket (TCP 0.0.0.0:5432)
       ↓
host network interfaces (eth0: 192.168.1.50)
       ↓
reachability classification (LAN reachable)
       ↓
root cause determination (ROOT CAUSE)
       ↓
actionable remediation (127.0.0.1:5432:5432)
```

---

## Installation

### From Source (Go 1.22+)

```bash
git clone https://github.com/lantern-dev/lantern.git
cd lantern
go build -o lantern ./cmd/lantern
```

To install directly to `$GOPATH/bin`:

```bash
go install ./cmd/lantern
```

---

## Requirements

- **Operating System**: Linux (kernel 3.10+) or WSL2 (Windows Subsystem for Linux 2).
- **Permissions**: Standard user access; read permissions on `/proc` for detailed process attribution.
- **Socket Tool**: `ss` utility (standard on most Linux distributions; falls back to `/proc/net/tcp`).
- **Container Tooling (Optional)**: Docker CLI and daemon connectivity for container and Compose correlation. In WSL2 environments using Docker Desktop, WSL integration must be enabled for the active distribution.

---

## Quick Start

```bash
# 1. Check system prerequisites and permissions
lantern doctor

# 2. Discover all listening services
lantern scan

# 3. Explain why a specific port is reachable
lantern why 5432

# 4. Preview automated remediation without modifying files
lantern fix 5432 --dry-run

# 5. Apply automated remediation
lantern fix 5432
```

---

## Commands

### `lantern scan`
Discovers active TCP listening sockets, attributes each listener to a process or container, classifies reachability, and renders a 5-column tabular summary.

```text
PORT    ADDRESS    PROCESS         CONTAINER    REACHABILITY
5432    0.0.0.0    docker-proxy    postgres     LAN reachable
8080    127.0.0.1  node            -            localhost only
```

### `lantern why <port>`
Investigates the complete exposure path and root cause for a specific TCP port (1–65535). Renders five structured sections: `SERVICE`, `EXPOSURE PATH`, `ROOT CAUSE` (or `LIKELY SOURCE`), `REACHABILITY`, and `RECOMMENDED CHANGE`.

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
lantern v0.1.0
```

### `lantern fix <port> [--dry-run]`
Applies automated, safe remediation to a supported exposure. Currently supports Docker Compose wildcard port publications by restricting host bindings to `127.0.0.1`.

- `--dry-run`: Performs complete analysis, previews the exact before/after change, reports the backup path that would be used, and makes zero writes.

---

## Example

```text
$ lantern why 5432
postgres :5432

EXPOSURE PATH

docker-compose.yml
    └── ports: 5432:5432
        └── Docker container: postgres
            └── socket: 0.0.0.0:5432 (tcp)
                └── eth0 (192.168.1.50) [LAN]
                    └── LAN reachable

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

## How Lantern Determines Exposure

1. **Listener Collection**: Collects active TCP listening sockets via `ss` (or `/proc/net/tcp` and `/proc/net/tcp6`).
2. **Process Attribution**: Reads socket inode links in `/proc/<pid>/fd/` and correlates process metadata (`comm`, `cmdline`, `stat`) from `/proc/<pid>/`.
3. **Docker Correlation**: Inspects container network settings via the Docker API, mapping host port publish bindings (`HostIp:HostPort -> ContainerPort`) to discovered host listeners.
4. **Compose AST Discovery**: Discovers Compose files via container labels or directory walking. Uses YAML AST nodes (`gopkg.in/yaml.v3`) to locate the exact service declaration and 1-indexed line number.
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

## Automated Remediation

For supported Docker Compose exposures, `lantern fix <port>` changes wildcard port bindings to loopback:

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

---

## Safety Model

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

## Development

### Building
```bash
go build ./...
```

### Linux Cross-Compilation
```bash
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
```

---

## Testing

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
