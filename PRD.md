# Lantern v0.1

**Tagline:** See exactly why your development machine exposes a service.

**Status:** Build specification  
**Version:** 0.1.0  
**Primary platform:** Linux / WSL2  
**Primary language:** Go  
**Interface:** CLI  
**License:** MIT recommended

---

# 1. Product Definition

Lantern is a local-first developer security tool that explains **why a network service is reachable**.

Lantern does not primarily ask:

> “Which ports are open?”

It asks:

> “What configuration caused this service to become reachable, through which components, and how can I safely change it?”

The core v0.1 command is:

```bash
lantern why <port>
```

Example:

```bash
lantern why 5432
```

Expected conceptual output:

```text
PostgreSQL :5432

EXPOSURE PATH

docker-compose.yml
       │
       ▼
5432:5432
       │
       ▼
Docker container: postgres
       │
       ▼
0.0.0.0:5432
       │
       ▼
Wi-Fi interface
       │
       ▼
LAN reachable

ROOT CAUSE

docker-compose.yml:18

    ports:
      - "5432:5432"

RECOMMENDED CHANGE

    ports:
      - "127.0.0.1:5432:5432"

REACHABILITY

Local machine: YES
LAN:           YES
Internet:      UNKNOWN

WHY

Docker published the container port on all host interfaces.
```

---

# 2. Problem

Modern development machines increasingly contain:

- Docker
- Docker Compose
- WSL
- local databases
- Redis
- development servers
- local LLM servers
- VPNs
- virtual interfaces
- IDE tooling
- multiple programming runtimes

Developers frequently expose services accidentally through:

```yaml
ports:
  - "5432:5432"
```

or:

```bash
python -m http.server 8000 --bind 0.0.0.0
```

or:

```javascript
server.listen(3000, "0.0.0.0")
```

Existing tools can tell developers that a port is listening.

Lantern's purpose is to connect the evidence:

```text
configuration
      ↓
process/container
      ↓
socket
      ↓
bind address
      ↓
network interface
      ↓
reachability
```

---

# 3. Goals

## v0.1 Goals

Lantern must be able to:

1. Discover TCP listening sockets.
2. Identify the owning process where permissions allow.
3. Identify the owning Docker container where applicable.
4. Identify Docker published-port mappings.
5. Determine the bind address.
6. Identify relevant network interfaces.
7. Locate likely Docker Compose configuration.
8. Explain the exposure path.
9. Provide a safe suggested configuration change.
10. Produce both human-readable and JSON output.
11. Work without cloud services.
12. Work without an account.
13. Work without an AI API.

---

# 4. Non-goals

Do NOT implement these in v0.1:

- vulnerability scanning
- CVE scanning
- Nmap replacement
- packet inspection
- firewall modification
- automatic remediation
- cloud dashboard
- telemetry
- AI explanations
- Kubernetes
- macOS support
- Windows-native support
- authentication
- user accounts
- GUI
- vulnerability exploitation
- internet-wide scanning

The product must remain small.

---

# 5. Target Users

Primary:

1. Docker developers
2. WSL developers
3. backend developers
4. full-stack developers
5. local AI/LLM developers
6. cybersecurity students
7. homelab/self-hosting users

Secondary:

- DevOps engineers
- security researchers
- educators
- development teams

---

# 6. Core User Stories

## US-01

As a developer, I want to know why port 5432 is reachable.

```bash
lantern why 5432
```

## US-02

As a developer, I want to know which process owns a listening port.

```bash
lantern why 8000
```

## US-03

As a Docker developer, I want to know which container published a port.

```bash
lantern why 6379
```

## US-04

As a developer, I want to know whether the service is localhost-only or LAN-accessible.

```bash
lantern why 3000
```

## US-05

As a developer, I want to know which configuration caused the exposure.

```bash
lantern why 5432
```

should ideally identify:

```text
docker-compose.yml:18
```

## US-06

As a developer, I want machine-readable output.

```bash
lantern why 5432 --json
```

---

# 7. CLI Design

## Command 1

```bash
lantern scan
```

Purpose:

Show detected listening services.

Example:

```text
PORT     ADDRESS       PROCESS        CONTAINER
22       0.0.0.0       sshd           -
3000     127.0.0.1     node           -
5432     0.0.0.0       docker-proxy   postgres
6379     0.0.0.0       docker-proxy   redis
```

---

## Command 2

```bash
lantern why <port>
```

This is the primary command.

Example:

```bash
lantern why 5432
```

Output sections:

```text
SERVICE
EXPOSURE PATH
ROOT CAUSE
REACHABILITY
RECOMMENDED CHANGE
```

---

## Command 3

```bash
lantern version
```

Output:

```text
lantern v0.1.0
```

---

## Command 4

```bash
lantern doctor
```

Purpose:

Check whether Lantern has sufficient permissions and required dependencies.

Example:

```text
Lantern Doctor

✓ Linux detected
✓ ss available
✓ Docker detected
✓ Docker daemon reachable
⚠ Process details may require elevated permissions

Ready.
```

---

## Future commands

Do NOT implement yet:

```bash
lantern watch
lantern diff
lantern history
lantern policy
lantern check
lantern fix
lantern graph
```

---

# 8. Detection Model

Lantern should internally represent an exposure as structured evidence.

Conceptual model:

```text
Exposure
├── Port
├── Protocol
├── BindAddress
├── Process
│   ├── PID
│   ├── Name
│   └── Command
├── Container
│   ├── ID
│   ├── Name
│   └── Image
├── DockerMapping
│   ├── HostIP
│   ├── HostPort
│   └── ContainerPort
├── Interfaces
├── ConfigSource
│   ├── File
│   ├── Line
│   └── Evidence
├── Reachability
└── Recommendation
```

---

# 9. Data Flow

```text
                    lantern why 5432
                           │
                           ▼
                    CLI argument parser
                           │
                           ▼
                    Listener Collector
                           │
                           ▼
                    Process Correlator
                           │
                           ▼
                    Docker Correlator
                           │
                           ▼
                  Configuration Resolver
                           │
                           ▼
                  Interface Classifier
                           │
                           ▼
                  Reachability Analyzer
                           │
                           ▼
                    Exposure Builder
                           │
                           ▼
                  Explanation Renderer
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
              Human output       JSON output
```

---

# 10. Linux Listener Detection

Primary source:

```bash
ss -lntp
```

Prefer structured parsing where possible.

Do not rely solely on human-formatted output if `/proc/net/tcp` or other kernel interfaces provide more reliable information.

Required information:

- protocol
- local address
- local port
- PID
- process name

Example:

```text
LISTEN
0.0.0.0:5432
PID 1234
```

Lantern must normalize:

```text
0.0.0.0
127.0.0.1
[::]
::1
specific interface address
```

---

# 11. Process Correlation

For every listener:

```text
PID
 ↓
/proc/<pid>/
 ↓
process executable
 ↓
command line
```

Capture when permitted:

```text
PID
Executable
Command
User
Parent PID
```

Do not require root by default.

If permission prevents process discovery:

```text
Process: unavailable
Reason: insufficient permissions
```

Do not silently fail.

---

# 12. Docker Correlation

Detect Docker availability.

Use:

```bash
docker ps
docker inspect
```

where appropriate.

For each running container identify:

```text
Container ID
Container name
Image
Published ports
Networks
```

Example:

```text
Container:
postgres-dev

Image:
postgres:16

Published:
0.0.0.0:5432 -> 5432/tcp
```

---

# 13. Docker Compose Attribution

Lantern should attempt to find the configuration responsible for the Docker mapping.

Search likely locations:

```text
docker-compose.yml
docker-compose.yaml
compose.yml
compose.yaml
```

Do not perform unrestricted filesystem scanning.

Search:

1. current working directory
2. parent directories
3. Docker Compose working-directory labels if available
4. paths explicitly supplied by the user

Potential command:

```bash
lantern why 5432 --project /path/to/project
```

can be added if automatic discovery is ambiguous.

---

# 14. Configuration Attribution

The resolver should find a relevant configuration line.

Example:

```yaml
ports:
  - "5432:5432"
```

Return:

```text
File:
docker-compose.yml

Line:
18

Evidence:
5432:5432
```

If attribution cannot be proven, do not claim certainty.

Use:

```text
Likely source
```

instead of:

```text
Root cause
```

when evidence is incomplete.

---

# 15. Reachability Model

v0.1 should distinguish:

### Localhost

```text
127.0.0.1
::1
```

Classification:

```text
LOCAL_ONLY
```

### Wildcard

```text
0.0.0.0
::
```

Classification:

```text
NON_LOCAL
```

### Specific interface

Example:

```text
192.168.1.25
```

Classification:

```text
INTERFACE_BOUND
```

Lantern should identify relevant interfaces with:

```bash
ip addr
```

and classify broadly:

```text
LOOPBACK
LAN
VPN
OTHER
```

Do not claim internet exposure merely because a service binds to `0.0.0.0`.

Instead:

```text
LAN reachable: likely
Internet reachable: unknown
```

unless actual evidence exists.

---

# 16. Reachability Semantics

Use conservative language.

### Example

```text
127.0.0.1:5432

Local: YES
LAN: NO
Internet: NO
```

### Example

```text
0.0.0.0:5432

Local: YES
LAN: POSSIBLE
Internet: UNKNOWN
```

### Example

```text
192.168.1.25:5432

Local: YES
LAN: POSSIBLE
Internet: UNKNOWN
```

Firewall state should not be inferred in v0.1.

---

# 17. Recommendation Engine

v0.1 recommendations should be deterministic.

Example:

```text
Current:
0.0.0.0:5432

Suggested:
127.0.0.1:5432
```

For Docker Compose:

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

For a process explicitly binding:

```text
Current:
0.0.0.0:8000

Suggestion:
bind the development server to 127.0.0.1
```

Lantern must NOT automatically edit files in v0.1.

---

# 18. JSON API

Every important result must be serializable.

Example:

```json
{
  "port": 5432,
  "protocol": "tcp",
  "bind_address": "0.0.0.0",
  "process": {
    "pid": 1234,
    "name": "docker-proxy"
  },
  "container": {
    "id": "abc123",
    "name": "postgres-dev",
    "image": "postgres:16"
  },
  "docker_mapping": {
    "host_ip": "0.0.0.0",
    "host_port": 5432,
    "container_port": 5432
  },
  "config": {
    "file": "docker-compose.yml",
    "line": 18,
    "evidence": "5432:5432"
  },
  "reachability": {
    "local": true,
    "lan": "possible",
    "internet": "unknown"
  },
  "recommendation": {
    "type": "bind_localhost",
    "value": "127.0.0.1:5432:5432"
  }
}
```

---

# 19. Architecture

Use a layered architecture.

```text
cmd/
  lantern/
      main.go

internal/
  cli/
  collector/
  process/
  docker/
  compose/
  network/
  exposure/
  explain/
  output/
```

Dependency direction:

```text
CLI
 ↓
Application/Use Cases
 ↓
Domain
 ↓
Infrastructure
```

Do not allow Docker-specific code to leak throughout the application.

---

# 20. Recommended Go Packages

Use the standard library wherever possible.

Potential libraries:

```text
cobra
```

for CLI parsing.

For YAML parsing:

```text
gopkg.in/yaml.v3
```

Avoid adding dependencies unless there is a concrete reason.

---

# 21. Folder Structure

```text
lantern/
│
├── cmd/
│   └── lantern/
│       └── main.go
│
├── internal/
│   ├── cli/
│   │   ├── root.go
│   │   ├── scan.go
│   │   ├── why.go
│   │   ├── doctor.go
│   │   └── version.go
│   │
│   ├── domain/
│   │   ├── exposure.go
│   │   ├── listener.go
│   │   ├── process.go
│   │   ├── container.go
│   │   ├── interface.go
│   │   └── config.go
│   │
│   ├── collector/
│   │   ├── listener.go
│   │   └── linux_listener.go
│   │
│   ├── process/
│   │   └── linux_process.go
│   │
│   ├── docker/
│   │   ├── client.go
│   │   ├── containers.go
│   │   └── ports.go
│   │
│   ├── compose/
│   │   ├── discover.go
│   │   ├── parse.go
│   │   └── attribution.go
│   │
│   ├── network/
│   │   ├── interfaces.go
│   │   └── classify.go
│   │
│   ├── exposure/
│   │   ├── analyzer.go
│   │   ├── reachability.go
│   │   └── recommendation.go
│   │
│   ├── explain/
│   │   └── explanation.go
│   │
│   └── output/
│       ├── text.go
│       └── json.go
│
├── tests/
│   ├── fixtures/
│   │   ├── compose-basic/
│   │   ├── compose-localhost/
│   │   └── compose-wildcard/
│   │
│   └── integration/
│
├── docs/
│   ├── architecture.md
│   ├── detection-model.md
│   └── threat-model.md
│
├── .github/
│   └── workflows/
│       ├── test.yml
│       └── release.yml
│
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
├── README.md
└── .gitignore
```

---

# 22. Domain Model

The domain must not know about shell commands.

For example:

```go
type Listener struct {
    Protocol    string
    Address     string
    Port        uint16
    PID         int
    ProcessName string
}
```

Container:

```go
type Container struct {
    ID      string
    Name    string
    Image   string
    Ports   []PortMapping
}
```

Port mapping:

```go
type PortMapping struct {
    HostIP        string
    HostPort      uint16
    ContainerPort uint16
    Protocol      string
}
```

Configuration:

```go
type ConfigEvidence struct {
    File     string
    Line     int
    Evidence string
    Kind     string
}
```

Reachability:

```go
type Reachability struct {
    Local     bool
    LAN       string
    Internet  string
}
```

Exposure:

```go
type Exposure struct {
    Listener       Listener
    Process        *Process
    Container      *Container
    Config         *ConfigEvidence
    Interfaces     []NetworkInterface
    Reachability   Reachability
    Recommendation *Recommendation
}
```

---

# 23. Error Handling

Never hide errors.

Use errors such as:

```text
Docker unavailable
Insufficient permissions
No process attribution available
Configuration source not found
Port not found
Unsupported environment
```

But continue collecting whatever evidence is still available.

Example:

```text
Port: 5432
Process: docker-proxy
Container: postgres-dev
Config: unavailable

Warning:
Could not locate the Compose configuration responsible for this mapping.
```

---

# 24. Testing Strategy

Unit tests:

```text
listener parsing
IP classification
port mapping parsing
compose parsing
reachability classification
recommendation generation
```

Integration tests:

```text
real Docker container
real published port
real process
real Compose file
```

Test cases:

### Case A

```text
127.0.0.1:3000
```

Expected:

```text
LOCAL_ONLY
```

### Case B

```text
0.0.0.0:3000
```

Expected:

```text
NON_LOCAL
```

### Case C

```yaml
ports:
  - "5432:5432"
```

Expected:

```text
0.0.0.0:5432
```

### Case D

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

Expected:

```text
127.0.0.1:5432
```

### Case E

No Docker.

Expected:

```text
Process-level explanation only.
```

---

# 25. Security Requirements

Lantern itself must be defensive.

Do not:

- send collected data anywhere
- execute commands discovered from configuration
- automatically modify firewall rules
- automatically modify Compose files
- execute arbitrary project scripts
- trust Docker labels as authoritative without validation
- expose collected system information through a network service

The CLI should operate locally.

---

# 26. Privacy

Default behavior:

```text
NO NETWORK TELEMETRY
NO CLOUD
NO ACCOUNT
NO ANALYTICS
```

README should explicitly state:

> Lantern runs locally and does not require an account or cloud service.

---

# 27. Performance

Target:

```text
lantern scan
< 1 second
```

on a normal developer machine where possible.

Do not optimize prematurely.

Correctness > micro-optimizations.

---

# 28. v0.1 Acceptance Criteria

v0.1 is complete only when:

### Detection

- [ ] Detect TCP listeners.
- [ ] Detect IPv4 listeners.
- [ ] Detect IPv6 listeners where practical.
- [ ] Identify PID where permissions allow.
- [ ] Identify process name.

### Docker

- [ ] Detect Docker.
- [ ] Identify containers.
- [ ] Identify published ports.
- [ ] Correlate host port to container.
- [ ] Detect host bind address.

### Compose

- [ ] Locate common Compose files.
- [ ] Parse port mappings.
- [ ] Identify relevant line.
- [ ] Provide evidence.

### Network

- [ ] Detect interfaces.
- [ ] Classify loopback.
- [ ] Classify likely LAN addresses.
- [ ] Avoid claiming internet exposure without evidence.

### CLI

- [ ] `lantern scan`
- [ ] `lantern why <port>`
- [ ] `lantern doctor`
- [ ] `lantern version`
- [ ] `--json`

### Quality

- [ ] Unit tests.
- [ ] Integration tests.
- [ ] Useful errors.
- [ ] README.
- [ ] Installation instructions.
- [ ] Example terminal output.
- [ ] MIT license.

---

# 29. Development Roadmap

## Phase 1 — Foundation

```text
Go project
CLI
domain types
logging/errors
tests
```

## Phase 2 — Linux

```text
listeners
processes
interfaces
```

## Phase 3 — Docker

```text
containers
published ports
correlation
```

## Phase 4 — Compose

```text
file discovery
YAML parsing
line attribution
```

## Phase 5 — Explanation

```text
exposure path
reachability
recommendation
```

## Phase 6 — Polish

```text
JSON
doctor
tests
README
demo
```

Only after these:

```text
watch
diff
history
policy
fix
```

---

# 30. Exact Antigravity Prompts

## Prompt 0 — Project rules

Give this first.

```text
You are working on Lantern, a local-first developer security CLI.

Read the repository before modifying anything.

Product:
Lantern explains why a development service is reachable.

Core command:
lantern why <port>

v0.1 target:
Linux and WSL2.

Language:
Go.

Architecture:
CLI -> application/use cases -> domain -> infrastructure.

Important constraints:
- Do not build a GUI.
- Do not add AI.
- Do not add cloud services.
- Do not add telemetry.
- Do not build a vulnerability scanner.
- Do not modify firewall rules.
- Do not automatically modify user files.
- Do not implement Kubernetes.
- Do not implement Windows-native support yet.
- Prefer Go standard library.
- Add dependencies only when justified.
- Keep the domain layer independent of shell commands and Docker.
- Never silently ignore errors.
- Never claim internet exposure when the evidence only proves wildcard binding.
- Never fabricate configuration attribution.

Before coding:
1. Inspect the repository.
2. Check the current Go version.
3. Check existing files.
4. Propose the smallest implementation for the current task.
5. Do not implement future roadmap items.

After coding:
1. Run formatting.
2. Run tests.
3. Run static checks available in the repository.
4. Report exactly what changed.
5. Report any limitations.
```

---

# 31. Prompt 1 — Scaffold

```text
Implement only the Lantern v0.1 project scaffold.

Create the Go module and the following structure:

cmd/lantern/
internal/cli/
internal/domain/
internal/collector/
internal/process/
internal/docker/
internal/compose/
internal/network/
internal/exposure/
internal/explain/
internal/output/
tests/
docs/

Implement:
- lantern version
- lantern doctor
- lantern scan placeholder
- lantern why placeholder

Create domain models for:
- Listener
- Process
- Container
- PortMapping
- NetworkInterface
- ConfigEvidence
- Reachability
- Recommendation
- Exposure

Do not implement Linux detection yet.

Acceptance:
go test ./...
go build ./...

Keep the code minimal.
```

---

# 32. Prompt 2 — Linux listener engine

```text
Implement the Linux listener discovery engine.

Goal:
Discover TCP listening sockets and return normalized Listener objects.

Requirements:
- Linux only for now.
- Prefer reliable system interfaces.
- You may use ss or /proc where appropriate.
- Do not parse terminal output more than necessary.
- Support IPv4.
- Support IPv6 where practical.
- Capture:
  protocol
  local address
  local port
  PID where available
  process name where available.

Do not implement Docker correlation yet.

Add unit tests using representative listener data.

Update:
lantern scan

Example output:

PORT     ADDRESS       PROCESS
22       0.0.0.0       sshd
3000     127.0.0.1     node
5432     0.0.0.0       postgres

If process information is unavailable, display:
unknown

Do not fail the complete scan because one process cannot be inspected.
```

---

# 33. Prompt 3 — Process correlation

```text
Implement Linux process correlation.

For a listener PID, inspect /proc/<pid>/ where permitted.

Capture:
- PID
- executable
- command line
- user if safely available
- parent PID if available
- process name

Requirements:
- Never require root by default.
- Handle permission errors gracefully.
- Return structured errors internally.
- Do not expose raw sensitive environment variables.
- Do not read arbitrary process environment variables.

Update lantern scan to display process information.

Add unit tests for:
- valid process
- missing process
- permission failure
- malformed /proc data

Do not implement Docker yet.
```

---

# 34. Prompt 4 — Docker correlation

```text
Implement Docker correlation.

Use the Docker CLI initially rather than adding a Docker SDK unless there is a compelling technical reason.

Detect whether Docker is available.

For running containers collect:
- container ID
- container name
- image
- published ports
- host IP
- host port
- container port
- protocol

Correlate a host listener with a Docker published port.

Example:

Host:
0.0.0.0:5432

Docker:
postgres-dev
5432 -> 5432/tcp

Return a structured correlation.

Handle:
- Docker unavailable
- Docker daemon unavailable
- malformed output
- permission errors

Do not make Docker a hard dependency for lantern scan.

Add tests using fixtures/mocks rather than requiring Docker for every unit test.
```

---

# 35. Prompt 5 — Network interface classification

```text
Implement Linux network interface discovery.

Collect:
- interface name
- IP address
- CIDR
- loopback status

Classify addresses as:
- LOOPBACK
- LAN
- VPN
- OTHER

Be conservative.

Do not claim that a service is internet-accessible merely because it binds to 0.0.0.0.

Implement reachability classification:

127.0.0.1 / ::1:
local=true
lan=false
internet=unknown

0.0.0.0 / :::
local=true
lan=possible
internet=unknown

specific LAN address:
local=true
lan=possible
internet=unknown

Keep the result structured.

Add tests for representative IPv4 and IPv6 addresses.
```

---

# 36. Prompt 6 — Compose attribution

```text
Implement Docker Compose attribution.

Supported filenames:
- docker-compose.yml
- docker-compose.yaml
- compose.yml
- compose.yaml

Search conservatively:
1. current working directory
2. parent directories
3. Docker Compose metadata when available

Do not recursively scan the entire filesystem.

Parse port mappings such as:

"5432:5432"

"127.0.0.1:5432:5432"

"0.0.0.0:5432:5432"

Also handle protocol where practical.

Return:
- file
- line number
- raw evidence
- host IP
- host port
- container port
- protocol

If multiple possible configuration sources exist, return ambiguity instead of pretending certainty.

Add fixture-based tests.
```

---

# 37. Prompt 7 — The core `why`

```text
Implement the core Lantern command:

lantern why <port>

This is the most important v0.1 feature.

Pipeline:

port
 ↓
listener
 ↓
process
 ↓
Docker container if applicable
 ↓
published port
 ↓
bind address
 ↓
network interface
 ↓
Compose configuration
 ↓
reachability
 ↓
recommendation

Output sections:

SERVICE
EXPOSURE PATH
ROOT CAUSE
REACHABILITY
RECOMMENDED CHANGE

Example:

lantern why 5432

PostgreSQL :5432

EXPOSURE PATH

docker-compose.yml
       ↓
5432:5432
       ↓
Docker
       ↓
0.0.0.0:5432
       ↓
Wi-Fi interface
       ↓
LAN reachable

ROOT CAUSE
docker-compose.yml:18

RECOMMENDED CHANGE
127.0.0.1:5432:5432

Important:
Only claim ROOT CAUSE when the evidence supports it.
Otherwise use LIKELY SOURCE.

Do not modify files.
```

---

# 38. Prompt 8 — JSON output

```text
Implement machine-readable output.

Add:

lantern scan --json
lantern why 5432 --json

JSON must be stable and documented.

Do not mix human-readable progress messages into stdout when --json is used.

Errors should be represented predictably.

Add golden tests for representative JSON output.

Document the JSON schema in docs/.
```

---

# 39. Prompt 9 — Doctor

```text
Implement lantern doctor.

Check:

- operating system
- Linux environment
- ss availability if required
- Docker availability
- Docker daemon accessibility
- process inspection capability
- network interface discovery
- current user permissions

Output clear statuses:

✓ available
⚠ limited
✗ unavailable

Doctor must not attempt to repair anything.

Add tests for dependency detection logic.
```

---

# 40. Prompt 10 — Integration test lab

```text
Create a reproducible Lantern integration-test environment.

Create fixtures for:

1. localhost-only Docker port
2. wildcard Docker port
3. regular Linux process listener
4. missing Compose file
5. Docker unavailable

For Docker integration tests, use an explicit opt-in mechanism so normal:

go test ./...

does not require Docker.

Create documentation explaining how to run the integration suite.

The test must verify the complete chain:

listener
→ process/container
→ port mapping
→ bind address
→ Compose evidence
→ explanation
```

---

# 41. Prompt 11 — Security review

```text
Perform a security review of the current Lantern implementation.

Look specifically for:

- command injection
- shell injection
- unsafe command construction
- arbitrary file reads
- arbitrary file writes
- path traversal
- unsafe YAML handling
- leaking environment variables
- leaking secrets
- trusting unvalidated Docker output
- accidental network communication
- privilege escalation
- automatic execution of project commands

Do not change functionality.

Produce:
1. findings
2. severity
3. affected files
4. recommended fix

Only after presenting findings should fixes be implemented.
```

---

# 42. Prompt 12 — Final v0.1 polish

```text
Prepare Lantern for an initial public GitHub release.

Do not add new product features.

Review:
- CLI help
- error messages
- README
- installation instructions
- examples
- JSON output
- tests
- documentation
- license
- GitHub Actions
- version handling

README must immediately communicate:

Lantern
See exactly why your development machine exposes a service.

Show this example near the top:

lantern why 5432

Then show:
configuration
→ Docker
→ socket
→ interface
→ LAN reachability
→ suggested fix

Do not describe Lantern as a vulnerability scanner or Nmap replacement.

Run:
go test ./...
go vet ./...
go build ./...

Report anything that remains incomplete.
```

---

# 43. Antigravity operating rule

Do not let Antigravity continuously expand the scope.

After every major prompt:

```text
git diff
go test ./...
```

Review the result.

Then give it the next prompt.

Do not say:

```text
"Build Lantern completely."
```

That will encourage it to invent abstractions and implement future features prematurely.

The correct workflow is:

```text
Prompt
 ↓
Code
 ↓
Test
 ↓
Inspect diff
 ↓
Fix
 ↓
Commit
 ↓
Next prompt
```

---

# 44. First milestone

The first meaningful milestone is:

```bash
lantern scan
```

returning something like:

```text
Lantern v0.1.0

PORT     ADDRESS        PROCESS
22       0.0.0.0        sshd
3000     127.0.0.1      node
5432     0.0.0.0        docker-proxy
6379     0.0.0.0        docker-proxy
```

The second milestone is the important one:

```bash
lantern why 5432
```

returning a defensible chain:

```text
docker-compose.yml
        ↓
5432:5432
        ↓
postgres container
        ↓
0.0.0.0:5432
        ↓
LAN possible
```

**Do not move to `watch`, `diff`, AI, policies, automatic fixes, or a GUI until this works reliably.**

---

# 45. Definition of a successful v0.1

A developer should be able to run:

```bash
lantern why 5432
```

and understand within **10 seconds**:

1. What is listening?
2. What owns it?
3. Is Docker involved?
4. What address is it bound to?
5. Which interface makes it reachable?
6. Which configuration caused it?
7. What should they change?

If Lantern does those seven things reliably, **v0.1 has achieved its purpose.**