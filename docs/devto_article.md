---
title: Why Docker Silently Binds to 0.0.0.0 (And How to Trace Port Causality in Go)
published: true
description: Ever wondered why an internal database was accessible across your entire LAN? Here is how Docker port binding works under the hood and how we built Lantern to trace causality from open ports back to Compose files.
tags: docker, devops, golang, security
cover_image: 
canonical_url: https://github.com/DhyaanKanoja11/Lantern
---

If you've spent any time working with Docker or Docker Compose, chances are high that you've written something like this:

```yaml
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"
```

It looks completely harmless. You just wanted to connect your local GUI database client (DBeaver, TablePlus, pgAdmin) to PostgreSQL.

**Except you just exposed your database to your entire local network and every public interface on your machine.**

---

### The Silent Wildcard Footgun

When you declare `"5432:5432"` without an explicit host IP prefix, Docker defaults to binding to **`0.0.0.0`** (the wildcard address, in IPv4) and `::` (in IPv6).

That means:
- If your laptop is on a coffee shop or office Wi-Fi, anyone on that subnet can reach port 5432.
- If this runs on a cloud VM without a restrictive security group, port 5432 is open to the entire public internet.
- iptables rules are automatically modified by the Docker daemon to bypass standard host firewalls (like UFW) unless specially configured.

To bind exclusively to your local machine, you have to remember to explicitly write:
```yaml
ports:
  - "127.0.0.1:5432:5432"
```

Yet across millions of repositories and development stacks, developers constantly forget the `127.0.0.1:` prefix.

---

### The Causality Black Box: `ss` and `lsof` Don't Help

When you suspect an unexpected port is open and run standard Linux diagnostic commands:

```bash
$ sudo ss -tulpn | grep 5432
tcp   LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("docker-proxy",pid=14205,fd=4))
```

All you see is `docker-proxy`.

- You don't know which container owns it.
- You don't know which `docker-compose.yml` file declared it.
- You don't know whether it was intended as public or an accidental wildcard binding.
- If you have 30 containers running across 5 microservices, you are left manually running `docker inspect` across every container or grepping your codebase.

---

### Building Lantern: Tracing Configuration Causality

To solve this visibility gap, we built [Lantern](https://github.com/DhyaanKanoja11/Lantern), an open-source, local-first CLI written in Go.

Instead of merely listing sockets, Lantern traverses the full causality graph:

```
[ Listening Socket ]
        ↓
[ OS Process / docker-proxy ]
        ↓
[ Docker Container ]
        ↓
[ Docker Compose Service & Source YAML Line ]
        ↓
[ Reachability Verdict (PUBLIC / LOCALHOST / DOCKER) ]
```

#### 1. Instant Reachability Audit (`lantern scan`)

Running `lantern scan` audits all listening TCP sockets and classifies their exposure:

```bash
$ lantern scan
PORT    PROTO   BIND ADDRESS    REACHABILITY   PROCESS         CONTAINER / SOURCE
5432    tcp     0.0.0.0         PUBLIC         docker-proxy    my-project-db-1 (docker-compose.yml:8)
8080    tcp     127.0.0.1       LOCALHOST      node            api-gateway
```

Any wildcard binding (`0.0.0.0` or `::`) is immediately flagged with a high-contrast **PUBLIC** warning.

#### 2. Root Cause Explanation (`lantern why <port>`)

If you want to know *why* a port is open, Lantern produces the exact causal chain:

```bash
$ lantern why 5432
Port 5432 (tcp) is bound to 0.0.0.0 (PUBLIC)
├─ Process: docker-proxy (PID 14205)
├─ Container: my-project-db-1 (ID 8a1b2c3d4e5f)
├─ Compose Service: db
└─ Defined in: /home/dev/projects/api/docker-compose.yml:8
   Recommendation: Change '5432:5432' to '127.0.0.1:5432:5432' to restrict access to localhost.
```

#### 3. Real-Time Terminal Watch Mode (`lantern scan -w`)

Developers frequently start and stop containers. With `-w, --watch`:
```bash
lantern scan -w --interval 2s
```
Lantern renders a live terminal dashboard that sounds an `[ALERT]` the moment a new wildcard exposure occurs.

---

### Enforcing Guardrails in CI/CD

Catching exposure on developer laptops is great, but preventing it from merging into production repositories is critical.

We built two native CI mechanisms into Lantern:

#### 1. Zero-Exit Flag
```bash
lantern scan --fail-on-wildcard --ignore-ports 80,443
```
If any container or process binds to `0.0.0.0` on a port other than 80 or 443, the command exits with code `1` and emits native GitHub Actions error annotations (`::error::`).

#### 2. Official GitHub Action
You can drop Lantern into any repository workflow with 2 lines:

```yaml
name: Security Audit
on: [pull_request, push]

jobs:
  port-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Spin up test environment
        run: docker compose up -d
      - name: Audit Port Exposures
        uses: DhyaanKanoja11/lantern-action@v1
        with:
          fail-on-wildcard: 'true'
          ignore-ports: '80,443'
```

It automatically formats a rich Markdown report on your GitHub Actions Step Summary page.

---

### How to Try It

Lantern has zero runtime dependencies and is distributed across major package managers:

```bash
# macOS / Linux (Homebrew)
brew tap DhyaanKanoja11/tap
brew install lantern

# Windows (Scoop)
scoop bucket add dhyaan https://github.com/DhyaanKanoja11/scoop-bucket
scoop install lantern

# Go toolchain
go install github.com/DhyaanKanoja11/Lantern/cmd/lantern@latest
```

---

### Open Source & Getting Involved

The entire project is MIT-licensed and built with standard library principles in Go:
- GitHub Repository: [https://github.com/DhyaanKanoja11/Lantern](https://github.com/DhyaanKanoja11/Lantern)
- GitHub Action: [https://github.com/DhyaanKanoja11/lantern-action](https://github.com/DhyaanKanoja11/lantern-action)

If you've ever had a container expose an unexpected port, give `lantern scan` a run and let us know what you think!
