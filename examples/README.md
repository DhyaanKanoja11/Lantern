# Lantern Quick Test Drive

This directory contains a deliberately exposed demo Docker Compose environment (`5432:5432`) to demonstrate Lantern's causal explanation and safe remediation capabilities.

> **Note:** This configuration intentionally binds port 5432 to `0.0.0.0` for demonstration purposes only. Do not use wildcard port bindings in production environments.

---

## 1. Start the Demo Service

```bash
docker compose up -d
```

## 2. Check Prerequisites

```bash
lantern doctor
```

## 3. Discover Active Listeners

```bash
lantern scan
```

You should see port `5432` bound to `0.0.0.0` classified as `LAN reachable`.

## 4. Trace the Exposure Root Cause

```bash
lantern why 5432
```

Lantern traces the complete exposure path:
- Pinpoints `docker-compose.yml:5` as the exact declaration.
- Identifies the Docker container (`db`).
- Classifies host network interfaces and reachability.
- Suggests binding to `127.0.0.1:5432:5432`.

## 5. Preview Safe Remediation (Zero Writes)

```bash
lantern fix 5432 --dry-run
```

Performs complete analysis and previews the exact before/after YAML modification with zero filesystem writes.

## 6. Apply Supported Remediation

```bash
lantern fix 5432
```

Requires explicit interactive confirmation (`[y/N]`). When confirmed:
1. Re-verifies file SHA-256 fingerprint (TOCTOU protection).
2. Creates a byte-verified backup (`docker-compose.yml.lantern.bak`).
3. Atomically updates the port mapping to `127.0.0.1:5432:5432`.
4. Re-reads and verifies the configuration on disk.

*(Note: Lantern's remediation engine is strictly limited to supported, deterministic Docker Compose port bindings; it never attempts arbitrary or heuristic system modifications).*

## 7. Cleanup

```bash
docker compose down
```
