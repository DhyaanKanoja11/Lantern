# Security Policy

## Supported Versions

We provide security updates and bug fixes for the following versions:

| Version | Supported          |
| :------ | :----------------- |
| v0.1.x  | :white_check_mark: |
| < v0.1  | :x:                |

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in Lantern, please report it responsibly. **Do not disclose security vulnerabilities through public GitHub issues.**

### Reporting Method

1. If enabled on the repository, please use [GitHub Private Vulnerability Reporting](https://github.com/DhyaanKanoja11/Lantern/security/advisories) by clicking **"Report a vulnerability"**.
2. Alternatively, reach out privately to the maintainer through GitHub ([@DhyaanKanoja11](https://github.com/DhyaanKanoja11)).

### What to Include

To help us triage and resolve the issue quickly, please provide:
- A clear description of the vulnerability.
- Steps to reproduce or a minimal proof-of-concept.
- The operating system and kernel version (including WSL2 details if applicable).
- Expected impact and any suggested mitigations.

### Response Timeline

- **Acknowledgment**: Within 48 hours of receipt.
- **Assessment**: We will verify the issue and provide an estimated fix timeline.
- **Fix & Disclosure**: A patched release will be tagged, followed by a public advisory crediting the reporter (if desired).

---

## Scope & Security Model

Lantern is designed with a defense-in-depth safety model:

- **Local Privileges**: Lantern executes under standard user privileges and never requests or requires root/admin escalation.
- **Fail-Closed Remediation**: The automated fix engine (`lantern fix`) enforces cryptographic SHA-256 fingerprinting (TOCTOU protection), byte-verified backups, and atomic writes.
- **Zero Outbound Traffic**: Lantern performs zero network requests, telemetry, or external communication.

Security issues of high priority include:
- Remediation race conditions or TOCTOU bypasses.
- Unbounded directory traversal during configuration discovery.
- File corruption or accidental overwrite of non-target configuration lines.
- Unsafe file permissions on created backup or temporary files.

*(Note: Lantern is an analysis and safe remediation tool for local development services; it is not a substitute for complete system-level host firewalls or endpoint security).*
