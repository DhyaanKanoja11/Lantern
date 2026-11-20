---
name: Tester Feedback
about: Provide feedback as part of the Lantern External Tester Programme
title: "[TESTER] "
labels: tester-feedback
assignees: ''
---

## 1. Environment Details
Please run `lantern doctor` and paste the diagnostic summary below:

```text
lantern doctor output here
```

- **OS / Distribution**: (e.g. Ubuntu 22.04 LTS, Arch Linux, WSL2 on Windows 11, macOS Sequoia)
- **Kernel Version**: `uname -r`
- **Docker / Compose Version**: `docker compose version`
- **Installation Method Used**:
  - [ ] Shell installer (`curl -fsSL ... | bash`)
  - [ ] Pre-compiled binary from GitHub Releases
  - [ ] `go install github.com/DhyaanKanoja11/Lantern/cmd/lantern@latest`
  - [ ] Built from source

---

## 2. Installation & First-Run Experience
- Did the installation succeed without manual path or permission adjustments? If not, what happened?
- Was `lantern doctor` easy to understand? Did any probe fail unexpectedly?

---

## 3. Diagnostic & Causality Workflow
- What command(s) did you test? (`lantern scan`, `lantern why <port>`, `lantern fix <port> --dry-run`)
- Did the `EXPOSURE PATH` and `ROOT CAUSE` clearly explain why the service was reachable?
- Was the distinction between loopback (`127.0.0.1`) and wildcard (`0.0.0.0`) clear?

---

## 4. Remediation Confidence (`lantern fix`)
- Did you test `lantern fix <port> --dry-run`?
- Did the proposed diff match your expectation for how the Compose file should be updated?
- Did you feel confident in the backup and fail-closed safety guarantees, or did anything feel risky?

---

## 5. Friction & Improvement Suggestions
- What was the most confusing or frustrating part of using Lantern?
- What single improvement or feature would make you keep Lantern installed for daily development?
