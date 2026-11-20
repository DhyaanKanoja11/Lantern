# Lantern External Tester Programme

Welcome to the Lantern External Tester Programme!

Lantern is an open-source, local-first security CLI that traces exposed development ports back to the exact line in your `docker-compose.yml` and provides safe, deterministic localhost remediation.

We are actively gathering structured feedback from our first cohort of **10–20 external developers** (Docker Compose users, Linux developers, self-hosters, and DevOps engineers) to evaluate real-world usability, installation friction, and diagnostic clarity.

---

## How to Participate (10-Minute Walkthrough)

Participation requires **zero registration** and **no personal information**. All feedback is tracked publicly via GitHub.

### Step 1: Install Lantern

Choose your preferred installation method:

**Option A (Shell Installer — Linux/macOS):**
```bash
curl -fsSL https://raw.githubusercontent.com/DhyaanKanoja11/Lantern/main/install.sh | bash
```

**Option B (Pre-compiled Binary):**
Download the appropriate archive for your architecture from [GitHub Releases](https://github.com/DhyaanKanoja11/Lantern/releases/tag/v0.2.1) and place the `lantern` executable in your `$PATH`.

**Option C (Go Install — Go 1.22+):**
```bash
go install github.com/DhyaanKanoja11/Lantern/cmd/lantern@latest
```

---

### Step 2: Validate Environment Prerequisites

Run the diagnostic probe:
```bash
lantern doctor
```
Verify that the host OS, `/proc` filesystem, socket inspection, and Docker daemon probes report operational status.

---

### Step 3: Run a Diagnostic Workflow

1. Start any existing Docker Compose project or run the bundled example:
   ```bash
   git clone https://github.com/DhyaanKanoja11/Lantern.git
   cd Lantern/examples
   docker compose up -d
   ```
2. Scan for exposed listening ports:
   ```bash
   lantern scan
   ```
3. Trace the root cause of an exposed port (e.g. 5432):
   ```bash
   lantern why 5432
   ```
4. Preview safe remediation without touching your files:
   ```bash
   lantern fix 5432 --dry-run
   ```

---

### Step 4: Submit Your Feedback

Open a new issue using our structured [Tester Feedback Template](https://github.com/DhyaanKanoja11/Lantern/issues/new?template=tester_feedback.md).

Key evaluation questions:
1. **Installation Friction**: Did the binary install smoothly into your `$PATH`?
2. **First-Command Clarity**: Did `lantern scan` and `lantern doctor` produce obvious, actionable results?
3. **Causal Explanation**: Did `lantern why <port>` clearly trace to the container and Compose line?
4. **Remediation Safety**: Did `--dry-run` give you full confidence in what would change?
5. **Drop-Off Reasons**: What, if anything, would prevent you from keeping Lantern installed?

Thank you for helping build a safer, more transparent developer workflow!
