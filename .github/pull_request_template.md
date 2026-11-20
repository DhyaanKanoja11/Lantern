## Description
<!-- Provide a clear, concise summary of the changes introduced in this pull request. -->

## Motivation & Context
<!-- Why is this change required? What issue does it fix, or what capability does it add? -->
<!-- If fixing an existing issue, link it here: e.g. Fixes #123 -->

## Architectural Alignment
<!-- Confirm adherence to Lantern's core engineering principles: -->
- [ ] **Domain Purity**: `internal/domain` contains zero external dependencies or OS syscalls.
- [ ] **Fail-Closed Safety**: Any ambiguity, file modification, or verification mismatch halts without touching user files.
- [ ] **Zero Telemetry**: Performs zero outbound network requests or background processing.
- [ ] **Platform Isolation**: Platform-specific logic is guarded by Go build tags (`//go:build linux`).

## Testing & Verification
<!-- Describe the tests executed to verify these changes. -->
- [ ] Unit tests pass: `go test -count=1 ./...`
- [ ] Race detector clean: `go test -race ./...`
- [ ] Static analysis clean: `go vet ./...`
- [ ] Formatting verified: `gofmt -s -l .`
- [ ] Multi-platform compilation passes (`linux/amd64`, `linux/arm64`, `windows/amd64`, `darwin/arm64`).

## Checklist
- [ ] My code follows the code style and conventions of this project.
- [ ] I have updated relevant documentation (`README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`).
- [ ] If changing CLI behavior, I have included updated tests and output assertions.
- [ ] No unnecessary third-party dependencies have been introduced.
