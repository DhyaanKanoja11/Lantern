package remediation

import (
	"context"
	"fmt"
	"os"
	"strings"

	"lantern/internal/compose"
	"lantern/internal/domain"
)

// Remediator defines the contract for planning and executing safe automated remediations.
type Remediator interface {
	Plan(ctx context.Context, exp *domain.Exposure) (*domain.Remediation, error)
	Apply(ctx context.Context, plan *domain.Remediation) (*domain.FixResult, error)
}

// DefaultRemediator implements the Remediator contract for Lantern.
type DefaultRemediator struct{}

// NewDefaultRemediator returns a new DefaultRemediator instance.
func NewDefaultRemediator() *DefaultRemediator {
	return &DefaultRemediator{}
}

// Plan computes a validated remediation plan for the given exposure.
func (r *DefaultRemediator) Plan(ctx context.Context, exp *domain.Exposure) (*domain.Remediation, error) {
	plan := Plan(exp)
	return plan, nil
}

// Apply executes a supported remediation plan with pre-modification backup and atomic writing.
func (r *DefaultRemediator) Apply(ctx context.Context, plan *domain.Remediation) (*domain.FixResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("cannot apply nil remediation plan")
	}

	// 1. TOCTOU Protection: Verify file fingerprint immediately before modification and before backup!
	if plan.Fingerprint == nil {
		return nil, fmt.Errorf("cannot apply remediation: plan has no recorded file fingerprint")
	}

	if err := VerifyFingerprint(plan.File, plan.Fingerprint); err != nil {
		return nil, err
	}

	fi, err := os.Stat(plan.File)
	if err != nil {
		return nil, fmt.Errorf("target file not found: %w", err)
	}

	// 2. File verified unchanged -> create byte-verified backup
	backupPath, err := CreateBackup(plan.File)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup before modification: %w", err)
	}

	// 2. Compute exact AST-guided modified bytes
	modifiedBytes, err := ApplyComposeFix(plan.File, plan.Service, plan.Line, 0, plan.After)
	if err != nil {
		return nil, fmt.Errorf("failed to compute safe modification: %w", err)
	}

	// 3. Atomically write to target file
	if err := AtomicWrite(plan.File, modifiedBytes, fi.Mode().Perm()); err != nil {
		return nil, fmt.Errorf("failed to atomically write modification: %w", err)
	}

	// 4. Post-fix verification on disk
	verifyBytes, err := os.ReadFile(plan.File)
	if err != nil {
		return &domain.FixResult{
			Success:      false,
			Remediation:  plan,
			BackupPath:   backupPath,
			ErrorMessage: fmt.Sprintf("post-fix verification failed: cannot read %s: %v", plan.File, err),
		}, nil
	}

	evidenceList, err := compose.ParseComposeFile(plan.File, verifyBytes)
	if err != nil {
		return &domain.FixResult{
			Success:      false,
			Remediation:  plan,
			BackupPath:   backupPath,
			ErrorMessage: fmt.Sprintf("post-fix verification failed: modified file has invalid Compose syntax: %v", err),
		}, nil
	}

	verified := false
	for _, ev := range evidenceList {
		if ev.Service == plan.Service && ev.Line == plan.Line {
			cleanIP := strings.Trim(strings.TrimSpace(ev.Port.HostIP), "[]")
			if cleanIP == "127.0.0.1" {
				verified = true
				break
			}
		}
	}

	if !verified {
		return &domain.FixResult{
			Success:      false,
			Remediation:  plan,
			BackupPath:   backupPath,
			ErrorMessage: "post-fix verification failed: target port on disk does not reflect localhost binding",
		}, nil
	}

	beforeDesc := plan.Before
	afterDesc := plan.After

	return &domain.FixResult{
		Success:     true,
		Remediation: plan,
		BeforeState: fmt.Sprintf("%s\n    LAN reachable", beforeDesc),
		AfterState:  fmt.Sprintf("%s\n    Local machine only", afterDesc),
		BackupPath:  backupPath,
	}, nil
}
