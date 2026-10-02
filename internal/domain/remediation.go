package domain

// RemediationStatus categorizes whether an exposure can be automatically remediated.
type RemediationStatus string

const (
	// RemediationSupported indicates the exposure has a verified, deterministic, automatic fix.
	RemediationSupported RemediationStatus = "SUPPORTED"
	// RemediationUnsupported indicates automatic remediation is not supported for this exposure type.
	RemediationUnsupported RemediationStatus = "UNSUPPORTED"
	// RemediationUnsafe indicates evidence is uncertain, ambiguous, or the target file cannot be safely verified.
	RemediationUnsafe RemediationStatus = "UNSAFE"
)

// FileFingerprint captures the identity and cryptographic hash of a file at analysis time.
type FileFingerprint struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Remediation encapsulates the planned or executed remediation for an exposed port.
type Remediation struct {
	Status      RemediationStatus `json:"status"`
	Type        string            `json:"type"` // e.g. "bind_localhost"
	File        string            `json:"file,omitempty"`
	Line        int               `json:"line,omitempty"`
	Service     string            `json:"service,omitempty"`
	Before      string            `json:"before"`
	After       string            `json:"after"`
	Reason      string            `json:"reason"`
	BackupPath  string            `json:"backup_path,omitempty"`
	Fingerprint *FileFingerprint  `json:"fingerprint,omitempty"`
}

// FixResult represents the outcome of applying a remediation.
type FixResult struct {
	Success      bool         `json:"success"`
	Remediation  *Remediation `json:"remediation"`
	BeforeState  string       `json:"before_state"` // e.g. "0.0.0.0:5432 (LAN reachable)"
	AfterState   string       `json:"after_state"`  // e.g. "127.0.0.1:5432 (Local machine only)"
	BackupPath   string       `json:"backup_path"`
	ErrorMessage string       `json:"error_message,omitempty"`
}
