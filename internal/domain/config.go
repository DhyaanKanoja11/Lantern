package domain

// ConfigEvidence represents configuration attribution for an exposed port.
type ConfigEvidence struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Evidence string `json:"evidence"`
	Kind     string `json:"kind"`    // e.g. "compose"
	Certain  bool   `json:"certain"` // true = ROOT CAUSE, false = LIKELY SOURCE
}
