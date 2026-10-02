package domain

// ConfigEvidence represents configuration attribution for an exposed port.
type ConfigEvidence struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	Evidence      string `json:"evidence"`
	Kind          string `json:"kind"`    // e.g. "compose"
	Certain       bool   `json:"certain"` // true = ROOT CAUSE, false = LIKELY SOURCE
	Service       string `json:"service,omitempty"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Original      string `json:"original,omitempty"`
}
