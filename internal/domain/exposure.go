package domain

// Exposure is the aggregate root explaining why a port is reachable.
type Exposure struct {
	Port           uint16             `json:"port"`
	Protocol       string             `json:"protocol"`
	BindAddress    string             `json:"bind_address"`
	Listener       Listener           `json:"listener"`
	Process        *Process           `json:"process,omitempty"`
	Container      *Container         `json:"container,omitempty"`
	DockerMapping  *PortMapping       `json:"docker_mapping,omitempty"`
	Config         *ConfigEvidence    `json:"config,omitempty"`
	Interfaces     []NetworkInterface `json:"interfaces,omitempty"`
	Reachability   Reachability       `json:"reachability"`
	Recommendation *Recommendation    `json:"recommendation,omitempty"`
	Warnings       []string           `json:"warnings,omitempty"`
}

// ExposureSummary represents a single line in `lantern scan`.
type ExposureSummary struct {
	Port          uint16 `json:"port"`
	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	ProcessName   string `json:"process_name"`
	PID           int    `json:"pid,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
}
