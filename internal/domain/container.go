package domain

// AttributionMode represents the evidence tier of container correlation.
type AttributionMode string

const (
	// AttributionDirect indicates socket ownership was verified via PID or docker-proxy process.
	AttributionDirect AttributionMode = "DIRECT"
	// AttributionInferred indicates correlation was established via published port matching for an unprivileged listener.
	AttributionInferred AttributionMode = "INFERRED"
)

// PortMapping represents a container port published to the host.
type PortMapping struct {
	HostIP        string `json:"host_ip"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Container represents container information correlated with a listener.
type Container struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Running         bool              `json:"running,omitempty"`
	HostPID         int               `json:"host_pid,omitempty"`
	Ports           []PortMapping     `json:"ports,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Networks        []string          `json:"networks,omitempty"`
	AttributionMode AttributionMode   `json:"attribution_mode,omitempty"`
}
