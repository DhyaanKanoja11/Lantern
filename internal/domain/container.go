package domain

// PortMapping represents a container port published to the host.
type PortMapping struct {
	HostIP        string `json:"host_ip"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Container represents container information correlated with a listener.
type Container struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Ports    []PortMapping     `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Networks []string          `json:"networks,omitempty"`
}
