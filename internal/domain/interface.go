package domain

// NetworkInterface represents a host network interface.
type NetworkInterface struct {
	Index      int    `json:"index,omitempty"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	CIDR       string `json:"cidr,omitempty"`
	Kind       string `json:"kind"` // "LOOPBACK", "LAN", "VPN", "OTHER"
	IsLoopback bool   `json:"is_loopback"`
	IsUp       bool   `json:"is_up"`
}
