package domain

// NetworkInterface represents a host network interface.
type NetworkInterface struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	CIDR       string `json:"cidr"`
	Kind       string `json:"kind"` // "LOOPBACK", "LAN", "VPN", "OTHER"
	IsLoopback bool   `json:"is_loopback"`
}
