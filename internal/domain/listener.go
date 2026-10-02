package domain

// Listener represents a bound TCP listening socket.
type Listener struct {
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        uint16 `json:"port"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}
