package domain

// Process represents OS process information discovered for a listener.
type Process struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Executable  string `json:"executable,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	User        string `json:"user,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
}
