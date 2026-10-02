package domain

// Recommendation represents a deterministic remediation recommendation.
type Recommendation struct {
	Type        string `json:"type"`      // e.g. "bind_localhost"
	Current     string `json:"current"`   // e.g. "0.0.0.0:5432"
	Suggested   string `json:"suggested"` // e.g. "127.0.0.1:5432:5432"
	Description string `json:"description,omitempty"`
}
