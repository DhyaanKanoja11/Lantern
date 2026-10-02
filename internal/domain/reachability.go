package domain

// Reachability represents the estimated reachability of a service.
type Reachability struct {
	Local    bool   `json:"local"`    // true if reachable on localhost
	LAN      string `json:"lan"`      // "no", "possible", "yes"
	Internet string `json:"internet"` // "unknown"
}
