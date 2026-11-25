package collector

import (
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestMostExposed(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  string
	}{
		{"loopback first, LAN second", []string{"127.0.0.1", "192.168.1.20"}, "192.168.1.20"},
		{"loopback and v6 wildcard", []string{"127.0.0.1", "::"}, "::"},
		{"v6 loopback and v4 LAN", []string{"::1", "10.0.0.5"}, "10.0.0.5"},
		{"specific and wildcard", []string{"192.168.1.20", "0.0.0.0"}, "0.0.0.0"},
		{"both wildcards keeps first", []string{"0.0.0.0", "::"}, "0.0.0.0"},
		{"only loopback", []string{"127.0.0.1", "::1"}, "127.0.0.1"},
		{"single", []string{"127.0.0.1"}, "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ls []domain.Listener
			for _, a := range tc.addrs {
				ls = append(ls, domain.Listener{Address: a, Port: 8080, Protocol: "tcp"})
			}
			if got := MostExposed(ls).Address; got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
