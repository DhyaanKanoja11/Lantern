package network

import (
	"context"
	"net"
	"strings"

	"lantern/internal/domain"
)

// InterfaceProvider abstracts host network interface enumeration.
type InterfaceProvider interface {
	Interfaces(ctx context.Context) ([]domain.NetworkInterface, error)
}

// SystemInterfaceProvider uses Go standard library net.Interfaces to discover local adapters.
type SystemInterfaceProvider struct{}

// Interfaces enumerates active network interfaces using net.Interfaces().
func (p *SystemInterfaceProvider) Interfaces(ctx context.Context) ([]domain.NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []domain.NetworkInterface

	for _, iface := range ifaces {
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		isUp := (iface.Flags & net.FlagUp) != 0

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			var mask net.IPMask

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				mask = v.Mask
			case *net.IPAddr:
				ip = v.IP
				mask = ip.DefaultMask()
			}

			if ip == nil {
				continue
			}

			// Format normalized IP string
			var ipStr string
			if v4 := ip.To4(); v4 != nil {
				ipStr = v4.String()
			} else {
				ipStr = ip.String()
			}

			cidr := ""
			if mask != nil {
				ones, _ := mask.Size()
				cidr = ipStr + "/" + strings.TrimPrefix(addr.String(), ip.String()+"/")
				if !strings.Contains(cidr, "/") {
					cidr = ipStr
				}
				_ = ones
			} else {
				cidr = addr.String()
			}

			kind := ClassifyIP(ip, iface.Name, isLoopback)

			result = append(result, domain.NetworkInterface{
				Index:      iface.Index,
				Name:       iface.Name,
				IP:         ipStr,
				CIDR:       addr.String(),
				Kind:       kind,
				IsLoopback: isLoopback,
				IsUp:       isUp,
			})
		}
	}

	return result, nil
}

// Classifier coordinates interface discovery and reachability classification.
type Classifier struct {
	provider InterfaceProvider
}

// NewDefaultClassifier creates a Classifier using the host's actual network interfaces.
func NewDefaultClassifier() *Classifier {
	return NewClassifierWithProvider(&SystemInterfaceProvider{})
}

// NewClassifierWithProvider creates a Classifier with a custom or mocked InterfaceProvider.
func NewClassifierWithProvider(provider InterfaceProvider) *Classifier {
	return &Classifier{provider: provider}
}

// DiscoverInterfaces queries the provider for all available network interfaces.
func (c *Classifier) DiscoverInterfaces(ctx context.Context) ([]domain.NetworkInterface, error) {
	return c.provider.Interfaces(ctx)
}

// ClassifyReachability evaluates reachability for a given bind address and interface list.
func (c *Classifier) ClassifyReachability(bindAddr string, ifaces []domain.NetworkInterface) domain.Reachability {
	reach, _ := EvaluateReachability(bindAddr, ifaces)
	return reach
}

// Assess returns reachability and the slice of relevant interfaces for a bind address.
func (c *Classifier) Assess(ctx context.Context, bindAddr string) (domain.Reachability, []domain.NetworkInterface, error) {
	ifaces, err := c.DiscoverInterfaces(ctx)
	if err != nil {
		return domain.Reachability{
			Local:    false,
			LAN:      "no",
			Internet: "unknown",
			State:    StateUnresolved,
		}, nil, err
	}

	reach, relevant := EvaluateReachability(bindAddr, ifaces)
	return reach, relevant, nil
}
