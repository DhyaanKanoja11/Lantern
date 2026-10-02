package docker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"lantern/internal/domain"
)

// rawContainer represents the JSON schema returned by `docker inspect`.
type rawContainer struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Pid     int    `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]struct{} `json:"Networks"`
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// ParseContainerIDs extracts container IDs from `docker ps -q` output.
func ParseContainerIDs(output []byte) []string {
	var ids []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// ParseInspectOutput parses the JSON output of `docker inspect`.
// If one container is malformed, valid containers are preserved.
func ParseInspectOutput(output []byte) ([]domain.Container, error) {
	data := bytes.TrimSpace(output)
	if len(data) == 0 {
		return nil, nil
	}

	var rawMessages []json.RawMessage
	if err := json.Unmarshal(data, &rawMessages); err != nil {
		// Attempt single object unmarshal if not an array
		var single rawContainer
		if errSingle := json.Unmarshal(data, &single); errSingle == nil {
			c, errConv := convertRawContainer(&single)
			if errConv != nil {
				return nil, errConv
			}
			return []domain.Container{*c}, nil
		}
		return nil, fmt.Errorf("malformed docker inspect JSON: %w", err)
	}

	var containers []domain.Container
	for _, rawMsg := range rawMessages {
		var raw rawContainer
		if err := json.Unmarshal(rawMsg, &raw); err != nil {
			// Skip malformed container object without discarding valid containers
			continue
		}
		c, err := convertRawContainer(&raw)
		if err != nil {
			continue
		}
		containers = append(containers, *c)
	}

	return containers, nil
}

// convertRawContainer converts an inspect JSON struct into a domain.Container.
func convertRawContainer(raw *rawContainer) (*domain.Container, error) {
	if raw.ID == "" {
		return nil, fmt.Errorf("missing container ID")
	}

	c := &domain.Container{
		ID:      raw.ID,
		Name:    strings.TrimPrefix(raw.Name, "/"),
		Image:   raw.Config.Image,
		Running: raw.State.Running,
		HostPID: raw.State.Pid,
		Labels:  raw.Config.Labels,
	}

	if len(raw.NetworkSettings.Networks) > 0 {
		for netName := range raw.NetworkSettings.Networks {
			c.Networks = append(c.Networks, netName)
		}
		sort.Strings(c.Networks)
	}

	if len(raw.NetworkSettings.Ports) > 0 {
		for portSpec, bindings := range raw.NetworkSettings.Ports {
			if len(bindings) == 0 {
				continue
			}

			parts := strings.Split(portSpec, "/")
			if len(parts) != 2 {
				continue
			}

			cPort, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil || cPort == 0 {
				continue
			}
			proto := strings.ToLower(parts[1])

			for _, b := range bindings {
				hPort, err := strconv.ParseUint(b.HostPort, 10, 16)
				if err != nil || hPort == 0 {
					continue
				}

				hostIP := strings.TrimSpace(b.HostIP)
				if hostIP == "" {
					hostIP = "0.0.0.0"
				} else if ip := net.ParseIP(hostIP); ip != nil {
					if v4 := ip.To4(); v4 != nil {
						hostIP = v4.String()
					} else {
						hostIP = ip.String()
					}
				}

				c.Ports = append(c.Ports, domain.PortMapping{
					HostIP:        hostIP,
					HostPort:      uint16(hPort),
					ContainerPort: uint16(cPort),
					Protocol:      proto,
				})
			}
		}

		sort.Slice(c.Ports, func(i, j int) bool {
			if c.Ports[i].HostPort != c.Ports[j].HostPort {
				return c.Ports[i].HostPort < c.Ports[j].HostPort
			}
			return c.Ports[i].ContainerPort < c.Ports[j].ContainerPort
		})
	}

	return c, nil
}
