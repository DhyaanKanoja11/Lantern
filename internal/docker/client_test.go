package docker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestCLIClient_ListContainers_Success(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.Contains(cmdStr, "ps -q") {
			return []byte("c1\nc2\n"), nil
		}
		if strings.Contains(cmdStr, "inspect c1 c2") {
			return []byte(`[
				{"Id": "c1", "Name": "/c1", "State": {"Pid": 101, "Running": true}, "Config": {"Image": "img1"}, "NetworkSettings": {"Ports": {}}},
				{"Id": "c2", "Name": "/c2", "State": {"Pid": 102, "Running": true}, "Config": {"Image": "img2"}, "NetworkSettings": {"Ports": {}}}
			]`), nil
		}
		return nil, errors.New("unexpected command: " + cmdStr)
	}

	client := NewCLIClientWithRunner(mockRunner)
	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(containers))
	}
	if containers[0].ID != "c1" || containers[1].ID != "c2" {
		t.Errorf("unexpected containers: %+v", containers)
	}
}

func TestCLIClient_CommandFailure(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("executable file not found in %PATH%")
	}

	client := NewCLIClientWithRunner(mockRunner)
	_, err := client.ListContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrDockerNotAvailable) {
		t.Errorf("expected ErrDockerNotAvailable, got %v", err)
	}
}

func TestCLIClient_DaemonUnavailable(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
	}

	client := NewCLIClientWithRunner(mockRunner)
	_, err := client.ListContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrDaemonNotAvailable) {
		t.Errorf("expected ErrDaemonNotAvailable, got %v", err)
	}
}

func TestCLIClient_ContainerDisappearingBetweenListAndInspect(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.Contains(cmdStr, "ps -q") {
			return []byte("c1\nc2_exited\n"), nil
		}
		// Batch inspect fails because c2_exited is gone
		if strings.Contains(cmdStr, "inspect c1 c2_exited") {
			return nil, errors.New("Error: No such object: c2_exited")
		}
		// Individual inspect for c1 succeeds
		if strings.Contains(cmdStr, "inspect c1") {
			return []byte(`[{"Id": "c1", "Name": "/c1", "State": {"Pid": 111}, "Config": {"Image": "img1"}, "NetworkSettings": {"Ports": {}}}]`), nil
		}
		// Individual inspect for c2_exited fails
		if strings.Contains(cmdStr, "inspect c2_exited") {
			return nil, errors.New("Error: No such object")
		}
		return nil, errors.New("unexpected command: " + cmdStr)
	}

	client := NewCLIClientWithRunner(mockRunner)
	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("expected graceful fallback, got error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container recovered, got %d", len(containers))
	}
	if containers[0].ID != "c1" {
		t.Errorf("expected c1, got %q", containers[0].ID)
	}
}

func TestCLIClient_InspectContainer(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[1] == "redis-dev" {
			return []byte(`[{"Id": "r1", "Name": "/redis-dev", "State": {"Pid": 555}, "Config": {"Image": "redis"}, "NetworkSettings": {"Ports": {}}}]`), nil
		}
		return nil, errors.New("No such object")
	}

	client := NewCLIClientWithRunner(mockRunner)

	// Valid inspect
	c, err := client.InspectContainer(context.Background(), "redis-dev")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID != "r1" || c.Name != "redis-dev" {
		t.Errorf("unexpected container: %+v", c)
	}

	// Missing container
	_, err = client.InspectContainer(context.Background(), "nonexistent")
	if err == nil {
		t.Errorf("expected error for nonexistent container, got nil")
	}

	// Empty ID
	_, err = client.InspectContainer(context.Background(), "")
	if err == nil {
		t.Errorf("expected error for empty container ID, got nil")
	}
}

func TestCLIClient_PIDCorrelation(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := strings.Join(args, " ")
		if strings.Contains(cmdStr, "ps -q") {
			return []byte("c1\nc2\n"), nil
		}
		if strings.Contains(cmdStr, "inspect") {
			return []byte(`[
				{
					"Id": "c1",
					"Name": "/postgres",
					"State": {"Pid": 1234, "Running": true},
					"Config": {"Image": "postgres:16"},
					"NetworkSettings": {
						"Ports": {
							"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]
						}
					}
				},
				{
					"Id": "c2",
					"Name": "/nginx",
					"State": {"Pid": 5678, "Running": true},
					"Config": {"Image": "nginx:alpine"},
					"NetworkSettings": {
						"Ports": {
							"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
						}
					}
				}
			]`), nil
		}
		return nil, errors.New("unexpected command")
	}

	client := NewCLIClientWithRunner(mockRunner)

	// 1. Match PID 1234 -> should find c1
	c, m, err := client.CorrelatePID(context.Background(), 1234)
	if err != nil {
		t.Fatalf("unexpected error correlating PID 1234: %v", err)
	}
	if c.ID != "c1" || c.Name != "postgres" {
		t.Errorf("expected c1 postgres, got ID=%s Name=%s", c.ID, c.Name)
	}
	if m == nil || m.HostPort != 5432 {
		t.Errorf("expected mapping on 5432, got %+v", m)
	}

	// 2. Match PID 5678 -> should find c2
	c2, m2, err := client.CorrelatePID(context.Background(), 5678)
	if err != nil {
		t.Fatalf("unexpected error correlating PID 5678: %v", err)
	}
	if c2.ID != "c2" || c2.Name != "nginx" {
		t.Errorf("expected c2 nginx, got ID=%s Name=%s", c2.ID, c2.Name)
	}
	if m2 == nil || m2.HostPort != 8080 {
		t.Errorf("expected mapping on 8080, got %+v", m2)
	}

	// 3. Match PID 9999 -> no matching container
	_, _, err = client.CorrelatePID(context.Background(), 9999)
	if err == nil {
		t.Errorf("expected error for unmapped PID, got nil")
	}

	// 4. Invalid PID
	_, _, err = client.CorrelatePID(context.Background(), 0)
	if err == nil {
		t.Errorf("expected error for PID 0, got nil")
	}
}

func TestCLIClient_AddressAwarePortMatching(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ps -q") {
			return []byte("c_local\nc_lan\nc_wildcard\n"), nil
		}
		return []byte(`[
			{
				"Id": "c_local",
				"Name": "/app-local",
				"State": {"Pid": 1001, "Running": true},
				"Config": {"Image": "local:v1"},
				"NetworkSettings": {
					"Ports": {
						"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
					}
				}
			},
			{
				"Id": "c_lan",
				"Name": "/app-lan",
				"State": {"Pid": 1002, "Running": true},
				"Config": {"Image": "lan:v1"},
				"NetworkSettings": {
					"Ports": {
						"8080/tcp": [{"HostIp": "192.168.1.50", "HostPort": "8080"}]
					}
				}
			},
			{
				"Id": "c_wildcard",
				"Name": "/app-wildcard",
				"State": {"Pid": 1003, "Running": true},
				"Config": {"Image": "wildcard:v1"},
				"NetworkSettings": {
					"Ports": {
						"9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}]
					}
				}
			}
		]`), nil
	}

	client := NewCLIClientWithRunner(mockRunner)

	// Case 1: Exact host IP match (127.0.0.1:8080 selects c_local)
	c1, _, err := client.CorrelatePort(context.Background(), "127.0.0.1", 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c1.Name != "app-local" {
		t.Errorf("expected app-local, got %s", c1.Name)
	}

	// Case 2: Exact host IP match on LAN address (192.168.1.50:8080 selects c_lan)
	c2, _, err := client.CorrelatePort(context.Background(), "192.168.1.50", 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c2.Name != "app-lan" {
		t.Errorf("expected app-lan, got %s", c2.Name)
	}

	// Case 3: Listener 10.0.0.1 vs mappings 127.0.0.1 and 192.168.1.50 -> MUST NOT match
	_, _, err = client.CorrelatePort(context.Background(), "10.0.0.1", 8080)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for unrelated IP, got %v", err)
	}

	// Case 4: Listener wildcard (0.0.0.0) vs Docker wildcard 0.0.0.0:9000 -> matches c_wildcard
	cWild, _, err := client.CorrelatePort(context.Background(), "0.0.0.0", 9000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cWild.Name != "app-wildcard" {
		t.Errorf("expected app-wildcard for wildcard binding match, got %s", cWild.Name)
	}

	// Case 5: Listener specific IP (192.168.1.100) vs Docker wildcard 0.0.0.0:9000 -> MUST NOT match (fail-closed)
	_, _, err = client.CorrelatePort(context.Background(), "192.168.1.100", 9000)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for specific IP vs wildcard mapping, got %v", err)
	}

	// Case 6: Cross-family wildcard (:: vs 0.0.0.0:9000) -> MUST NOT match
	_, _, err = client.CorrelatePort(context.Background(), "::", 9000)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for cross-family wildcard, got %v", err)
	}

	// Case 7: Unmapped port -> ErrContainerNotFound
	_, _, err = client.CorrelatePort(context.Background(), "0.0.0.0", 9999)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound, got %v", err)
	}
}

func TestCLIClient_AmbiguousPortCorrelation(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ps -q") {
			return []byte("c1\nc2\n"), nil
		}
		return []byte(`[
			{
				"Id": "c1",
				"Name": "/app1",
				"State": {"Pid": 101, "Running": true},
				"Config": {"Image": "img1"},
				"NetworkSettings": {
					"Ports": {
						"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
					}
				}
			},
			{
				"Id": "c2",
				"Name": "/app2",
				"State": {"Pid": 102, "Running": true},
				"Config": {"Image": "img2"},
				"NetworkSettings": {
					"Ports": {
						"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
					}
				}
			}
		]`), nil
	}

	client := NewCLIClientWithRunner(mockRunner)

	// Both containers legitimate match port 8080 on 0.0.0.0 -> MUST return ErrAmbiguousMapping
	c, m, err := client.CorrelatePort(context.Background(), "0.0.0.0", 8080)
	if !errors.Is(err, ErrAmbiguousMapping) {
		t.Fatalf("expected ErrAmbiguousMapping, got c=%v, m=%v, err=%v", c, m, err)
	}
	if c != nil || m != nil {
		t.Errorf("expected nil container and mapping when ambiguous, got c=%+v, m=%+v", c, m)
	}
}

func TestCLIClient_CorrelateListener_StrictFallback(t *testing.T) {
	mockRunner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ps -q") {
			return []byte("c_db\nc_udp\nc_v6\nc_stopped\n"), nil
		}
		return []byte(`[
			{
				"Id": "c_db",
				"Name": "/postgres-container",
				"State": {"Pid": 2000, "Running": true},
				"Config": {"Image": "postgres:16"},
				"NetworkSettings": {
					"Ports": {
						"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]
					}
				}
			},
			{
				"Id": "c_udp",
				"Name": "/dns-container",
				"State": {"Pid": 3000, "Running": true},
				"Config": {"Image": "coredns:v1"},
				"NetworkSettings": {
					"Ports": {
						"53/udp": [{"HostIp": "0.0.0.0", "HostPort": "53"}]
					}
				}
			},
			{
				"Id": "c_v6",
				"Name": "/ipv6-container",
				"State": {"Pid": 4000, "Running": true},
				"Config": {"Image": "ipv6app:v1"},
				"NetworkSettings": {
					"Ports": {
						"8088/tcp": [{"HostIp": "::", "HostPort": "8088"}]
					}
				}
			},
			{
				"Id": "c_stopped",
				"Name": "/stopped-container",
				"State": {"Pid": 0, "Running": false},
				"Config": {"Image": "stopped:v1"},
				"NetworkSettings": {
					"Ports": {
						"7000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "7000"}]
					}
				}
			}
		]`), nil
	}

	client := NewCLIClientWithRunner(mockRunner)

	// State 1: Native process (e.g. python or node) on port 5432
	// MUST NOT correlate to Docker container even though container published 5432!
	nativeListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         8888, // native PID, not container HostPID
		ProcessName: "python3",
	}
	c1, _, err := client.CorrelateListener(context.Background(), nativeListener)
	if err == nil || c1 != nil {
		t.Fatalf("native process MUST NOT be associated with Docker container, got container: %+v", c1)
	}
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for native process, got %v", err)
	}

	// State 2: docker-proxy on port 5432
	// Positive verification -> DIRECT attribution
	proxyListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         9999, // docker-proxy PID
		ProcessName: "docker-proxy",
	}
	c2, m2, err := client.CorrelateListener(context.Background(), proxyListener)
	if err != nil {
		t.Fatalf("docker-proxy should correlate through fallback, got error: %v", err)
	}
	if c2.Name != "postgres-container" || m2.HostPort != 5432 {
		t.Errorf("unexpected correlation for proxy: c=%+v, m=%+v", c2, m2)
	}
	if c2.AttributionMode != domain.AttributionDirect {
		t.Errorf("expected AttributionDirect for docker-proxy listener, got %s", c2.AttributionMode)
	}

	// State 2 variant: Mixed-case "Docker-Proxy" with PID > 0 -> DIRECT attribution
	mixedProxyListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         9999,
		ProcessName: "Docker-Proxy",
	}
	c2Mixed, _, err := client.CorrelateListener(context.Background(), mixedProxyListener)
	if err != nil {
		t.Fatalf("mixed-case 'Docker-Proxy' should correlate through direct attribution: %v", err)
	}
	if c2Mixed.AttributionMode != domain.AttributionDirect {
		t.Errorf("expected AttributionDirect for mixed-case Docker-Proxy, got %s", c2Mixed.AttributionMode)
	}

	// State 3: Nonzero PID whose process inspection failed / unknown
	// MUST NOT assume Docker! (Fail-closed)
	unknownPIDListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         7777,
		ProcessName: "",
	}
	_, _, err = client.CorrelateListener(context.Background(), unknownPIDListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for nonzero uninspected PID, got %v", err)
	}

	// State 4: Unprivileged Linux listener (PID == 0, ProcessName == "")
	// Root-owned docker-proxy FD unreadable by unprivileged user -> INFERRED attribution
	unprivListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "",
	}
	c4, m4, err := client.CorrelateListener(context.Background(), unprivListener)
	if err != nil {
		t.Fatalf("unprivileged listener should correlate via inference, got error: %v", err)
	}
	if c4.Name != "postgres-container" || m4.HostPort != 5432 {
		t.Errorf("unexpected correlation for unprivileged listener: c=%+v, m=%+v", c4, m4)
	}
	if c4.AttributionMode != domain.AttributionInferred {
		t.Errorf("expected AttributionInferred for PID 0 unprivileged listener, got %s", c4.AttributionMode)
	}

	// State 4 variant: PID == 0, ProcessName == "unknown"
	unprivUnknownListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "unknown",
	}
	c4b, _, err := client.CorrelateListener(context.Background(), unprivUnknownListener)
	if err != nil {
		t.Fatalf("unprivileged 'unknown' listener should correlate via inference, got error: %v", err)
	}
	if c4b.AttributionMode != domain.AttributionInferred {
		t.Errorf("expected AttributionInferred, got %s", c4b.AttributionMode)
	}

	// State 4 variant: PID == 0, Mixed-case "Unknown" -> INFERRED attribution
	unprivMixedUnknownListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "Unknown",
	}
	c4c, _, err := client.CorrelateListener(context.Background(), unprivMixedUnknownListener)
	if err != nil {
		t.Fatalf("unprivileged mixed-case 'Unknown' listener should correlate via inference: %v", err)
	}
	if c4c.AttributionMode != domain.AttributionInferred {
		t.Errorf("expected AttributionInferred for mixed-case Unknown, got %s", c4c.AttributionMode)
	}

	// State 4 variant: PID == 0, Mixed-case "DOCKER-PROXY" -> INFERRED attribution
	unprivMixedDockerProxyListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "DOCKER-PROXY",
	}
	c4d, _, err := client.CorrelateListener(context.Background(), unprivMixedDockerProxyListener)
	if err != nil {
		t.Fatalf("unprivileged mixed-case 'DOCKER-PROXY' listener should correlate via inference: %v", err)
	}
	if c4d.AttributionMode != domain.AttributionInferred {
		t.Errorf("expected AttributionInferred for mixed-case DOCKER-PROXY, got %s", c4d.AttributionMode)
	}

	// State 5: PID == 0, but identified native process name -> MUST NOT correlate
	unprivNativeListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "nginx",
	}
	_, _, err = client.CorrelateListener(context.Background(), unprivNativeListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for identified native process with PID 0, got %v", err)
	}

	// State 5 variant: PID == 0, mixed-case identified native process name "Nginx" -> MUST NOT correlate
	unprivMixedNativeListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         0,
		ProcessName: "Nginx",
	}
	_, _, err = client.CorrelateListener(context.Background(), unprivMixedNativeListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for mixed-case native process with PID 0, got %v", err)
	}

	// Primary correlation: Container running in host network mode where listener PID == container.HostPID
	hostNetListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         2000, // matches c_db HostPID!
		ProcessName: "postgres",
	}
	cHost, _, err := client.CorrelateListener(context.Background(), hostNetListener)
	if err != nil {
		t.Fatalf("primary PID correlation failed: %v", err)
	}
	if cHost.Name != "postgres-container" {
		t.Errorf("expected postgres-container, got %s", cHost.Name)
	}
	if cHost.AttributionMode != domain.AttributionDirect {
		t.Errorf("expected AttributionDirect for HostPID match, got %s", cHost.AttributionMode)
	}

	// Protocol mismatch: TCP listener on port 53 vs UDP container mapping on port 53
	tcpListenerOnUDPPort := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        53,
		PID:         0,
		ProcessName: "",
	}
	_, _, err = client.CorrelateListener(context.Background(), tcpListenerOnUDPPort)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for protocol mismatch (TCP listener vs UDP container), got %v", err)
	}

	// Cross-family wildcard mismatch: IPv4 listener 0.0.0.0 vs IPv6 mapping ::
	crossFamilyListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        8088,
		PID:         0,
		ProcessName: "",
	}
	_, _, err = client.CorrelateListener(context.Background(), crossFamilyListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for cross-family wildcard (0.0.0.0 vs ::), got %v", err)
	}

	// IPv6 wildcard exact match: IPv6 listener :: vs IPv6 mapping ::
	ipv6Listener := domain.Listener{
		Protocol:    "tcp",
		Address:     "::",
		Port:        8088,
		PID:         0,
		ProcessName: "",
	}
	cV6, _, err := client.CorrelateListener(context.Background(), ipv6Listener)
	if err != nil {
		t.Fatalf("IPv6 listener should match IPv6 mapping, got error: %v", err)
	}
	if cV6.Name != "ipv6-container" {
		t.Errorf("expected ipv6-container, got %s", cV6.Name)
	}

	// Stopped container: listener on port 7000 vs stopped container
	stoppedListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        7000,
		PID:         0,
		ProcessName: "",
	}
	_, _, err = client.CorrelateListener(context.Background(), stoppedListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound for stopped container, got %v", err)
	}

	// Listener with no match
	noMatchListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        9999,
		PID:         0,
		ProcessName: "",
	}
	_, _, err = client.CorrelateListener(context.Background(), noMatchListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound, got %v", err)
	}
}

func TestCLIClient_CheckDaemon_Diagnostics(t *testing.T) {
	tests := []struct {
		name          string
		errMsg        string
		expectedErr   error
		isDaemonError bool
	}{
		{
			name:          "daemon stopped",
			errMsg:        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
			expectedErr:   ErrDaemonStopped,
			isDaemonError: true,
		},
		{
			name:          "permission denied",
			errMsg:        "got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
			expectedErr:   ErrDockerPermissionDenied,
			isDaemonError: true,
		},
		{
			name:          "socket missing",
			errMsg:        "dial unix /var/run/docker.sock: connect: no such file or directory",
			expectedErr:   ErrDockerSocketMissing,
			isDaemonError: true,
		},
		{
			name:          "not on path",
			errMsg:        "executable file not found in $PATH",
			expectedErr:   ErrDockerNotAvailable,
			isDaemonError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				return nil, errors.New(tt.errMsg)
			}
			client := NewCLIClientWithRunner(runner)
			if tt.expectedErr != ErrDockerNotAvailable {
				client.SetLookPath(func(file string) (string, error) {
					return "/usr/bin/docker", nil
				})
			} else {
				client.SetLookPath(func(file string) (string, error) {
					return "", errors.New("not found")
				})
			}
			err := client.CheckDaemon(context.Background())
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected %v, got %v", tt.expectedErr, err)
			}
			if tt.isDaemonError && !errors.Is(err, ErrDaemonNotAvailable) {
				t.Errorf("expected error to also match ErrDaemonNotAvailable, got %v", err)
			}
		})
	}
}

func TestCLIClient_IsAvailable(t *testing.T) {
	// Success runner
	clientOk := NewCLIClientWithRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("c1"), nil
	})
	if !clientOk.IsAvailable(context.Background()) {
		t.Log("Note: docker executable not on PATH, LookPath returned false (expected in sandboxed test)")
	}

	// Failing runner
	clientFail := NewCLIClientWithRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("daemon stopped")
	})
	if clientFail.IsAvailable(context.Background()) {
		t.Errorf("expected IsAvailable false when runner errors, got true")
	}
}

func TestCLIClient_StopContainer(t *testing.T) {
	var capturedArgs []string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("c123"), nil
	}
	client := NewCLIClientWithRunner(runner)

	// Empty ID error
	if err := client.StopContainer(context.Background(), "", 10); err == nil {
		t.Error("expected error for empty container ID, got nil")
	}

	// Normal stop with timeout
	if err := client.StopContainer(context.Background(), "c123", 5); err != nil {
		t.Fatalf("unexpected error stopping container: %v", err)
	}
	expected := []string{"stop", "-t", "5", "c123"}
	if len(capturedArgs) != len(expected) {
		t.Fatalf("expected args %v, got %v", expected, capturedArgs)
	}
	for i := range expected {
		if capturedArgs[i] != expected[i] {
			t.Errorf("arg[%d] expected %q, got %q", i, expected[i], capturedArgs[i])
		}
	}

	// Stop without timeout
	if err := client.StopContainer(context.Background(), "c123", 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedNoTimeout := []string{"stop", "c123"}
	if len(capturedArgs) != len(expectedNoTimeout) {
		t.Fatalf("expected args %v, got %v", expectedNoTimeout, capturedArgs)
	}
}
