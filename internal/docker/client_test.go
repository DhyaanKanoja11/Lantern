package docker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lantern/internal/domain"
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

	// Case 4: Listener specific IP (192.168.1.100) vs Docker wildcard 0.0.0.0:9000 -> matches c_wildcard
	cWild, _, err := client.CorrelatePort(context.Background(), "192.168.1.100", 9000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cWild.Name != "app-wildcard" {
		t.Errorf("expected app-wildcard for wildcard binding match, got %s", cWild.Name)
	}

	// Case 5: Unmapped port -> ErrContainerNotFound
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
			return []byte("c_db\n"), nil
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
			}
		]`), nil
	}

	client := NewCLIClientWithRunner(mockRunner)

	// Scenario 1: Native process (e.g. python or node) on port 5432
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

	// Scenario 2: docker-proxy on port 5432
	// MAY correlate through port/address fallback!
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

	// Scenario 3: Container running in host network mode where listener PID == container.HostPID
	// Primary correlation MUST work regardless of process name!
	hostNetListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        5432,
		PID:         2000, // matches c_db HostPID!
		ProcessName: "postgres",
	}
	c3, _, err := client.CorrelateListener(context.Background(), hostNetListener)
	if err != nil {
		t.Fatalf("primary PID correlation failed: %v", err)
	}
	if c3.Name != "postgres-container" {
		t.Errorf("expected postgres-container, got %s", c3.Name)
	}

	// Scenario 4: Listener with no match
	noMatchListener := domain.Listener{
		Protocol:    "tcp",
		Address:     "0.0.0.0",
		Port:        9999,
		PID:         7777,
		ProcessName: "docker-proxy",
	}
	_, _, err = client.CorrelateListener(context.Background(), noMatchListener)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Errorf("expected ErrContainerNotFound, got %v", err)
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
