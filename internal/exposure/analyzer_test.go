package exposure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lantern/internal/domain"
	"lantern/internal/explain"
)

// Mock ListenerCollector
type mockCollector struct {
	listeners []domain.Listener
	err       error
}

func (m *mockCollector) CollectListeners(ctx context.Context) ([]domain.Listener, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listeners, nil
}

func (m *mockCollector) FindListenerByPort(ctx context.Context, port uint16) (*domain.Listener, error) {
	for _, l := range m.listeners {
		if l.Port == port {
			return &l, nil
		}
	}
	return nil, ErrNoListener
}

// Mock ProcessInspector
type mockInspector struct {
	procs map[int]*domain.Process
	err   error
}

func (m *mockInspector) Inspect(ctx context.Context, pid int) (*domain.Process, error) {
	if m.err != nil {
		return nil, m.err
	}
	if p, ok := m.procs[pid]; ok {
		return p, nil
	}
	return nil, errors.New("process not found")
}

func (m *mockInspector) Correlate(ctx context.Context, pid int) (*domain.Process, error) {
	return m.Inspect(ctx, pid)
}

// Mock DockerCorrelator
type mockDocker struct {
	containers map[uint16]*domain.Container
	mappings   map[uint16]*domain.PortMapping
	available  bool
}

func (m *mockDocker) ListContainers(ctx context.Context) ([]domain.Container, error) {
	var list []domain.Container
	for _, c := range m.containers {
		list = append(list, *c)
	}
	return list, nil
}

func (m *mockDocker) InspectContainer(ctx context.Context, id string) (*domain.Container, error) {
	for _, c := range m.containers {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, errors.New("container not found")
}

func (m *mockDocker) IsAvailable(ctx context.Context) bool {
	return m.available
}

func (m *mockDocker) CorrelatePID(ctx context.Context, pid int) (*domain.Container, *domain.PortMapping, error) {
	return nil, nil, errors.New("not implemented")
}

func (m *mockDocker) CorrelatePort(ctx context.Context, address string, port uint16) (*domain.Container, *domain.PortMapping, error) {
	if c, ok := m.containers[port]; ok {
		return c, m.mappings[port], nil
	}
	return nil, nil, errors.New("not found")
}

func (m *mockDocker) CorrelateListener(ctx context.Context, l domain.Listener) (*domain.Container, *domain.PortMapping, error) {
	if c, ok := m.containers[l.Port]; ok {
		return c, m.mappings[l.Port], nil
	}
	return nil, nil, errors.New("not found")
}

// Mock ComposeResolver
type mockCompose struct {
	evidences map[uint16]*domain.ConfigEvidence
}

func (m *mockCompose) ResolveAttribution(ctx context.Context, container *domain.Container, hostPort uint16) (*domain.ConfigEvidence, error) {
	if ev, ok := m.evidences[hostPort]; ok {
		return ev, nil
	}
	return nil, errors.New("no compose evidence")
}

// Mock InterfaceClassifier
type mockNetwork struct {
	ifaces []domain.NetworkInterface
}

func (m *mockNetwork) DiscoverInterfaces(ctx context.Context) ([]domain.NetworkInterface, error) {
	return m.ifaces, nil
}

func (m *mockNetwork) ClassifyReachability(bindAddr string, ifaces []domain.NetworkInterface) domain.Reachability {
	if bindAddr == "127.0.0.1" || bindAddr == "::1" {
		return domain.Reachability{Local: true, LAN: "no", Internet: "unknown", State: "LOOPBACK_ONLY"}
	}
	return domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}
}

func (m *mockNetwork) Assess(ctx context.Context, bindAddr string) (domain.Reachability, []domain.NetworkInterface, error) {
	reach := m.ClassifyReachability(bindAddr, m.ifaces)
	return reach, m.ifaces, nil
}

func TestAnalyzer_Why_ComposeExposure(t *testing.T) {
	col := &mockCollector{
		listeners: []domain.Listener{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, PID: 1000},
		},
	}
	insp := &mockInspector{
		procs: map[int]*domain.Process{
			1000: {PID: 1000, Name: "docker-proxy"},
		},
	}
	doc := &mockDocker{
		available: true,
		containers: map[uint16]*domain.Container{
			5432: {ID: "c_pg", Name: "postgres", HostPID: 1000},
		},
		mappings: map[uint16]*domain.PortMapping{
			5432: {HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
		},
	}
	comp := &mockCompose{
		evidences: map[uint16]*domain.ConfigEvidence{
			5432: {
				File:          "/app/docker-compose.yml",
				Line:          18,
				Evidence:      "5432:5432",
				Service:       "db",
				HostPort:      5432,
				ContainerPort: 5432,
				Certain:       true,
			},
		},
	}
	net := &mockNetwork{
		ifaces: []domain.NetworkInterface{
			{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsUp: true},
		},
	}
	exp := explain.NewDefaultExplainer()

	analyzer := NewAnalyzerWithDeps(col, insp, doc, comp, net, exp)

	exposure, err := analyzer.Why(context.Background(), 5432, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if exposure.Port != 5432 {
		t.Errorf("expected port 5432, got %d", exposure.Port)
	}
	if exposure.Container == nil || exposure.Container.Name != "postgres" {
		t.Errorf("expected container postgres, got %+v", exposure.Container)
	}
	if exposure.Config == nil || exposure.Config.File != "/app/docker-compose.yml" {
		t.Errorf("expected config evidence, got %+v", exposure.Config)
	}
	if exposure.Recommendation == nil || exposure.Recommendation.Suggested != "127.0.0.1:5432:5432" {
		t.Errorf("expected recommendation 127.0.0.1:5432:5432, got %+v", exposure.Recommendation)
	}
}

func TestAnalyzer_Why_NativeProcess(t *testing.T) {
	col := &mockCollector{
		listeners: []domain.Listener{
			{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, PID: 2000},
		},
	}
	insp := &mockInspector{
		procs: map[int]*domain.Process{
			2000: {PID: 2000, Name: "node"},
		},
	}
	doc := &mockDocker{available: false}
	comp := &mockCompose{}
	net := &mockNetwork{
		ifaces: []domain.NetworkInterface{
			{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		},
	}
	exp := explain.NewDefaultExplainer()

	analyzer := NewAnalyzerWithDeps(col, insp, doc, comp, net, exp)

	exposure, err := analyzer.Why(context.Background(), 8080, ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if exposure.Port != 8080 {
		t.Errorf("expected port 8080, got %d", exposure.Port)
	}
	if exposure.Process == nil || exposure.Process.Name != "node" {
		t.Errorf("expected process node, got %+v", exposure.Process)
	}
	if exposure.Container != nil {
		t.Errorf("expected nil container for native process, got %+v", exposure.Container)
	}
	// Loopback service should not have a bind_localhost recommendation
	if exposure.Recommendation != nil {
		t.Errorf("expected nil recommendation for loopback service, got %+v", exposure.Recommendation)
	}
}

func TestAnalyzer_Why_NoListener(t *testing.T) {
	col := &mockCollector{listeners: nil}
	analyzer := NewAnalyzerWithDeps(col, nil, nil, nil, nil, explain.NewDefaultExplainer())

	_, err := analyzer.Why(context.Background(), 9999, ".")
	if err == nil {
		t.Fatal("expected error for missing listener, got nil")
	}
	if !errors.Is(err, ErrNoListener) {
		t.Errorf("expected ErrNoListener, got %v", err)
	}
}

func TestAnalyzer_Why_AmbiguousListeners(t *testing.T) {
	col := &mockCollector{
		listeners: []domain.Listener{
			{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, PID: 100},
			{Protocol: "tcp", Address: "192.168.1.50", Port: 8080, PID: 200},
		},
	}
	analyzer := NewAnalyzerWithDeps(col, nil, nil, nil, nil, explain.NewDefaultExplainer())

	_, err := analyzer.Why(context.Background(), 8080, ".")
	if err == nil {
		t.Fatal("expected error for ambiguous listeners, got nil")
	}
	if !errors.Is(err, ErrAmbiguousListener) {
		t.Errorf("expected ErrAmbiguousListener, got %v", err)
	}
}

func TestAnalyzer_Scan(t *testing.T) {
	col := &mockCollector{
		listeners: []domain.Listener{
			{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, PID: 1000},
			{Protocol: "tcp", Address: "127.0.0.1", Port: 3000, PID: 2000},
		},
	}
	insp := &mockInspector{
		procs: map[int]*domain.Process{
			1000: {PID: 1000, Name: "docker-proxy"},
			2000: {PID: 2000, Name: "node"},
		},
	}
	doc := &mockDocker{
		available: true,
		containers: map[uint16]*domain.Container{
			5432: {ID: "c1", Name: "postgres"},
		},
		mappings: map[uint16]*domain.PortMapping{
			5432: {HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
		},
	}
	net := &mockNetwork{
		ifaces: []domain.NetworkInterface{
			{Name: "eth0", IP: "192.168.1.50", Kind: "LAN", IsUp: true},
			{Name: "lo", IP: "127.0.0.1", Kind: "LOOPBACK", IsLoopback: true, IsUp: true},
		},
	}

	analyzer := NewAnalyzerWithDeps(col, insp, doc, nil, net, explain.NewDefaultExplainer())

	summaries, err := analyzer.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	// First summary: Docker postgres
	s1 := summaries[0]
	if s1.Port != 5432 || s1.ProcessName != "docker-proxy" || s1.ContainerName != "postgres" || s1.TargetType != "Docker" {
		t.Errorf("unexpected summary 1: %+v", s1)
	}
	if !strings.Contains(s1.Reachability, "LAN reachable") {
		t.Errorf("expected LAN reachable for 0.0.0.0, got %s", s1.Reachability)
	}

	// Second summary: Native node
	s2 := summaries[1]
	if s2.Port != 3000 || s2.ProcessName != "node" || s2.ContainerName != "-" || s2.TargetType != "native" {
		t.Errorf("unexpected summary 2: %+v", s2)
	}
	if !strings.Contains(s2.Reachability, "localhost only") {
		t.Errorf("expected localhost only for 127.0.0.1, got %s", s2.Reachability)
	}
}
