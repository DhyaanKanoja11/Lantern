package explain

import (
	"strings"
	"testing"

	"lantern/internal/domain"
)

// 1. Compose published port with matching evidence
func TestClassifyRootCause_ComposePublishedPort(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 5432}
	container := &domain.Container{ID: "c1234", Name: "postgres", Image: "postgres:15"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	config := &domain.ConfigEvidence{
		File:          "/app/docker-compose.yml",
		Line:          18,
		Evidence:      "5432:5432",
		Original:      "5432:5432",
		Service:       "db",
		HostPort:      5432,
		ContainerPort: 5432,
		Certain:       true,
	}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, nil, container, mapping, config, reach)

	if rc.Type != RootCauseComposePublishedPort {
		t.Fatalf("expected type %s, got %s", RootCauseComposePublishedPort, rc.Type)
	}
	if !rc.Certain {
		t.Errorf("expected Certain == true")
	}
	if rc.File != "/app/docker-compose.yml" {
		t.Errorf("expected file /app/docker-compose.yml, got %s", rc.File)
	}
	if rc.Line != 18 {
		t.Errorf("expected line 18, got %d", rc.Line)
	}
	if rc.Source != "/app/docker-compose.yml:18" {
		t.Errorf("expected source /app/docker-compose.yml:18, got %s", rc.Source)
	}
	if !strings.Contains(rc.Description, "Docker Compose published host port 5432") {
		t.Errorf("unexpected description: %s", rc.Description)
	}
}

// 2. Docker published port without Compose
func TestClassifyRootCause_DockerPublishedPortWithoutCompose(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 6379}
	container := &domain.Container{ID: "c5678", Name: "redis", Image: "redis:alpine"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 6379, ContainerPort: 6379, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, nil, container, mapping, nil, reach)

	if rc.Type != RootCauseDockerPublishedPort {
		t.Fatalf("expected type %s, got %s", RootCauseDockerPublishedPort, rc.Type)
	}
	if !rc.Certain {
		t.Errorf("expected Certain == true")
	}
	if rc.Source != "docker container redis" {
		t.Errorf("expected source 'docker container redis', got %s", rc.Source)
	}
	if !strings.Contains(rc.Description, "without Compose") {
		t.Errorf("expected description to mention without Compose: %s", rc.Description)
	}
}

// 3. Native loopback listener
func TestClassifyRootCause_NativeLoopback(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "127.0.0.1", Port: 8080}
	proc := &domain.Process{PID: 1234, Name: "node"}
	reach := domain.Reachability{Local: true, LAN: "no", Internet: "unknown", State: "LOOPBACK_ONLY"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	if rc.Type != RootCauseProcessLoopbackBind {
		t.Fatalf("expected type %s, got %s", RootCauseProcessLoopbackBind, rc.Type)
	}
	if !rc.Certain {
		t.Errorf("expected Certain == true")
	}
	if rc.Source != "127.0.0.1:8080" {
		t.Errorf("expected source 127.0.0.1:8080, got %s", rc.Source)
	}
	if !strings.Contains(rc.Description, "loopback") {
		t.Errorf("expected loopback in description: %s", rc.Description)
	}
}

// 4. Native wildcard listener
func TestClassifyRootCause_NativeWildcard(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 8080}
	proc := &domain.Process{PID: 5678, Name: "nginx"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	if rc.Type != RootCauseProcessWildcardBind {
		t.Fatalf("expected type %s, got %s", RootCauseProcessWildcardBind, rc.Type)
	}
	if !rc.Certain {
		t.Errorf("expected Certain == true")
	}
	if rc.Source != "0.0.0.0:8080" {
		t.Errorf("expected source 0.0.0.0:8080, got %s", rc.Source)
	}
	if strings.Contains(strings.ToLower(rc.Description), "internet") {
		t.Errorf("wildcard root cause description must not claim Internet exposure: %s", rc.Description)
	}
}

// 5. Specific LAN address
func TestClassifyRootCause_SpecificLANAddress(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "192.168.1.20", Port: 8080}
	proc := &domain.Process{PID: 9999, Name: "custom-app"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	if rc.Type != RootCauseProcessSpecificBind {
		t.Fatalf("expected type %s, got %s", RootCauseProcessSpecificBind, rc.Type)
	}
	if !rc.Certain {
		t.Errorf("expected Certain == true")
	}
	if rc.Source != "192.168.1.20:8080" {
		t.Errorf("expected source 192.168.1.20:8080, got %s", rc.Source)
	}
}

// 6. VPN reachability preserved
func TestClassifyRootCause_VPNReachabilityPreserved(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "10.8.0.5", Port: 9000}
	proc := &domain.Process{PID: 4321, Name: "internal-api"}
	reach := domain.Reachability{Local: true, LAN: "no", Internet: "unknown", State: "VPN_REACHABLE"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	if rc.Type != RootCauseProcessSpecificBind {
		t.Fatalf("expected type %s, got %s", RootCauseProcessSpecificBind, rc.Type)
	}
	if !strings.Contains(rc.Detail, "VPN_REACHABLE") {
		t.Errorf("expected detail to preserve VPN_REACHABLE, got %s", rc.Detail)
	}
}

// 7. Multi-interface reachability preserved
func TestClassifyRootCause_MultiInterfacePreserved(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 3000}
	proc := &domain.Process{PID: 777, Name: "web"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "MULTI_INTERFACE"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	if rc.Type != RootCauseProcessWildcardBind {
		t.Fatalf("expected type %s, got %s", RootCauseProcessWildcardBind, rc.Type)
	}
	if !strings.Contains(rc.Detail, "MULTI_INTERFACE") {
		t.Errorf("expected detail to preserve MULTI_INTERFACE, got %s", rc.Detail)
	}
}

// 8. Insufficient evidence (Unresolved)
func TestClassifyRootCause_UnresolvedEvidence(t *testing.T) {
	// Listener exists, but process, container, and config are unavailable
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 4000}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, nil, nil, nil, nil, reach)

	if rc.Type != RootCauseUnresolved {
		t.Fatalf("expected type %s, got %s", RootCauseUnresolved, rc.Type)
	}
	if rc.Certain {
		t.Errorf("expected Certain == false for unresolved evidence")
	}

	// Listener with port 0
	rcInvalid := ClassifyRootCause(domain.Listener{}, nil, nil, nil, nil, reach)
	if rcInvalid.Type != RootCauseUnresolved || rcInvalid.Certain {
		t.Errorf("expected unresolved and uncertain for port 0")
	}
}

// 9. No false Internet claim
func TestClassifyRootCause_NoFalseInternetClaim(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 8080}
	proc := &domain.Process{PID: 100, Name: "app"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	rc := ClassifyRootCause(listener, proc, nil, nil, nil, reach)

	descLower := strings.ToLower(rc.Description)
	detailLower := strings.ToLower(rc.Detail)

	if strings.Contains(descLower, "internet exposed") || strings.Contains(descLower, "internet reachable") {
		t.Errorf("root cause description falsely claimed Internet exposure: %s", rc.Description)
	}
	if strings.Contains(detailLower, "internet exposed") || strings.Contains(detailLower, "internet reachable") {
		t.Errorf("root cause detail falsely claimed Internet exposure: %s", rc.Detail)
	}
}

// 10. Certain vs uncertain evidence behavior
func TestClassifyRootCause_CertainVsUncertain(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	// Uncertain Compose config (e.g. multiple ambiguous compose services)
	configUncertain := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          10,
		Evidence:      "5432:5432",
		HostPort:      5432,
		ContainerPort: 5432,
		Certain:       false,
	}

	rcUncertain := ClassifyRootCause(listener, nil, container, mapping, configUncertain, reach)
	if rcUncertain.Type != RootCauseComposePublishedPort {
		t.Errorf("expected Compose type, got %s", rcUncertain.Type)
	}
	if rcUncertain.Certain {
		t.Errorf("expected Certain == false when config evidence is uncertain")
	}

	// Certain Compose config
	configCertain := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          10,
		Evidence:      "5432:5432",
		HostPort:      5432,
		ContainerPort: 5432,
		Certain:       true,
	}

	rcCertain := ClassifyRootCause(listener, nil, container, mapping, configCertain, reach)
	if !rcCertain.Certain {
		t.Errorf("expected Certain == true when config evidence is certain")
	}
}

// 11. Compose evidence must correspond to observed Docker mapping
func TestClassifyRootCause_ComposeEvidenceMustCorrespondToDockerMapping(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	// Mismatched Compose configuration (e.g. Compose declared port 9999, but container mapped 5432)
	configMismatch := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          15,
		Evidence:      "9999:9999",
		HostPort:      9999,
		ContainerPort: 9999,
		Certain:       true,
	}

	rc := ClassifyRootCause(listener, nil, container, mapping, configMismatch, reach)

	// Must NOT claim Compose is the root cause for port 5432
	if rc.Type == RootCauseComposePublishedPort {
		t.Errorf("mismatched Compose config must NOT be attributed as root cause")
	}
	if rc.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected fallback to DockerPublishedPort, got %s", rc.Type)
	}
	if rc.Certain {
		t.Errorf("mismatch must yield Certain == false")
	}
	if !strings.Contains(rc.Detail, "does not match observed mapping") {
		t.Errorf("expected detail to explain mismatch, got %s", rc.Detail)
	}
}

// 12. Conflicting/ambiguous evidence must not produce a confident root cause
func TestClassifyRootCause_AmbiguousEvidenceMustNotProduceConfidentRootCause(t *testing.T) {
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	// Sub-case A: Process attribution missing
	rcA := ClassifyRootCause(domain.Listener{Address: "0.0.0.0", Port: 80}, nil, nil, nil, nil, reach)
	if rcA.Certain {
		t.Errorf("missing process attribution must not be certain")
	}
	if rcA.Type != RootCauseUnresolved {
		t.Errorf("expected UNRESOLVED, got %s", rcA.Type)
	}

	// Sub-case B: Container without published port mapping and no process details
	containerNoPorts := &domain.Container{ID: "c_unknown", Name: ""}
	rcB := ClassifyRootCause(domain.Listener{Address: "0.0.0.0", Port: 80}, nil, containerNoPorts, nil, nil, reach)
	if rcB.Type != RootCauseUnresolved {
		t.Errorf("unmapped container without PID or proc must produce UNRESOLVED, got %s", rcB.Type)
	}
	if rcB.Certain {
		t.Errorf("expected Certain == false")
	}
}

// Regression Test 1: Compose HostIP mismatch (Finding 1)
func TestClassifyRootCause_ComposeHostIPMismatch(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "127.0.0.1", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mapping := &domain.PortMapping{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "no", Internet: "unknown", State: "LOOPBACK_ONLY"}

	// Compose declared 0.0.0.0:5432:5432, but runtime mapping is 127.0.0.1:5432:5432
	config := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          15,
		Evidence:      "0.0.0.0:5432:5432",
		HostIP:        "0.0.0.0",
		HostPort:      5432,
		ContainerPort: 5432,
		Protocol:      "tcp",
		Certain:       true,
	}

	rc := ClassifyRootCause(listener, nil, container, mapping, config, reach)

	// Must NOT claim Compose is the root cause
	if rc.Type == RootCauseComposePublishedPort {
		t.Errorf("Compose with 0.0.0.0 HostIP must NOT be attributed to 127.0.0.1 Docker mapping")
	}
	if rc.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected DOCKER_PUBLISHED_PORT fallback, got %s", rc.Type)
	}
	if rc.Certain {
		t.Errorf("mismatched Compose evidence must yield Certain == false")
	}
}

// Regression Test 2: Compose ContainerPort mismatch (Finding 1)
func TestClassifyRootCause_ComposeContainerPortMismatch(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	// Compose declared 5432:8080 (container port 8080), but runtime container port is 5432
	config := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          15,
		Evidence:      "5432:8080",
		HostPort:      5432,
		ContainerPort: 8080,
		Protocol:      "tcp",
		Certain:       true,
	}

	rc := ClassifyRootCause(listener, nil, container, mapping, config, reach)

	if rc.Type == RootCauseComposePublishedPort {
		t.Errorf("Compose with container port 8080 must NOT match container port 5432")
	}
	if rc.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected DOCKER_PUBLISHED_PORT fallback, got %s", rc.Type)
	}
	if rc.Certain {
		t.Errorf("mismatch must yield Certain == false")
	}
}

// Regression Test 3: Compose protocol mismatch (Finding 1)
func TestClassifyRootCause_ComposeProtocolMismatch(t *testing.T) {
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mapping := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}

	// Compose declared UDP port, but runtime is TCP
	config := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          15,
		Evidence:      "5432:5432/udp",
		HostPort:      5432,
		ContainerPort: 5432,
		Protocol:      "udp",
		Certain:       true,
	}

	rc := ClassifyRootCause(listener, nil, container, mapping, config, reach)

	if rc.Type == RootCauseComposePublishedPort {
		t.Errorf("Compose with UDP protocol must NOT match TCP mapping")
	}
	if rc.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected DOCKER_PUBLISHED_PORT fallback, got %s", rc.Type)
	}
	if rc.Certain {
		t.Errorf("mismatch must yield Certain == false")
	}
}

// Regression Test 5: Host-networking container without PID correlation (Finding 3)
func TestClassifyRootCause_HostNetworkingWithoutPIDCorrelation(t *testing.T) {
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}
	listener := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, PID: 1234}
	container := &domain.Container{ID: "c1", Name: "other-container", HostPID: 9999}

	// Sub-case A: Native process evidence exists and does not match container HostPID
	proc := &domain.Process{PID: 1234, Name: "native-nginx"}
	rcA := ClassifyRootCause(listener, proc, container, nil, nil, reach)

	if rcA.Type != RootCauseProcessWildcardBind {
		t.Errorf("expected native process attribution PROCESS_WILDCARD_BIND, got %s", rcA.Type)
	}
	if !strings.Contains(rcA.Description, "native-nginx") {
		t.Errorf("expected description to attribute native process: %s", rcA.Description)
	}
	if strings.Contains(rcA.Description, "other-container") {
		t.Errorf("uncorrelated container must not be attributed in description: %s", rcA.Description)
	}

	// Sub-case B: No native process evidence available
	rcB := ClassifyRootCause(listener, nil, container, nil, nil, reach)
	if rcB.Type != RootCauseUnresolved {
		t.Errorf("uncorrelated container without process evidence must be UNRESOLVED, got %s", rcB.Type)
	}
	if rcB.Certain {
		t.Errorf("expected Certain == false")
	}

	// Sub-case C: PID DOES match container HostPID -> valid host networking attribution
	containerMatching := &domain.Container{ID: "c2", Name: "hostnet-container", HostPID: 1234}
	rcC := ClassifyRootCause(listener, proc, containerMatching, nil, nil, reach)
	if rcC.Type != RootCauseProcessWildcardBind {
		t.Errorf("expected PROCESS_WILDCARD_BIND, got %s", rcC.Type)
	}
	if !strings.Contains(rcC.Description, "hostnet-container") {
		t.Errorf("expected description to attribute hostnet container: %s", rcC.Description)
	}
	if !rcC.Certain {
		t.Errorf("expected Certain == true for PID-correlated hostnet container")
	}
}

// Regression Test 6: Docker HostIP incompatible with listener (Finding 4)
func TestClassifyRootCause_DockerHostIPIncompatibleWithListener(t *testing.T) {
	reach := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}
	listener := domain.Listener{Protocol: "tcp", Address: "192.168.1.50", Port: 8080, PID: 4321}
	container := &domain.Container{ID: "c_redis", Name: "redis", HostPID: 9000}
	// Docker mapping is strictly on 127.0.0.1, incompatible with listener 192.168.1.50
	mapping := &domain.PortMapping{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 8080, Protocol: "tcp"}

	// Sub-case A: With native process evidence for PID 4321
	proc := &domain.Process{PID: 4321, Name: "my-app"}
	rcA := ClassifyRootCause(listener, proc, container, mapping, nil, reach)

	if rcA.Type == RootCauseDockerPublishedPort {
		t.Errorf("incompatible Docker HostIP 127.0.0.1 must NOT attribute 192.168.1.50 listener to Docker")
	}
	if rcA.Type != RootCauseProcessSpecificBind {
		t.Errorf("expected native PROCESS_SPECIFIC_BIND, got %s", rcA.Type)
	}
	if !strings.Contains(rcA.Description, "my-app") {
		t.Errorf("expected description to attribute native process: %s", rcA.Description)
	}

	// Sub-case B: Without process evidence
	rcB := ClassifyRootCause(listener, nil, container, mapping, nil, reach)
	if rcB.Type != RootCauseUnresolved {
		t.Errorf("expected UNRESOLVED when Docker mapping incompatible and process missing, got %s", rcB.Type)
	}
	if rcB.Certain {
		t.Errorf("expected Certain == false")
	}
}

// Regression Test 7: Positive control tests
func TestClassifyRootCause_PositiveControls(t *testing.T) {
	reach := domain.Reachability{Local: true, LAN: "no", Internet: "unknown", State: "LOOPBACK_ONLY"}

	// Positive Control 1: Matching 127.0.0.1 Compose declaration
	listenerLocal := domain.Listener{Protocol: "tcp", Address: "127.0.0.1", Port: 5432}
	container := &domain.Container{ID: "c1", Name: "postgres"}
	mappingLocal := &domain.PortMapping{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"}
	configLocal := &domain.ConfigEvidence{
		File:          "docker-compose.yml",
		Line:          10,
		Evidence:      "127.0.0.1:5432:5432",
		HostIP:        "127.0.0.1",
		HostPort:      5432,
		ContainerPort: 5432,
		Protocol:      "tcp",
		Certain:       true,
	}

	rcCompose := ClassifyRootCause(listenerLocal, nil, container, mappingLocal, configLocal, reach)
	if rcCompose.Type != RootCauseComposePublishedPort {
		t.Errorf("expected COMPOSE_PUBLISHED_PORT for exact 127.0.0.1 match, got %s", rcCompose.Type)
	}
	if !rcCompose.Certain {
		t.Errorf("expected Certain == true")
	}

	// Positive Control 2: Wildcard Docker published port (no Compose)
	reachWildcard := domain.Reachability{Local: true, LAN: "yes", Internet: "unknown", State: "LAN_REACHABLE"}
	listenerWildcard := domain.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 6379}
	mappingWildcard := &domain.PortMapping{HostIP: "0.0.0.0", HostPort: 6379, ContainerPort: 6379, Protocol: "tcp"}

	rcDockerWildcard := ClassifyRootCause(listenerWildcard, nil, container, mappingWildcard, nil, reachWildcard)
	if rcDockerWildcard.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected DOCKER_PUBLISHED_PORT for wildcard Docker mapping, got %s", rcDockerWildcard.Type)
	}
	if !rcDockerWildcard.Certain {
		t.Errorf("expected Certain == true")
	}

	// Positive Control 3: Wildcard compatibility (listener 0.0.0.0, Docker HostIP "")
	mappingEmptyIP := &domain.PortMapping{HostIP: "", HostPort: 6379, ContainerPort: 6379, Protocol: "tcp"}
	rcEmptyIP := ClassifyRootCause(listenerWildcard, nil, container, mappingEmptyIP, nil, reachWildcard)
	if rcEmptyIP.Type != RootCauseDockerPublishedPort {
		t.Errorf("expected DOCKER_PUBLISHED_PORT for empty HostIP, got %s", rcEmptyIP.Type)
	}
}
