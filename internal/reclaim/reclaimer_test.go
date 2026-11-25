package reclaim

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DhyaanKanoja11/Lantern/internal/domain"
)

func TestDefaultReclaimer_Plan_NilExposure(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	_, err := reclaimer.Plan(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil exposure, got nil")
	}
}

func TestDefaultReclaimer_Plan_ContainerTarget(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	exp := &domain.Exposure{
		Port: 5432,
		Container: &domain.Container{
			ID:      "c1234567890ab",
			Name:    "/my-postgres",
			Image:   "postgres:16-alpine",
			HostPID: 4321,
			Labels: map[string]string{
				"com.docker.compose.project": "my-app",
				"com.docker.compose.service": "db",
			},
		},
		Listener: domain.Listener{
			Port: 5432,
			PID:  4321,
		},
	}

	plan, err := reclaimer.Plan(context.Background(), exp)
	if err != nil {
		t.Fatalf("unexpected plan error: %v", err)
	}

	if plan.TargetType != TargetContainer {
		t.Errorf("expected TargetContainer, got %s", plan.TargetType)
	}
	if plan.Port != 5432 {
		t.Errorf("expected port 5432, got %d", plan.Port)
	}
	if plan.ContainerID != "c1234567890ab" {
		t.Errorf("expected container ID c1234567890ab, got %s", plan.ContainerID)
	}
	if plan.ContainerName != "my-postgres" {
		t.Errorf("expected stripped container name 'my-postgres', got %q", plan.ContainerName)
	}
	if plan.Image != "postgres:16-alpine" {
		t.Errorf("expected image postgres:16-alpine, got %s", plan.Image)
	}
	if plan.Project != "my-app" {
		t.Errorf("expected project my-app, got %s", plan.Project)
	}
	if plan.Service != "db" {
		t.Errorf("expected service db, got %s", plan.Service)
	}
	if plan.PID != 4321 {
		t.Errorf("expected PID 4321, got %d", plan.PID)
	}
}

func TestDefaultReclaimer_Plan_ProcessTarget(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	exp := &domain.Exposure{
		Port: 3000,
		Process: &domain.Process{
			PID:         9876,
			Name:        "node",
			CommandLine: "node server.js",
			User:        "testuser",
		},
		Listener: domain.Listener{
			Port: 3000,
			PID:  9876,
		},
	}

	plan, err := reclaimer.Plan(context.Background(), exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if plan.TargetType != TargetProcess {
		t.Errorf("expected TargetProcess, got %s", plan.TargetType)
	}
	if plan.PID != 9876 {
		t.Errorf("expected PID 9876, got %d", plan.PID)
	}
	if plan.ProcessName != "node" {
		t.Errorf("expected ProcessName node, got %s", plan.ProcessName)
	}
	if plan.CommandLine != "node server.js" {
		t.Errorf("expected CommandLine 'node server.js', got %s", plan.CommandLine)
	}
	if plan.User != "testuser" {
		t.Errorf("expected User testuser, got %s", plan.User)
	}
}

func TestDefaultReclaimer_Plan_ListenerFallback(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	exp := &domain.Exposure{
		Port: 8080,
		Listener: domain.Listener{
			Port:        8080,
			PID:         5555,
			ProcessName: "caddy",
		},
	}

	plan, err := reclaimer.Plan(context.Background(), exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if plan.TargetType != TargetProcess {
		t.Errorf("expected TargetProcess, got %s", plan.TargetType)
	}
	if plan.PID != 5555 {
		t.Errorf("expected PID 5555, got %d", plan.PID)
	}
	if plan.ProcessName != "caddy" {
		t.Errorf("expected ProcessName caddy, got %s", plan.ProcessName)
	}
}

func TestDefaultReclaimer_Plan_UnknownTarget(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	exp := &domain.Exposure{
		Port: 9000,
		Listener: domain.Listener{
			Port: 9000,
			PID:  0,
		},
	}

	plan, err := reclaimer.Plan(context.Background(), exp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if plan.TargetType != TargetUnknown {
		t.Errorf("expected TargetUnknown, got %s", plan.TargetType)
	}
}

func TestDefaultReclaimer_Apply_NilPlan(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	_, err := reclaimer.Apply(context.Background(), nil, false, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for nil plan, got nil")
	}
}

func TestDefaultReclaimer_Apply_Container_Success(t *testing.T) {
	var stoppedID string
	var stoppedTimeout int
	stopper := func(ctx context.Context, id string, timeoutSeconds int) error {
		stoppedID = id
		stoppedTimeout = timeoutSeconds
		return nil
	}

	reclaimer := NewReclaimerWithDeps(stopper, nil, func() int { return 99999 })
	plan := &ReclaimPlan{
		Port:          5432,
		TargetType:    TargetContainer,
		ContainerID:   "cont-abc",
		ContainerName: "db-service",
	}

	res, err := reclaimer.Apply(context.Background(), plan, false, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}

	if stoppedID != "cont-abc" {
		t.Errorf("expected stopped ID 'cont-abc', got %q", stoppedID)
	}
	if stoppedTimeout != 5 {
		t.Errorf("expected timeout 5s, got %d", stoppedTimeout)
	}
	if res.Port != 5432 {
		t.Errorf("expected port 5432, got %d", res.Port)
	}
	if res.TargetType != TargetContainer {
		t.Errorf("expected TargetContainer, got %s", res.TargetType)
	}
	if !strings.Contains(res.Description, "db-service") {
		t.Errorf("expected description to contain container name, got %q", res.Description)
	}
}

func TestDefaultReclaimer_Apply_Container_Failure(t *testing.T) {
	stopper := func(ctx context.Context, id string, timeoutSeconds int) error {
		return errors.New("docker daemon is unreachable")
	}

	reclaimer := NewReclaimerWithDeps(stopper, nil, nil)
	plan := &ReclaimPlan{
		Port:        5432,
		TargetType:  TargetContainer,
		ContainerID: "cont-abc",
	}

	_, err := reclaimer.Apply(context.Background(), plan, false, 5*time.Second)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "docker daemon is unreachable") {
		t.Errorf("expected daemon error message, got: %v", err)
	}
}

func TestDefaultReclaimer_Apply_Process_Success(t *testing.T) {
	var killedPID int
	var killedForce bool
	killer := func(pid int, force bool, gracePeriod time.Duration) error {
		killedPID = pid
		killedForce = force
		return nil
	}

	reclaimer := NewReclaimerWithDeps(nil, killer, func() int { return 99999 })
	plan := &ReclaimPlan{
		Port:        3000,
		TargetType:  TargetProcess,
		PID:         1234,
		ProcessName: "node",
	}

	res, err := reclaimer.Apply(context.Background(), plan, true, 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}

	if killedPID != 1234 {
		t.Errorf("expected killed PID 1234, got %d", killedPID)
	}
	if !killedForce {
		t.Errorf("expected killedForce true, got false")
	}
	if !strings.Contains(res.Description, "node") {
		t.Errorf("expected description to contain process name, got %q", res.Description)
	}
}

func TestDefaultReclaimer_Apply_Process_Guardrails(t *testing.T) {
	killer := func(pid int, force bool, gracePeriod time.Duration) error {
		return nil
	}
	selfPID := 5000
	reclaimer := NewReclaimerWithDeps(nil, killer, func() int { return selfPID })

	// Guardrail 1: Refuse PID 1
	plan1 := &ReclaimPlan{
		Port:       80,
		TargetType: TargetProcess,
		PID:        1,
	}
	_, err := reclaimer.Apply(context.Background(), plan1, false, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refusing to terminate system process") {
		t.Errorf("expected refusal for PID 1, got: %v", err)
	}

	// Guardrail 2: Refuse PID <= 0
	plan0 := &ReclaimPlan{
		Port:       80,
		TargetType: TargetProcess,
		PID:        0,
	}
	_, err = reclaimer.Apply(context.Background(), plan0, false, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "invalid or unknown PID") {
		t.Errorf("expected refusal for PID 0, got: %v", err)
	}

	// Guardrail 3: Refuse Self PID
	planSelf := &ReclaimPlan{
		Port:       80,
		TargetType: TargetProcess,
		PID:        selfPID,
	}
	_, err = reclaimer.Apply(context.Background(), planSelf, false, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "refusing to terminate self") {
		t.Errorf("expected refusal for self PID, got: %v", err)
	}
}

func TestDefaultReclaimer_Apply_UnknownTarget_Rejection(t *testing.T) {
	reclaimer := NewDefaultReclaimer()
	plan := &ReclaimPlan{
		Port:       8080,
		TargetType: TargetUnknown,
	}
	_, err := reclaimer.Apply(context.Background(), plan, false, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for TargetUnknown, got nil")
	}
	if !strings.Contains(err.Error(), "listener process is unknown") {
		t.Errorf("expected unknown listener error message, got: %v", err)
	}
}

// If Docker couldn't tell us which container owns the port, the listener is
// still docker-proxy. Killing it breaks Docker networking, so refuse.
func TestDefaultReclaimer_Plan_RefusesUnattributedDockerProxy(t *testing.T) {
	cases := map[string]*domain.Exposure{
		"process name": {
			Port:     5432,
			Process:  &domain.Process{PID: 1111, Name: "docker-proxy"},
			Listener: domain.Listener{Port: 5432, PID: 1111},
		},
		"listener name only": {
			Port:     5432,
			Listener: domain.Listener{Port: 5432, PID: 1111, ProcessName: "docker-proxy"},
		},
		"command line path": {
			Port:     5432,
			Process:  &domain.Process{PID: 1111, CommandLine: "/usr/bin/docker-proxy -proto tcp -host-port 5432"},
			Listener: domain.Listener{Port: 5432, PID: 1111},
		},
	}
	for name, exp := range cases {
		t.Run(name, func(t *testing.T) {
			plan, err := NewDefaultReclaimer().Plan(context.Background(), exp)
			if err == nil {
				t.Fatalf("expected refusal, got plan %+v", plan)
			}
		})
	}
}
