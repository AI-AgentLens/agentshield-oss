package logger

import (
	"fmt"
	"testing"
)

type mockLogger struct {
	events []AuditEvent
	err    error
}

func (m *mockLogger) Log(event AuditEvent) error {
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockLogger) Close() error {
	return nil
}

func TestMultiLogger_FanOut(t *testing.T) {
	backend1 := &mockLogger{}
	backend2 := &mockLogger{}

	ml := NewMultiLogger(backend1, backend2)

	event := AuditEvent{
		Timestamp: "2026-03-14T00:00:00Z",
		Command:   "echo hello",
		Decision:  "ALLOW",
	}

	if err := ml.Log(event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(backend1.events) != 1 {
		t.Errorf("expected 1 event in backend1, got %d", len(backend1.events))
	}
	if len(backend2.events) != 1 {
		t.Errorf("expected 1 event in backend2, got %d", len(backend2.events))
	}

	if backend1.events[0].Command != "echo hello" {
		t.Errorf("expected 'echo hello', got '%s'", backend1.events[0].Command)
	}
}

func TestMultiLogger_PartialFailure(t *testing.T) {
	backend1 := &mockLogger{err: fmt.Errorf("backend1 failed")}
	backend2 := &mockLogger{}

	ml := NewMultiLogger(backend1, backend2)

	event := AuditEvent{
		Timestamp: "2026-03-14T00:00:00Z",
		Command:   "test",
		Decision:  "ALLOW",
	}

	err := ml.Log(event)
	if err == nil {
		t.Error("expected error from partial failure")
	}

	// backend2 should still have received the event
	if len(backend2.events) != 1 {
		t.Errorf("expected 1 event in backend2 despite backend1 failure, got %d", len(backend2.events))
	}
}
