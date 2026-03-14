package logger

import (
	"encoding/json"
	"fmt"
	"log/syslog"
)

// SyslogLogger sends audit events to a syslog server using RFC 5424 format.
type SyslogLogger struct {
	writer *syslog.Writer
}

// NewSyslogLogger creates a new syslog backend.
func NewSyslogLogger(protocol, address string) (*SyslogLogger, error) {
	w, err := syslog.Dial(protocol, address, syslog.LOG_INFO|syslog.LOG_AUTH, "agentshield")
	if err != nil {
		return nil, fmt.Errorf("syslog dial %s://%s: %w", protocol, address, err)
	}
	return &SyslogLogger{writer: w}, nil
}

// Log sends an audit event to syslog as structured JSON.
func (s *SyslogLogger) Log(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("[agentshield] decision=%s command=%q %s", event.Decision, event.Command, string(data))

	switch event.Decision {
	case "BLOCK":
		return s.writer.Warning(msg)
	case "AUDIT":
		return s.writer.Notice(msg)
	default:
		return s.writer.Info(msg)
	}
}

// Close closes the syslog connection.
func (s *SyslogLogger) Close() error {
	return s.writer.Close()
}
