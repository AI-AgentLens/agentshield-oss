//go:build windows

package logger

import "errors"

// SyslogLogger is unavailable on Windows: Go's log/syslog does not exist
// there. Configuring a syslog backend fails at startup with this error
// rather than dropping events quietly.
type SyslogLogger struct{}

// NewSyslogLogger always fails on Windows.
func NewSyslogLogger(protocol, address string) (*SyslogLogger, error) {
	return nil, errors.New("syslog audit backend is not supported on windows")
}

// Log is never reached: NewSyslogLogger returns no logger to call it on.
func (s *SyslogLogger) Log(event AuditEvent) error { return nil }

// Close is a no-op.
func (s *SyslogLogger) Close() error { return nil }
