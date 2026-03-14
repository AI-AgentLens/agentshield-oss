package logger

// Logger is the interface for audit event backends.
type Logger interface {
	Log(event AuditEvent) error
	Close() error
}

// MultiLogger fans out Log() calls to multiple backends.
type MultiLogger struct {
	backends []Logger
}

// NewMultiLogger creates a MultiLogger from the given backends.
func NewMultiLogger(backends ...Logger) *MultiLogger {
	return &MultiLogger{backends: backends}
}

// Log writes the event to all backends, returning the first error encountered.
func (m *MultiLogger) Log(event AuditEvent) error {
	var firstErr error
	for _, b := range m.backends {
		if err := b.Log(event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all backends, returning the first error encountered.
func (m *MultiLogger) Close() error {
	var firstErr error
	for _, b := range m.backends {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
