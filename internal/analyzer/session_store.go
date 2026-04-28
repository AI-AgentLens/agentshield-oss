package analyzer

import (
	"sync"
	"time"
)

// SessionStore tracks command history within a session for multi-step
// attack chain detection. In-memory now; extensible to Redis later.
type SessionStore interface {
	// Record stores an evaluated command in the session history.
	Record(cmd EvaluatedCommand) error

	// GetHistory returns the most recent commands (up to limit).
	GetHistory(limit int) ([]EvaluatedCommand, error)

	// GetAccessedPaths returns paths accessed in this session with timestamps.
	GetAccessedPaths() (map[string]time.Time, error)

	// GetRiskScore returns the cumulative session risk score.
	GetRiskScore() (float64, error)

	// Close releases resources held by the store.
	Close() error
}

// EvaluatedCommand is a command that has been evaluated by the engine,
// stored in the session for multi-step analysis.
type EvaluatedCommand struct {
	Command   string
	Decision  string
	Timestamp time.Time
	Paths     []string // filesystem paths extracted
	Domains   []string // network domains extracted
	Tags      []string // tags from findings (e.g., "download", "execute")
}

// InMemoryStore is a thread-safe in-memory session store.
// Suitable for single-process use. For distributed deployments,
// implement SessionStore with Redis or similar.
type InMemoryStore struct {
	mu       sync.RWMutex
	history  []EvaluatedCommand
	maxSize  int
	paths    map[string]time.Time
	riskAcc  float64
}

// NewInMemoryStore creates an in-memory session store.
func NewInMemoryStore(maxSize int) *InMemoryStore {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &InMemoryStore{
		maxSize: maxSize,
		paths:   make(map[string]time.Time),
	}
}

func (s *InMemoryStore) Record(cmd EvaluatedCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.history = append(s.history, cmd)
	if len(s.history) > s.maxSize {
		s.history = s.history[len(s.history)-s.maxSize:]
	}

	now := time.Now()
	for _, p := range cmd.Paths {
		s.paths[p] = now
	}

	// Accumulate risk based on decision severity
	switch cmd.Decision {
	case "BLOCK":
		s.riskAcc += 1.0
	case "AUDIT":
		s.riskAcc += 0.3
	}

	return nil
}

func (s *InMemoryStore) GetHistory(limit int) ([]EvaluatedCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.history) {
		limit = len(s.history)
	}
	start := len(s.history) - limit
	if start < 0 {
		start = 0
	}

	result := make([]EvaluatedCommand, limit)
	copy(result, s.history[start:])
	return result, nil
}

func (s *InMemoryStore) GetAccessedPaths() (map[string]time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]time.Time, len(s.paths))
	for k, v := range s.paths {
		result[k] = v
	}
	return result, nil
}

func (s *InMemoryStore) GetRiskScore() (float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.riskAcc, nil
}

func (s *InMemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = nil
	s.paths = nil
	return nil
}
