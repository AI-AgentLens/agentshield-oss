package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// machineIDWait bounds how long sendRemoteAudit waits for the machine id
// before sending without it (#4208 fix round 1). The send runs before the
// hook returns its verdict, so this wait is paid by the verdict; an
// unbounded wait on the ioreg exec behind enterprise.MachineID held a
// BLOCK forever with ioreg stopped (Opus pass 1, B1).
//
// 250 ms: ioreg measured ~10 ms here, and the read is started at hook entry
// (prefetchMachineID), so it normally finishes during evaluation and the
// send waits for nothing. 25x the normal read leaves room for a loaded
// machine's first read; the worst case it adds to a verdict is a quarter
// second, far inside the 10 s Codex/Gemini hook timeouts, and only until
// the first successful read is cached (after that no process execs at all).
// On timeout machine_id is omitted, which the contract allows.
const machineIDWait = 250 * time.Millisecond

// machineIDCacheFile is the cached hardware id, plain text, one line, in
// the directory that holds credentials.json (~/.agentshield/machine_id).
// It sits beside the credentials because only an install with credentials
// ever reads the id.
const machineIDCacheFile = "machine_id"

// machineIDSource resolves this machine's id at most once per process:
// from the cache file when it holds a hardware id, otherwise by the live
// read (enterprise.MachineID, the heartbeat's value) in the background.
// Nothing ever waits on it unbounded: within() gives up after a deadline,
// and a goroutine left reading does not hold the process open (Go exits
// when the hook returns, whatever other goroutines are doing).
type machineIDSource struct {
	once   sync.Once
	done   chan struct{}
	id     string
	read   func() string         // the live read; a seam for tests
	cached func() (string, bool) // the cache read; a seam for tests
}

func newMachineIDSource(read func() string) *machineIDSource {
	return &machineIDSource{done: make(chan struct{}), read: read, cached: readCachedMachineID}
}

// machineIDs is the process's source. Tests swap it for one with a stub read.
var machineIDs = newMachineIDSource(enterprise.MachineID)

// start begins resolving the id, once, and only spawns: no file I/O and no
// exec runs on the caller's goroutine. sync.Once blocks every concurrent
// caller until the first Do returns, so a read inside Do would sit in front
// of within()'s timer; a FIFO at the cache path hung every hook call that
// way (fix round 1, item 2). In the goroutine, the cache is tried first
// and the live read runs on a miss; only a hardware id is cached.
func (s *machineIDSource) start() {
	s.once.Do(func() {
		go func() {
			id, ok := s.cached()
			if !ok {
				id = s.read()
				if isHardwareMachineID(id) {
					writeCachedMachineID(id)
				}
			}
			s.id = id
			close(s.done)
		}()
	})
}

// within returns the id if it is known within d, and "" otherwise.
func (s *machineIDSource) within(d time.Duration) string {
	s.start()
	select {
	case <-s.done:
		return s.id
	default:
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.done:
		return s.id
	case <-t.C:
		return ""
	}
}

// prefetchMachineID starts resolving the id when this install reports to a
// SaaS, so the read overlaps evaluation. An install with no credentials
// sends nothing and never reads the id.
func prefetchMachineID() {
	if creds, _ := auth.Load(); creds != nil && creds.Token != "" {
		machineIDs.start()
	}
}

// isHardwareMachineID reports whether id came from the hardware registry or
// /etc/machine-id rather than enterprise.MachineID's hostname-hash
// fallback. Only those are cached: caching a fallback written after one
// failed ioreg would pin this machine to a second id, and the SaaS would
// see every later event under it as a different machine (a false break at
// the switch). The shape check also refuses a cache file someone filled
// with anything but an id.
func isHardwareMachineID(id string) bool {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, "fallback-") {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return false
		}
	}
	return true
}

func machineIDCachePath() string {
	return filepath.Join(filepath.Dir(auth.CredentialsPath()), machineIDCacheFile)
}

// machineIDCacheMaxBytes caps the cache read: an id is at most 128 bytes.
const machineIDCacheMaxBytes = 256

// readCachedMachineID returns the cached id when the file holds exactly one
// hardware id. Anything else is a miss, and the caller does the bounded
// live read: absent, unreadable, malformed, a fallback, or not a small
// regular file. The open never blocks and the kind is checked on the open
// descriptor (logger.ReadRegularFileCapped, the tail reader's pattern), so
// a FIFO, a device or a huge file at the path costs nothing.
func readCachedMachineID() (string, bool) {
	data, ok := logger.ReadRegularFileCapped(machineIDCachePath(), machineIDCacheMaxBytes)
	if !ok {
		return "", false
	}
	id := strings.TrimSuffix(string(data), "\n")
	if !isHardwareMachineID(id) {
		return "", false
	}
	return id, true
}

// writeCachedMachineID writes the id beside the credentials, atomically
// (temp file + rename), so a reader never sees a partial id. Best effort:
// a failed write only means the next process reads live again.
func writeCachedMachineID(id string) {
	path := machineIDCachePath()
	f, err := os.CreateTemp(filepath.Dir(path), ".machine_id-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.WriteString(id + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp, 0o600) != nil || os.Rename(tmp, path) != nil {
		_ = os.Remove(tmp)
	}
}

// refreshingMachineID is the heartbeat's live read plus the cache repair
// (#4475). The cache is written once and the hook trusts it from then on, so
// a HOME carried to another machine (Migration Assistant, a restored backup,
// a golden image built from a logged-in HOME) kept sending the old machine's
// id on /api/audit while the heartbeat, which always reads live, sent the
// real one. The heartbeat is off the verdict path, so it is the place to pay
// for the comparison: when its hardware id differs from the cached one, the
// cache is rewritten. A fallback id is never written (see isHardwareMachineID).
func refreshingMachineID(read func() string) string {
	id := read()
	if isHardwareMachineID(id) {
		if cur, ok := readCachedMachineID(); !ok || cur != id {
			writeCachedMachineID(id)
		}
	}
	return id
}
