// Command shield-server exposes the AgentShield analyzer pipeline over HTTP.
//
// Statement of purpose (point-of-coupling, workspace layering rule):
// shield-server exists to serve REMOTE / AGENTLESS evaluation — a
// customer-VPC appliance or hosted endpoint that thin clients (a curl-based
// IDE hook, a CI wrapper, an LLM-gateway policy callout) call instead of
// installing the agentshield binary on every host. It is NOT for local hook
// evaluation (that stays in-process in ./cmd/agentshield) and it is NOT a
// policy-management API. If this binary is removed, remote evaluation
// breaks; local hooks are unaffected. Roadmap and phase gates: issue #3315.
//
// Like every AgentShield surface, this server EVALUATES commands and tool
// calls; it never executes them (the `run`-subcommand-removal invariant).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Set via -ldflags at build time (see the Makefile build-server target).
// Deliberately local to this package: importing internal/cli for its version
// vars would drag in ~22 cobra init()s and the whole CLI surface.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func main() {
	var (
		addr      = flag.String("addr", "127.0.0.1:8383", "listen address; non-loopback requires --token or AGENTSHIELD_SERVER_TOKEN")
		policy    = flag.String("policy", "", "shell policy YAML override (skips ~/.agentshield/packs, mirrors `agentshield check --policy`, #3030)")
		mcpPolicy = flag.String("mcp-policy", "", "MCP policy YAML override (default: ~/.agentshield/mcp-policy.yaml)")
		logPath   = flag.String("log", "", "audit log path (default: ~/.agentshield/audit.jsonl)")
		mode      = flag.String("mode", "", "enforcement mode: enforce or audit-only (default: resolved from config)")
		token     = flag.String("token", os.Getenv("AGENTSHIELD_SERVER_TOKEN"), "static bearer token required on /v1/*")
		version   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Printf("shield-server %s\nCommit: %s\nBuilt:  %s\n", Version, GitCommit, BuildDate)
		return
	}

	// Secure by default: an unauthenticated listener is only acceptable on
	// loopback. Refusing to start beats starting open — a degraded-but-up
	// posture here would silently expose policy evaluation (and command text
	// sent by clients) to the network.
	if *token == "" && !isLoopback(*addr) {
		log.Fatalf("refusing to listen on non-loopback %q without a token: set --token or AGENTSHIELD_SERVER_TOKEN", *addr)
	}

	srv, err := NewServer(Options{
		PolicyPath:    *policy,
		MCPPolicyPath: *mcpPolicy,
		LogPath:       *logPath,
		Mode:          *mode,
		Token:         *token,
		Version:       Version,
	})
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	for _, w := range srv.warnings {
		log.Printf("warning: %s", w)
	}
	if srv.degraded {
		log.Printf("WARNING: %d pack(s) failed to load — verdicts are evaluated against a DEGRADED ruleset", len(srv.failedPacks))
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("shield-server %s (%s) listening on %s — mode=%s degraded=%v auth=%v",
		Version, GitCommit, *addr, srv.mode, srv.degraded, *token != "")
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
	srv.Close()
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
