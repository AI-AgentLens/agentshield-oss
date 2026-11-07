package cli

import (
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// auditFlushCmd is the background uploader the hook starts (#4467): it sends
// ~/.agentshield/audit-queue to the SaaS and exits. Hidden, because nothing
// but the hook needs to run it; running it by hand is harmless (it exits at
// once if another uploader holds the queue).
var auditFlushCmd = &cobra.Command{
	Use:    "audit-flush",
	Short:  "Upload queued audit events to the AI Agent Lens SaaS",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		flushAuditQueue()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditFlushCmd)
}

// auditFlusherArgv is the uploader's command line and any extra environment.
// It is this binary and the fixed word "audit-flush": no event data, no
// agent input, ever reaches a command line (TestAuditFlusherArgv_IsFixed).
// A variable only so the package tests can re-exec the test binary instead.
var auditFlusherArgv = func() (argv, extraEnv []string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	return []string{exe, auditFlushCmd.Name()}, nil, nil
}

// spawnDetachedFlusher starts the uploader so that the hook never waits for
// it:
//
//   - stdin, stdout and stderr are /dev/null (exec.Cmd's nil). A harness such
//     as Claude Code waits until the hook's stdout and stderr pipes close, not
//     just until the hook exits; a child holding either pipe would make every
//     hook call as slow as the upload (TestAuditFlusher_HookDoesNotWaitForUpload);
//   - its own session (Setsid), so a signal to the hook's process group (a
//     harness timing the hook out) does not reach it;
//   - reaped in the background (startReaped). The hook exits right after and
//     never waits; an MCP proxy lives as long as its client, and an uploader
//     it never waited for stayed a zombie, one per decision, until the user
//     ran out of processes (#4734 review).
//
// Its working directory is the queue directory, so it does not pin the
// agent's project directory.
func spawnDetachedFlusher() error {
	argv, extraEnv, err := auditFlusherArgv()
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Dir = auditQueueDir()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	cmd.SysProcAttr = detachedProcAttr()
	_, err = startReaped(cmd)
	return err
}

// startReaped starts cmd and waits for it in a goroutine, so a long-lived
// caller collects its exit status instead of leaving a zombie. The returned
// channel closes once it has. A caller that exits first leaves the child to
// init/launchd, as before.
func startReaped(cmd *exec.Cmd) (<-chan struct{}, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	reaped := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(reaped)
	}()
	return reaped, nil
}
