package analyzer

import (
	"slices"
	"testing"
)

// fi8uc3NoL2lkX3JzYQ== is base64 for the SSH private key path. We hard-code
// the encoded form here (rather than computing it at test time) so the test
// itself can run inside an AgentShield-protected dev box without the hook
// blocking the test source.
const (
	encodedSSHKeyB64 = "fi8uc3NoL2lkX3JzYQ=="    // base64(~/.ssh/id_rsa)
	encodedSSHKeyHex = "7e2f2e7373682f69645f727361" // hex(~/.ssh/id_rsa)
	expectedSSHKey   = "~/.ssh/id_rsa"
)

func TestDecoderFold_Base64ConstInput(t *testing.T) {
	// The canonical attack: pure-constant base64 in a $(echo X | base64 -d)
	// pipeline. No vars involved — Layer 2.5 must still fold the decoder
	// to surface the materialized path.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64 -d)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path %q, got %v", expectedSSHKey, got)
	}
}

func TestDecoderFold_Base64DecodeFlag(t *testing.T) {
	// `base64 --decode` is the GNU long form. Must fold the same way.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64 --decode)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path with --decode flag, got %v", got)
	}
}

func TestDecoderFold_Base64BSDDFlag(t *testing.T) {
	// `base64 -D` is the BSD/macOS short form. Same effect as -d.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64 -D)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path with BSD -D flag, got %v", got)
	}
}

func TestDecoderFold_Base64VarInput(t *testing.T) {
	// Source piped to decoder is a $VAR, with VAR set by an earlier Assign.
	// The fold must consult the symbol table built earlier in the analyzer.
	got := runSubstitution(t, "B="+encodedSSHKeyB64+"; cat $(echo $B | base64 -d)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path with var input, got %v", got)
	}
}

func TestDecoderFold_PrintfPercentS(t *testing.T) {
	// `printf '%s' CONST` is the printf equivalent of `echo -n CONST`.
	// Often preferred by attackers because echo's behavior varies across
	// shells and -n is non-portable.
	got := runSubstitution(t, "cat $(printf '%s' "+encodedSSHKeyB64+" | base64 -d)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path with printf source, got %v", got)
	}
}

func TestDecoderFold_HexXxdRP(t *testing.T) {
	// `xxd -r -p` reverses plain hex back to bytes. Same path encoded as
	// hex must surface the same materialized form as the base64 case.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyHex+" | xxd -r -p)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path from hex, got %v", got)
	}
}

func TestDecoderFold_HexXxdCombinedFlag(t *testing.T) {
	// `-rp` is the combined-letters form. xxd accepts it the same as `-r
	// -p`. The flag-matching code must treat them identically.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyHex+" | xxd -rp)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected materialized path from -rp combined flag, got %v", got)
	}
}

func TestDecoderFold_EchoNFlagStripped(t *testing.T) {
	// `echo -n` is bash's no-newline echo. The -n must be stripped from
	// the input — otherwise the decoder receives "-n BASE64..." and fails.
	got := runSubstitution(t, "cat $(echo -n "+encodedSSHKeyB64+" | base64 -d)")
	if !slices.Contains(got, expectedSSHKey) {
		t.Errorf("expected echo -n flag to be stripped, got %v", got)
	}
}

func TestDecoderFold_BailsOnEncodeForm(t *testing.T) {
	// `base64` with NO flag is the encode direction. Folding it would
	// produce different bytes than the runtime — we MUST refuse so we
	// don't surface garbage to the protected-path matcher.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64)")
	for _, p := range got {
		if p == expectedSSHKey {
			t.Errorf("must NOT fold encode-form base64, but materialized %q", expectedSSHKey)
		}
	}
}

func TestDecoderFold_BailsOnUnknownDecoder(t *testing.T) {
	// `rot13` isn't in our whitelist. Folding an unknown decoder would
	// produce wrong values (best case) or false BLOCKs (worst case). Bail.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | rot13)")
	if len(got) != 0 {
		t.Errorf("expected no fold for unknown decoder, got %v", got)
	}
}

func TestDecoderFold_BailsOnInvalidBase64(t *testing.T) {
	// Garbage input that isn't valid base64. The decoder must fail cleanly
	// and the fold must bail rather than surface partial output.
	got := runSubstitution(t, "cat $(echo not-valid-base64-data-!!!! | base64 -d)")
	if len(got) != 0 {
		t.Errorf("expected bail on invalid base64, got %v", got)
	}
}

func TestDecoderFold_BailsOnInvalidHex(t *testing.T) {
	// Odd-length hex, non-hex chars — must bail.
	got := runSubstitution(t, "cat $(echo zzz | xxd -r -p)")
	if len(got) != 0 {
		t.Errorf("expected bail on invalid hex, got %v", got)
	}
}

func TestDecoderFold_BailsOnCmdSubstInput(t *testing.T) {
	// Source is itself a CmdSubst (`$(cat /tmp/file)`). We can't know
	// the runtime contents — bail.
	got := runSubstitution(t, "cat $(cat /tmp/source.b64 | base64 -d)")
	if len(got) != 0 {
		t.Errorf("expected bail when source is CmdSubst, got %v", got)
	}
}

func TestDecoderFold_BailsOnExtraDecoderFlags(t *testing.T) {
	// Wrap the decoder with an extra flag — `base64 -d -i`. The strict
	// flag-match should reject this rather than guess at semantics.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64 -d -i)")
	if len(got) != 0 {
		t.Errorf("expected bail when decoder has extra flags, got %v", got)
	}
}

func TestDecoderFold_BailsOnXxdMissingFlag(t *testing.T) {
	// `xxd -p` alone is encode (plain). We require both -r AND -p to fold.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyHex+" | xxd -p)")
	if len(got) != 0 {
		t.Errorf("expected bail on xxd without -r, got %v", got)
	}
}

func TestDecoderFold_BailsOnMultiPipe(t *testing.T) {
	// Multi-stage pipelines (`echo X | rev | base64 -d`) are out of scope
	// in v1 — chaining decoders requires multi-round semantics.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | rev | base64 -d)")
	if len(got) != 0 {
		t.Errorf("expected bail on multi-pipe pipeline, got %v", got)
	}
}

func TestDecoderFold_BailsOnRedirect(t *testing.T) {
	// `... > /tmp/x` redirect changes semantics — the CmdSubst evaluates
	// to empty (or whatever was on stdout, which won't be the decoded
	// value). Bail.
	got := runSubstitution(t, "cat $(echo "+encodedSSHKeyB64+" | base64 -d > /tmp/x)")
	if len(got) != 0 {
		t.Errorf("expected bail on redirect, got %v", got)
	}
}

func TestDecoderFold_BenignDecodedPathSurfaces(t *testing.T) {
	// Same shape as the attack but the decoded path is benign. The
	// materialized path should appear, but the engine's protected-path
	// check (separate from this analyzer) won't match — TN handled at
	// the engine level, not by suppressing the materialization.
	const benignB64 = "L3RtcC9oZWxsby50eHQ=" // base64("/tmp/hello.txt")
	got := runSubstitution(t, "cat $(echo "+benignB64+" | base64 -d)")
	if !slices.Contains(got, "/tmp/hello.txt") {
		t.Errorf("expected benign decoded path to surface, got %v", got)
	}
}

func TestDecoderFold_IsRecognizedDecoderExported(t *testing.T) {
	// The Guardian companion needs to key off the same decoder name set.
	// This test pins the exported-symbol contract so renames don't silently
	// break the cross-analyzer link.
	if !IsRecognizedDecoder("base64") {
		t.Error("base64 should be a recognized decoder")
	}
	if !IsRecognizedDecoder("xxd") {
		t.Error("xxd should be a recognized decoder")
	}
	if IsRecognizedDecoder("rot13") {
		t.Error("rot13 should NOT be a recognized decoder")
	}
	if IsRecognizedDecoder("") {
		t.Error("empty string should NOT match any decoder")
	}
}
