package mcp

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// NonTextContentSignal identifies a class of abuse in non-text MCP content
// blocks (image, audio, resource, resource_link). The existing response
// scanner short-circuits on Type != "text"; everything below routes through
// fields the text scanner cannot see.
type NonTextContentSignal string

const (
	// SignalNonTextCredentialURI fires when a content block's URI (or embedded
	// resource URI) references a credential file path. A `resource_link` block
	// rendered by the host shows the URI to the user as a clickable name; a
	// `resource` block carries the URI plus optional inline content. Either
	// path lets a malicious server steer the agent into citing or re-reading
	// a credential file under a benign-looking display name.
	SignalNonTextCredentialURI NonTextContentSignal = "non_text_credential_uri"

	// SignalNonTextIMDSURI fires when a URI points at a cloud instance metadata
	// endpoint (AWS/Azure/GCP/Alibaba/OCI). MCP clients that auto-fetch
	// resource_link or follow embedded resource URIs become an SSRF pivot into
	// the host's cloud identity.
	SignalNonTextIMDSURI NonTextContentSignal = "non_text_imds_uri"

	// SignalNonTextDangerousScheme fires when a URI uses a scheme that has no
	// defensible use as MCP content: javascript:, vbscript:, data: (when
	// carrying script-like MIME types), or file:// pointing at process/dev
	// pseudo-filesystems. Hosts that render markdown/HTML in consent UIs or
	// that auto-resolve resource_link URIs will activate these payloads.
	SignalNonTextDangerousScheme NonTextContentSignal = "non_text_dangerous_scheme"

	// SignalNonTextNameInjection fires when the `name` or `description` of a
	// non-text block carries prompt-injection markers. resource_link blocks
	// surface the name to the user in consent dialogs AND to the LLM during
	// listing — making name a dual-surface threat invisible to text scanners.
	SignalNonTextNameInjection NonTextContentSignal = "non_text_name_injection"

	// SignalNonTextMIMEMismatch fires when a content block's declared `type`
	// is incompatible with its `mimeType`. An `image` block whose mimeType is
	// `text/plain`, `text/html`, or `application/javascript` is a smuggling
	// shape — the host routes the block through its image-rendering path
	// while the bytes are interpreted by the model as text/script.
	SignalNonTextMIMEMismatch NonTextContentSignal = "non_text_mime_mismatch"
)

// NonTextContentFinding records one detection.
type NonTextContentFinding struct {
	Signal       NonTextContentSignal `json:"signal"`
	Detail       string               `json:"detail"`
	ContentType  string               `json:"content_type,omitempty"`
	ContentIndex int                  `json:"content_index,omitempty"`
	Snippet      string               `json:"snippet,omitempty"`
}

// NonTextContentScanResult is the result of scanning a tool response's
// non-text content blocks.
type NonTextContentScanResult struct {
	Blocked  bool                    `json:"blocked"`
	Findings []NonTextContentFinding `json:"findings,omitempty"`
}

// ScanNonTextContentBlocks inspects image, audio, resource, and resource_link
// content blocks in a tool response. Text and unknown content types are
// skipped — those are handled by ScanToolCallResponse.
func ScanNonTextContentBlocks(items []ContentItem) NonTextContentScanResult {
	var result NonTextContentScanResult
	for i, item := range items {
		switch item.Type {
		case "resource_link", "resource", "image", "audio":
			scanOneNonTextBlock(&result, i, item)
		}
	}
	result.Blocked = len(result.Findings) > 0
	return result
}

func scanOneNonTextBlock(result *NonTextContentScanResult, idx int, item ContentItem) {
	// URI checks apply to resource_link directly and to resource blocks via
	// the embedded Resource.URI. Image/audio blocks may also (non-standardly)
	// carry a URI; if present we treat it the same way.
	uri := item.URI
	if uri == "" && item.Resource != nil {
		uri = item.Resource.URI
	}
	if uri != "" {
		scanURI(result, idx, item.Type, uri)
	}

	// Name and description are scanned for prompt-injection markers. These
	// fields are surfaced to humans in consent dialogs AND to the LLM during
	// listing — making them a dual-surface threat that bypasses text scans.
	for fieldName, fieldVal := range map[string]string{
		"name":        item.Name,
		"description": item.Description,
	} {
		if fieldVal == "" {
			continue
		}
		scanNonTextInjectionField(result, idx, item.Type, fieldName, fieldVal)
		scanNonTextInjectionFieldSeparatorFolded(result, idx, item.Type, fieldName, fieldVal)
	}

	// MIME mismatch: image/audio block claiming text/html/script MIME is a
	// smuggling shape. We only flag the dangerous directions; legitimate
	// image content uses image/* and audio content uses audio/*.
	if item.MIMEType != "" {
		lowerMIME := strings.ToLower(item.MIMEType)
		switch item.Type {
		case "image":
			if !strings.HasPrefix(lowerMIME, "image/") {
				result.Findings = append(result.Findings, NonTextContentFinding{
					Signal:       SignalNonTextMIMEMismatch,
					Detail:       fmt.Sprintf("image-type content block declares non-image MIME %q (smuggling shape)", item.MIMEType),
					ContentType:  item.Type,
					ContentIndex: idx,
					Snippet:      item.MIMEType,
				})
			}
		case "audio":
			if !strings.HasPrefix(lowerMIME, "audio/") {
				result.Findings = append(result.Findings, NonTextContentFinding{
					Signal:       SignalNonTextMIMEMismatch,
					Detail:       fmt.Sprintf("audio-type content block declares non-audio MIME %q (smuggling shape)", item.MIMEType),
					ContentType:  item.Type,
					ContentIndex: idx,
					Snippet:      item.MIMEType,
				})
			}
		}
	}
}

// scanNonTextInjectionField checks one name/description field of a non-text
// content block for prompt-injection markers.
func scanNonTextInjectionField(result *NonTextContentScanResult, idx int, itemType, fieldName, fieldVal string) {
	if loc := nonTextInjectionRe.FindStringIndex(strings.ToLower(fieldVal)); loc != nil {
		result.Findings = append(result.Findings, NonTextContentFinding{
			Signal:       SignalNonTextNameInjection,
			Detail:       fmt.Sprintf("Prompt-injection marker in non-text content %s field", fieldName),
			ContentType:  itemType,
			ContentIndex: idx,
			Snippet:      safeSnippet(fieldVal, loc[0], 80),
		})
	}
}

// scanNonTextInjectionFieldSeparatorFolded re-runs scanNonTextInjectionField
// against a separator-normalized rendering of the field value, appending
// only a finding when the raw pass did not already produce one.
//
// nonTextInjectionRe's override-directive alternatives are spelled with
// `\s+`/`\s*` ("ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"), and
// Go's RE2 `\s` class is ASCII-only. A resource_link or resource block's
// `name`/`description` is shown to the user in a consent dialog AND to the
// LLM during tool-result listing, so a server that separates the directive's
// words with a Unicode space bypasses the one check this dual-surface field
// gets — text scanners never see it, because ScanToolCallResponse only
// processes ContentItems of type "text". See unicode.FoldUnicodeSeparators
// and scanResponseSeparatorFolded (response_scanner.go) for the fold
// rationale and false-positive-safety argument this mirrors.
func scanNonTextInjectionFieldSeparatorFolded(result *NonTextContentScanResult, idx int, itemType, fieldName, fieldVal string) {
	folded, changed := unicode.FoldUnicodeSeparators(fieldVal)
	if !changed {
		return
	}

	seen := make(map[string]bool, len(result.Findings))
	for _, f := range result.Findings {
		seen[string(f.Signal)+"\x00"+f.Detail] = true
	}

	var foldedResult NonTextContentScanResult
	scanNonTextInjectionField(&foldedResult, idx, itemType, fieldName, folded)

	for _, f := range foldedResult.Findings {
		key := string(f.Signal) + "\x00" + f.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		f.Detail = f.Detail + " — recovered by folding non-ASCII Unicode separator characters " +
			"(NBSP / thin / ideographic space and siblings) to ASCII; RE2's `\\s` class is ASCII-only, " +
			"so the value as sent matched no pattern while rendering and tokenizing identically"
		result.Findings = append(result.Findings, f)
	}
}

func scanURI(result *NonTextContentScanResult, idx int, contentType, rawURI string) {
	lowerURI := strings.ToLower(rawURI)

	// Parse the URI; if it fails to parse, still run substring checks on the
	// lowercased form — adversarial URIs may be intentionally malformed.
	parsed, _ := url.Parse(rawURI)
	scheme := ""
	if parsed != nil {
		scheme = strings.ToLower(parsed.Scheme)
	}

	// Dangerous schemes: javascript, vbscript are unambiguously hostile.
	// data: is only flagged when carrying script-like MIME — base64 image
	// data URIs are legitimate.
	switch scheme {
	case "javascript", "vbscript":
		result.Findings = append(result.Findings, NonTextContentFinding{
			Signal:       SignalNonTextDangerousScheme,
			Detail:       fmt.Sprintf("Content block URI uses %s: scheme (script-execution vector)", scheme),
			ContentType:  contentType,
			ContentIndex: idx,
			Snippet:      truncateForSnippet(rawURI, 120),
		})
	case "data":
		if dataSchemeScriptRe.MatchString(lowerURI) {
			result.Findings = append(result.Findings, NonTextContentFinding{
				Signal:       SignalNonTextDangerousScheme,
				Detail:       "Content block URI uses data: scheme with script/html MIME (XSS-via-render vector)",
				ContentType:  contentType,
				ContentIndex: idx,
				Snippet:      truncateForSnippet(rawURI, 120),
			})
		}
	case "file":
		// file:///proc, file:///dev, file:///sys are kernel pseudo-filesystem
		// pivots; the canonical scanner below covers credential paths too.
		if procDevSysFileRe.MatchString(lowerURI) {
			result.Findings = append(result.Findings, NonTextContentFinding{
				Signal:       SignalNonTextDangerousScheme,
				Detail:       "file:// URI references kernel pseudo-filesystem (/proc, /dev, /sys) — info-disclosure or memory-read pivot",
				ContentType:  contentType,
				ContentIndex: idx,
				Snippet:      truncateForSnippet(rawURI, 120),
			})
		}
	}

	// Credential file paths in URI. Covers SSH keys, AWS/GCP creds, k8s/kube
	// configs, gcloud/azure tokens, npmrc, dockercfg, gpg keys, vault tokens,
	// and the common "secret/token/credential" filename idioms.
	if loc := credentialURIRe.FindStringIndex(lowerURI); loc != nil {
		result.Findings = append(result.Findings, NonTextContentFinding{
			Signal:       SignalNonTextCredentialURI,
			Detail:       "Content block URI references a credential file path",
			ContentType:  contentType,
			ContentIndex: idx,
			Snippet:      safeSnippet(rawURI, loc[0], 80),
		})
	}

	// IMDS hosts. Match the canonical cloud metadata endpoints regardless of
	// scheme (a `file://169.254.169.254/...` would be unusual but we still
	// flag any URI that names the host).
	if loc := imdsHostRe.FindStringIndex(lowerURI); loc != nil {
		result.Findings = append(result.Findings, NonTextContentFinding{
			Signal:       SignalNonTextIMDSURI,
			Detail:       "Content block URI references a cloud instance metadata endpoint (IMDS)",
			ContentType:  contentType,
			ContentIndex: idx,
			Snippet:      safeSnippet(rawURI, loc[0], 80),
		})
	}
}

// ── Compiled patterns ──────────────────────────────────────────────────────

var (
	// credentialURIRe matches credential file paths inside a URI. The patterns
	// are intentionally specific (full filenames or distinctive segments) to
	// avoid firing on developer-named files like `keys.json` in a project src
	// tree. SSH/AWS/GCP/Azure/k8s/npm/docker/gpg/vault all covered.
	credentialURIRe = regexp.MustCompile(
		`(?:/\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys|known_hosts)\b` +
			`|/\.aws/(?:credentials|config)\b` +
			`|/\.gnupg/(?:secring|private-keys)` +
			`|/\.kube/config\b` +
			`|/\.config/gcloud/(?:credentials|application_default_credentials)\b` +
			`|/\.azure/accesstokens\.json\b` +
			`|/\.docker/config\.json\b` +
			`|/\.npmrc\b` +
			`|/\.netrc\b` +
			`|/\.pypirc\b` +
			`|/etc/shadow\b` +
			`|/\.vault-token\b` +
			`|/secrets?/[^/?#]*\.(?:key|pem|p12|pfx)\b` +
			`)`)

	// imdsHostRe matches cloud instance metadata endpoint hosts. Includes the
	// IPv4 link-local 169.254.169.254 (AWS/Azure/GCP/Oracle/Alibaba),
	// metadata.google.internal (GCP), the GCE IPv6 alias, and the Azure
	// IMDS DNS form.
	imdsHostRe = regexp.MustCompile(
		`(?:169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254|100\.100\.100\.200)`)

	// dataSchemeScriptRe matches data:URIs carrying script-or-HTML MIME types
	// (the dangerous shape). Base64-encoded image data: URIs are legitimate
	// and not matched.
	dataSchemeScriptRe = regexp.MustCompile(
		`^data:(?:text/html|application/(?:x-)?javascript|application/ecmascript|text/javascript)\b`)

	// procDevSysFileRe matches file:// URIs pointing at kernel pseudo-FSs.
	// Constrained to /proc, /dev, /sys roots (with optional path tail) so
	// developer files named procfile.txt do not match.
	procDevSysFileRe = regexp.MustCompile(`^file:///+(?:proc|dev|sys)(?:/|$)`)

	// nonTextInjectionRe matches the high-confidence prompt-injection shapes
	// most likely to appear in a poisoned `name`/`description` field. We keep
	// the surface tight because these fields are short — full description
	// scanner has many more patterns but those need long-text context. Here:
	// role tags, instruction-override directives, system-prompt markers.
	nonTextInjectionRe = regexp.MustCompile(
		`<\s*(?:important|system|instruction|cmd)\s*>` +
			`|\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b` +
			`|\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+instructions\b` +
			`|\[\s*system\s*\]` +
			`|<\|im_start\|>|<<sys>>|\[/inst\]`)
)
