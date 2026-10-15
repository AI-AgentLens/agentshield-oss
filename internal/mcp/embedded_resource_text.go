package mcp

import "strings"

// withEmbeddedResourceText returns the tools/call content a text scanner
// should read: the wire items unchanged and in order, followed by one text
// item for each piece of text an embedded resource carries (#4296).
//
// An EmbeddedResource block — {"type":"resource","resource":{uri, mimeType,
// text|blob}} — is content for the model exactly as a text block is, but every
// text scanner on this path reads only items of type "text", so its text was
// forwarded unscanned and unrecorded. prompts/get already scans resource.text
// (ScanPromptsGetResponse) and resources/read projects its contents into text
// items the same way (FilterResourceReadResponse); this is that projection for
// tools/call, done once where the result is decoded rather than in each scanner.
//
// What is projected:
//   - resource.text, always. A TextResourceContents is text whatever its
//     mimeType claims.
//   - resource.blob, base64-decoded, only when the resource's mimeType is
//     textual (isTextualMIME). A binary-typed or untyped blob is NOT decoded:
//     whether a host puts such bytes into the model's context is unmeasured,
//     so it stays the known gap pinned by
//     TestToolCallEmbeddedResourceNonTextBlobKnownGap4296.
//
// Each projected item carries the block's Annotations. Per spec they live on
// the outer EmbeddedResource, not the nested resource, and they govern its
// text: an audience:["assistant"] resource is model-only content, the same
// carry-over ScanPromptsGetAudienceChannel does for prompts/get.
//
// Why appended rather than placed next to their block: each scanner reports
// its findings in item order, so within a scanner the resource text can add a
// finding but never displace the first one the wire items produced. Every
// scanner here only adds findings as items are added, and none forwards early
// on an AUDIT, so appending can raise a decision and never lower one. Across
// scanners the handler stops at the first BLOCK, so a resource can now trip an
// earlier scanner (a credential, a formula) and the BLOCK receipt then names
// that rule: exactly what is recorded when the same text arrives as a text
// item after the others.
//
// Scanners that judge the KIND or the annotations of every block (non-text
// content, content ranking, staged trust) keep reading the wire items: the
// resource block is still there for them, and a projected copy would count
// its annotations twice.
func withEmbeddedResourceText(items []ContentItem) []ContentItem {
	var projected []ContentItem
	for _, item := range items {
		if item.Type != "resource" || item.Resource == nil {
			continue
		}
		if item.Resource.Text != "" {
			projected = append(projected, ContentItem{Type: "text", Text: item.Resource.Text, Annotations: item.Annotations})
		}
		if text, ok := textualBlobText(item.Resource); ok {
			projected = append(projected, ContentItem{Type: "text", Text: text, Annotations: item.Annotations})
		}
	}
	if len(projected) == 0 {
		return items
	}
	out := make([]ContentItem, 0, len(items)+len(projected))
	out = append(out, items...)
	return append(out, projected...)
}

// textualBlobText decodes a resource blob whose mimeType declares text. The
// result is made valid UTF-8 the way encoding/json makes a text field valid
// (U+FFFD for each invalid byte), so a scanner sees what it would have seen
// had the same bytes arrived as resource.text.
func textualBlobText(r *ResourceContentItem) (string, bool) {
	if r.Blob == "" || !isTextualMIME(r.MIMEType) {
		return "", false
	}
	b, ok := decodeBase64Lenient(r.Blob)
	if !ok || len(b) == 0 {
		return "", false
	}
	return strings.ToValidUTF8(string(b), "\uFFFD"), true
}

// isTextualMIME reports whether a declared media type is text a host could
// put in front of the model as-is: any text/* type, and the application/*
// types that are text formats by definition. Parameters (charset) and case
// are ignored. image/* is excluded even with a +xml suffix (SVG): an image
// resource is rendered, not read, and that call is left open.
func isTextualMIME(mimeType string) bool {
	base := mimeType
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(strings.TrimSpace(base))
	typ, sub, ok := strings.Cut(base, "/")
	if !ok || sub == "" {
		return false
	}
	switch typ {
	case "text":
		return true
	case "application":
		if textualApplicationSubtypes[sub] {
			return true
		}
		for _, suffix := range []string{"+json", "+xml", "+yaml"} {
			if strings.HasSuffix(sub, suffix) {
				return true
			}
		}
	}
	return false
}

var textualApplicationSubtypes = map[string]bool{
	"json": true, "ndjson": true, "x-ndjson": true,
	"xml":  true,
	"yaml": true, "x-yaml": true,
	"toml": true, "x-toml": true,
	"javascript": true, "x-javascript": true, "ecmascript": true,
	"sql": true, "graphql": true,
	"x-sh": true, "x-shellscript": true,
}
