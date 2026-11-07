package redact

import (
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// Secrets and customer data labels in one redaction (#4813).
//
// Before #4813 the audit record scrubbed data-label values first and then
// redacted secrets in what was left. A label value inside a secret's value
// then cut the secret's pattern short at the placeholder, and the rest of
// the secret stayed in the record:
//
//	export TOKEN=abcdefghijklmn<label>zz9yy8xx7ww6vv5u
//	export [REDACTED][LABEL:customer-records]zz9yy8xx7ww6vv5u
//
// Redacting first is wrong the other way: a secret's match that ends inside
// a label value (a token run straight into an email) leaves the rest of the
// label, which the scrubber no longer recognises. So both are found on the
// text as written, and their union is masked.
//
// The union alone is not enough either, because a label value can also cut a
// secret's match short ON THE TEXT AS WRITTEN: an email's "@" inside a URL's
// password ends the userinfo pattern there, while main's placeholder, which
// has no "@", let it run on to the password's real end. So the mask also
// takes every range main's order (scrub, then redact) hid under [REDACTED],
// tracked back to the text as written: the record hides every byte main's
// record hid, and every secret and label byte found on the text.
//
// A text with no label span is redacted exactly as Redact redacts it, so a
// host with no data labels, and every text no label matches, records what it
// recorded before.

// RedactWithLabels returns text with its secrets and data-label values
// masked. labels returns a text's label spans (datalabel.Engine.Spans); nil
// means no labels.
//
// When labels finds no span in text the result is Redact(text). Otherwise
// three sets of spans are masked together: every label span and every match
// of every secret pattern, each found on text itself, and every range main's
// order (the label spans replaced, then Redact) hid under [REDACTED]. A run of
// overlapping spans becomes one placeholder, [REDACTED] when a secret's span
// is in it, otherwise the label's [LABEL:<id>]. Redact then runs once over
// the result, so a secret that Redact's own sequence of patterns finds there
// is found too.
func RedactWithLabels(text string, labels func(string) []datalabel.Span) string {
	if labels == nil || text == "" {
		return Redact(text)
	}
	return redactSpans(text, labels(text))
}

// redactSpans is RedactWithLabels for text whose label spans are known.
func redactSpans(text string, labels []datalabel.Span) string {
	if len(labels) == 0 {
		return Redact(text)
	}
	spans, _ := maskSpans(text, labels, 0, nil, 1)
	return Redact(mask(text, spans))
}

// maskSpans appends to dst, shifted by off, the spans the record of text
// masks: its label spans, every secret pattern's matches on text, and every
// range main's order hid under [REDACTED], main's order being the label spans
// replaced and then Redact, passes times (an MCP value under a parent key was
// redacted twice). It also returns main's record of text with its origins,
// for a caller that redacts a line made of texts.
func maskSpans(text string, labels []datalabel.Span, off int, dst []span, passes int) ([]span, origins) {
	for _, l := range labels {
		dst = append(dst, labelSpan(l, off))
	}
	dst = appendSecretSpans(dst, text, off)
	o := newOrigins(text, off).replaceLabels(labels)
	for ; passes > 0; passes-- {
		o, dst = o.redact(dst)
	}
	return dst, o
}

// RedactArgsWithLabels is RedactArgs for an argument list that may carry
// data-label values. With no label span in any argument or in the line they
// make, joined by spaces, it is RedactArgs(args). Otherwise each argument is
// redacted with RedactWithLabels, and the line is masked with the secret and
// label spans of the line and of every argument, all found on the arguments
// as written (a secret RedactArgs finds only across arguments, Bearer and its
// token, is found whole even when a label value sits inside it), and with
// every range main's RedactArgs hid, its line pass included. As in
// RedactArgs, the result is the per-argument list when the line finds
// nothing more, and otherwise the masked line split on whitespace.
func RedactArgsWithLabels(args []string, labels func(string) []datalabel.Span) []string {
	if labels == nil {
		return RedactArgs(args)
	}
	line := strings.Join(args, " ")
	var spans []span
	if line != "" {
		for _, l := range labels(line) {
			spans = append(spans, labelSpan(l, 0))
		}
	}
	argLabels := make([][]datalabel.Span, len(args))
	off := 0
	for i, a := range args {
		if a != "" {
			argLabels[i] = labels(a)
		}
		for _, l := range argLabels[i] {
			spans = append(spans, labelSpan(l, off))
		}
		off += len(a) + 1
	}
	if len(spans) == 0 {
		return RedactArgs(args)
	}

	// The line's own secrets and labels; each argument's spans, main's
	// record of each among them; then main's line pass over those records,
	// so every range main's RedactArgs hid is in the mask.
	spans = appendSecretSpans(spans, line, 0)
	result := make([]string, len(args))
	// joined is main's per-argument records joined by spaces, built in one
	// pass: a separator stands for itself in the line.
	var jb strings.Builder
	jb.Grow(len(line))
	jlo, jhi := make([]int32, 0, len(line)), make([]int32, 0, len(line))
	off = 0
	for i, a := range args {
		var argSpans []span
		var o origins
		if len(argLabels[i]) == 0 {
			argSpans = appendSecretSpans(nil, a, off)
			o, argSpans = newOrigins(a, off).redact(argSpans)
			result[i] = o.text
		} else {
			argSpans, o = maskSpans(a, argLabels[i], off, nil, 1)
			local := make([]span, len(argSpans))
			for k, sp := range argSpans {
				local[k] = span{start: sp.start - off, end: sp.end - off, placeholder: sp.placeholder}
			}
			result[i] = Redact(mask(a, local))
		}
		spans = append(spans, argSpans...)
		if i > 0 {
			jb.WriteByte(' ')
			jlo, jhi = append(jlo, int32(off-1)), append(jhi, int32(off))
		}
		jb.WriteString(o.text)
		jlo, jhi = append(jlo, o.lo...), append(jhi, o.hi...)
		off += len(a) + 1
	}
	_, spans = origins{text: jb.String(), lo: jlo, hi: jhi}.redact(spans)
	whole := Redact(mask(line, spans))
	if whole == strings.Join(result, " ") {
		return result
	}
	return strings.Fields(whole)
}

// RedactArgumentsWithLabels is RedactArguments for arguments that may carry
// data-label values: every string is redacted with RedactWithLabels, and a
// string under a key that names a secret is replaced whole when the key
// judges it a secret with its label spans replaced (as before #4813) or as
// written. With no label span in any string it is RedactArguments(args).
func RedactArgumentsWithLabels(args map[string]interface{}, labels func(string) []datalabel.Span) map[string]interface{} {
	return redactor{labels: labels}.object("", args)
}

// span is a byte range [start, end) to mask: a secret's, or a label's with
// its placeholder.
type span struct {
	start, end  int
	placeholder string // the label's [LABEL:<id>]; "" for a secret
}

func labelSpan(l datalabel.Span, off int) span {
	return span{start: l.Start + off, end: l.End + off, placeholder: l.Placeholder()}
}

// origins is a text being rewritten, with the range of the original each of
// its bytes stands for: lo[i], hi[i] for text[i]. A byte kept stands for
// itself; a placeholder's bytes stand for the whole range they replaced. It
// is how main's order, run as main runs it, says which original bytes its
// record hid.
type origins struct {
	text   string
	lo, hi []int32
}

// newOrigins starts from text as written, at offset off of a longer line.
func newOrigins(text string, off int) origins {
	o := origins{text: text, lo: make([]int32, len(text)), hi: make([]int32, len(text))}
	// Every byte, not every rune: a range that ends on a multi-byte
	// character takes its end from that character's last byte.
	for i := 0; i < len(text); i++ {
		o.lo[i], o.hi[i] = int32(off+i), int32(off+i+1)
	}
	return o
}

// replace returns o with the sorted, disjoint ranges locs replaced, the i-th
// by repl(i), and calls hid with the original range each one stood for.
func (o origins) replace(locs [][]int, repl func(int) string, hid func(lo, hi int)) origins {
	if len(locs) == 0 {
		return o
	}
	var sb strings.Builder
	sb.Grow(len(o.text))
	lo := make([]int32, 0, len(o.lo))
	hi := make([]int32, 0, len(o.hi))
	pos := 0
	for i, l := range locs {
		sb.WriteString(o.text[pos:l[0]])
		lo = append(lo, o.lo[pos:l[0]]...)
		hi = append(hi, o.hi[pos:l[0]]...)
		// Origins only grow along the text, so a range stands for its
		// first byte's start to its last byte's end. No range is empty:
		// every secret pattern and every label span matches a byte.
		rlo, rhi := o.lo[l[0]], o.hi[l[1]-1]
		if hid != nil {
			hid(int(rlo), int(rhi))
		}
		r := repl(i)
		sb.WriteString(r)
		for k := 0; k < len(r); k++ {
			lo, hi = append(lo, rlo), append(hi, rhi)
		}
		pos = l[1]
	}
	sb.WriteString(o.text[pos:])
	lo = append(lo, o.lo[pos:]...)
	hi = append(hi, o.hi[pos:]...)
	return origins{text: sb.String(), lo: lo, hi: hi}
}

// replaceLabels is the scrubber's step: each label span, merged and disjoint
// as Engine.Spans returns them, replaced by its placeholder.
func (o origins) replaceLabels(labels []datalabel.Span) origins {
	locs := make([][]int, 0, len(labels))
	holders := make([]string, 0, len(labels))
	for _, l := range labels {
		if l.End > l.Start {
			locs = append(locs, []int{l.Start, l.End})
			holders = append(holders, l.Placeholder())
		}
	}
	return o.replace(locs, func(i int) string { return holders[i] }, nil)
}

// redact is Redact with origins: each secret pattern in turn over the text as
// the patterns before it left it. Each range a match hid is appended to dst
// as a secret's span. Its text is Redact(o.text).
func (o origins) redact(dst []span) (origins, []span) {
	for _, p := range sensitivePatterns {
		o = o.replace(p.FindAllStringIndex(o.text, -1), func(int) string { return redactedPlaceholder }, func(lo, hi int) {
			if hi > lo {
				dst = append(dst, span{start: lo, end: hi})
			}
		})
	}
	return o, dst
}

// appendSecretSpans appends every match of every secret pattern on text,
// each pattern run on text itself rather than on the previous pattern's
// output, shifted by off.
func appendSecretSpans(dst []span, text string, off int) []span {
	for _, p := range sensitivePatterns {
		for _, loc := range p.FindAllStringIndex(text, -1) {
			if loc[1] > loc[0] {
				dst = append(dst, span{start: loc[0] + off, end: loc[1] + off})
			}
		}
	}
	return dst
}

// mask returns text with each run of overlapping spans replaced by one
// placeholder: [REDACTED] when a secret's span is in the run, otherwise the
// placeholder of its earliest label span. Spans that only touch stay
// separate runs, as Engine.Scrub keeps two adjacent labels apart. With label
// spans alone it returns what Engine.Scrub returns.
func mask(text string, spans []span) string {
	if len(spans) == 0 {
		return text
	}
	sort.SliceStable(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
	var out strings.Builder
	out.Grow(len(text))
	pos := 0
	for i := 0; i < len(spans); {
		run := spans[i]
		secret := run.placeholder == ""
		i++
		for i < len(spans) && spans[i].start < run.end {
			if spans[i].end > run.end {
				run.end = spans[i].end
			}
			secret = secret || spans[i].placeholder == ""
			i++
		}
		if run.start > pos {
			out.WriteString(text[pos:run.start])
		}
		if secret {
			out.WriteString(redactedPlaceholder)
		} else {
			out.WriteString(run.placeholder)
		}
		if run.end > pos {
			pos = run.end
		}
	}
	out.WriteString(text[pos:])
	return out.String()
}
