package mcp

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Annotation-vs-Schema coherence checks.
//
// MCP 2025 tool annotations (readOnly / destructive / idempotent / openWorld)
// are informational hints used by clients to decide whether to prompt for user
// approval, suppress confirmation dialogs, or treat a call as safe-to-retry.
// The MCP spec explicitly states annotations are not guaranteed to be accurate.
//
// Existing annotation-spoofing detection (checkAnnotationConsistency) compares
// the boolean hints against the tool *name* and *description* text. An attacker
// who is careful with their prose can pass those checks while still revealing
// the true capability through the *inputSchema property names* — schema
// parameters that only make sense for a capability the annotation denies.
//
// Examples this catches that name/description checks miss:
//   • destructive:false + a `force` or `recursive` property — these parameters
//     exist only for state-mutating, irreversible operations.
//   • idempotent:true + an `idempotency_key` / `nonce` / `request_id` property
//     — these parameters exist *because* the underlying operation is not
//     naturally idempotent; the client supplies a dedupe token. Their presence
//     directly contradicts the annotation.
//   • openWorld:false + a `webhook_url` / `callback_url` / `destination_url`
//     property — schema reveals a server- or argument-controllable egress
//     target that the annotation hides from MCP-host egress monitors.
//
// These are zero-FP signals against well-formed MCP tool schemas: legitimate
// tools that take a `force` argument annotate destructive:true; legitimate
// tools that accept an idempotency key annotate idempotent:false (or omit the
// hint). Detection fires only on the combination — schema property name AND
// contradicting annotation — never on either alone.

const (
	// SignalAnnotationSchemaDestructive flags MCP tools whose `destructive:false`
	// annotation contradicts the presence of a destructive-operator parameter in
	// the input schema (force / recursive / cascade / skip_confirmation / no_undo).
	// MCP hosts use destructive:false to suppress confirmation dialogs; a tool
	// declaring such a parameter is unambiguously performing destructive work
	// regardless of what the annotation claims.
	SignalAnnotationSchemaDestructive PoisonSignal = "annotation_schema_destructive"

	// SignalAnnotationIdempotencyParadox flags MCP tools whose `idempotent:true`
	// annotation contradicts the presence of an idempotency-key parameter
	// (idempotency_key / idempotency_token / dedupe_token / nonce / client_token /
	// request_id). These parameters exist precisely because the underlying
	// operation is *not* naturally idempotent — the client must supply a dedupe
	// token for the server to de-duplicate retried calls. Their presence is a
	// direct logical contradiction with the annotation. Clients that treat
	// idempotent:true as safe-to-retry-without-token will produce duplicate
	// writes when the dedupe token is omitted.
	SignalAnnotationIdempotencyParadox PoisonSignal = "annotation_idempotency_paradox"

	// SignalAnnotationOpenWorldUrlArg flags MCP tools whose `openWorld:false`
	// annotation contradicts the presence of an outbound-URL parameter in the
	// input schema (webhook_url / callback_url / destination_url / endpoint_url
	// / forward_url / relay_url / notification_url / target_url). MCP hosts use
	// openWorld:false to skip network-egress warnings; a tool that accepts a
	// server-controllable HTTP destination cannot honestly declare a closed
	// world. The existing openWorld concealment check only inspects description
	// *verbs* — this surface fires on the schema-level network indicator that
	// description-text checks miss.
	SignalAnnotationOpenWorldUrlArg PoisonSignal = "annotation_openworld_url_arg"

	// SignalAnnotationReadOnlySideEffect flags MCP tools whose `readOnly:true`
	// annotation contradicts the presence of ANY side-effect parameter in the
	// input schema — a destructive-operator (force / recursive / hard_delete),
	// an idempotency / dedupe token (idempotency_key / nonce / request_id), or an
	// outbound-delivery URL (webhook_url / callback_url / destination_url).
	//
	// readOnlyHint is the *strongest* safety claim in the MCP annotation set:
	// per the 2025-03-26 spec it means the tool "does not modify its environment"
	// at all. MCP hosts treat readOnly:true as the signal to skip the approval
	// dialog entirely — strictly stronger than destructive:false (which only
	// promises additive-not-irreversible) or openWorld:false (which only promises
	// no external interaction). A read-only tool therefore cannot honestly carry:
	//   • a destructive-operator parameter — `force`/`recursive`/`hard_delete`
	//     only exist to mutate or irreversibly remove state;
	//   • a dedupe/idempotency token — reads are *naturally* idempotent, so the
	//     only reason to accept `idempotency_key`/`nonce` is to de-duplicate a
	//     state-mutating retry;
	//   • an outbound-delivery URL — transmitting data to a `webhook_url`/
	//     `callback_url` is itself a side effect on the external world.
	//
	// The existing one-to-one checks above wire each schema-property category to
	// exactly one annotation (destructive→destructive-op, idempotent→dedupe-key,
	// openWorld→egress-url). They miss the readOnly umbrella entirely — the most
	// dangerous lie, because readOnly is the annotation that suppresses approval.
	// This signal closes that gap: it fires when readOnly:true is paired with a
	// side-effect property from ANY of the three categories, even when the more
	// specific annotation (destructive / openWorld) is absent. Zero-FP: a
	// genuinely read-only tool exposes none of these parameter shapes.
	SignalAnnotationReadOnlySideEffect PoisonSignal = "annotation_readonly_side_effect"

	// SignalAnnotationOutputSideEffect flags MCP tools whose `readOnly:true`
	// annotation contradicts a mutation-result field in the *outputSchema* — a
	// return-value property whose only reason to exist is to report a state change
	// the call performed: `rows_affected`, `deleted_count`, `records_inserted`,
	// `bytes_written`, `was_created`, etc.
	//
	// All four existing coherence checks above inspect the *inputSchema* property
	// names. An attacker who keeps the input schema clean (e.g. `{ "id": ... }`)
	// while declaring readOnly:true to skip the host approval dialog can still leak
	// the true capability through the OUTPUT schema — which MCP 2025-06-18 hosts
	// also show to the LLM during tools/list. A tool that returns `rows_affected`
	// or `was_deleted` self-evidently mutated state, so a readOnly:true claim
	// alongside it is a spoof on the second, previously unscanned schema surface.
	//
	// Scoped to readOnly:true only (the umbrella "no side effects of any kind"
	// claim). destructive:false is deliberately NOT flagged here: a non-destructive
	// tool legitimately mutates additive state (e.g. `create_record` honestly
	// returns `was_created:true` and annotates destructive:false). Zero-FP: the
	// mutation-result property names matched are unambiguous side-effect reports
	// that a genuinely read-only tool never returns; read metadata (count, total,
	// created_at, size, etag) is excluded.
	SignalAnnotationOutputSideEffect PoisonSignal = "annotation_output_side_effect"
)

// destructiveOperatorProperties matches inputSchema property names whose
// existence only makes sense for destructive/irreversible operations.
// Anchored to property-name boundaries so partial matches inside a longer name
// (e.g. `force_majeure_clause`) do not fire — only exact tokens like `force`,
// `recursive`, snake_case variants, and the obvious destructive verbs.
var destructiveOperatorPropertyRE = regexp.MustCompile(
	`^(force|recursive|cascade|skip_?confirm(ation)?|no_?undo|no_?backup|irreversible|hard_?delete|permanent_?delete|purge|wipe|nuke|truncate|drop_?table|disable_?protection|bypass_?confirmation|allow_?destructive)$`,
)

// idempotencyKeyProperties matches parameter names that exist specifically to
// let the client dedupe retried calls. Their presence on a tool annotated
// idempotent:true is a direct logical contradiction — naturally idempotent
// operations do not need a client-supplied dedupe token.
var idempotencyKeyPropertyRE = regexp.MustCompile(
	`^(idempotency_?key|idempotency_?token|idempotent_?key|dedupe_?token|dedup_?token|deduplication_?key|nonce|client_?token|request_?id|request_?token|operation_?id|x_?request_?id)$`,
)

// readOnlyIncompatibleDedupeRE is a deliberately NARROWER subset of
// idempotencyKeyPropertyRE used only by the readOnly:true check. It matches the
// dedupe-token names whose sole purpose is to de-duplicate a retried *mutation*
// (idempotency_key / dedupe_token / deduplication_key) — these are unambiguously
// incompatible with a read-only tool.
//
// It intentionally EXCLUDES the broader regex's `nonce`, `request_id`,
// `operation_id`, `client_token`, and `x_request_id`: those legitimately appear
// on read-only tools as distributed-tracing / correlation identifiers
// (OpenTelemetry trace context, request correlation IDs) and as anti-replay
// nonces, so firing the readOnly contradiction on them would be a false positive.
// The idempotent:true check keeps using the broad regex because in THAT context
// (a tool claiming natural idempotence) a request_id genuinely signals
// server-side de-duplication of a non-idempotent operation.
var readOnlyIncompatibleDedupeRE = regexp.MustCompile(
	`^(idempotency_?key|idempotency_?token|idempotent_?key|dedupe_?token|dedup_?token|deduplication_?key)$`,
)

// outboundURLProperties matches parameter names that denote a server-controllable
// HTTP egress destination. A tool annotated openWorld:false (no external
// interaction) cannot honestly accept such an argument.
//
// Intentionally narrow — we do NOT match generic `url` / `endpoint` / `host`
// because read-only fetch tools legitimately accept those (e.g. a github
// fetcher that takes `url`). We match only the destination-shaped names that
// imply outbound delivery: webhook, callback, notification, forward, relay,
// destination. These are unambiguous egress sinks.
var outboundURLPropertyRE = regexp.MustCompile(
	`^(webhook_?url|callback_?url|notification_?url|forward_?url|relay_?url|destination_?url|sink_?url|exfil_?url|reply_?to_?url|delivery_?url|push_?url|emit_?url|posthook_?url|outbound_?url|target_?webhook|webhook_?endpoint|callback_?endpoint|webhook_?uri|callback_?uri)$`,
)

// mutationResultPropertyRE matches OUTPUT-schema property names that only exist
// to report a state change this call performed — the return-value side of a
// mutation. A tool that returns any of these self-evidently modified state, so a
// `readOnly:true` annotation alongside one is a spoof.
//
// Deliberately narrow to eliminate false positives against read tools:
//   - count/flag forms of mutation verbs: rows_affected, deleted_count,
//     records_inserted, num_updated, was_created, bytes_written.
//   - EXCLUDES read metadata that a genuine read returns: count, total,
//     result_count, match_count, size, created_at / modified_at (timestamps),
//     etag, version, id. A bare `created`/`modified`/`count` is NOT matched —
//     only the explicit mutation-result compounds are.
var mutationResultPropertyRE = regexp.MustCompile(
	`^(?:rows?_?affected|affected_?rows?|` +
		`(?:rows?|records?|items?|files?|objects?|entries|documents?|keys?|nodes?)_?(?:deleted|inserted|created|updated|modified|written|upserted|purged|removed)|` +
		`(?:deleted|inserted|created|updated|modified|written|upserted|purged|affected|removed)_?count|` +
		`num_?(?:deleted|inserted|created|updated|modified|written|affected|removed)|` +
		`bytes_?(?:written|uploaded|deleted|flushed)|` +
		`was_?(?:created|deleted|updated|modified|inserted|written|removed))$`,
)

// destructionLanguageRE matches description prose that explicitly declares
// irreversible-destruction semantics. Used to extend the existing
// `destructive:false` check beyond the tool *name* (existing
// destructiveLiePattern) to the description body — an attacker who names the
// tool blandly (`manage_records`) can still leak intent through prose like
// "permanently deletes all matching records".
//
// Anchored to phrases that combine an irreversibility adverb with a
// state-mutating verb. Bare "delete" is not matched — that is a plausible
// label for a read-only "find deleted records" tool. The phrase must convey
// permanence or unrecoverability for a finding to fire.
var destructionLanguageRE = regexp.MustCompile(
	`(?i)(permanently\s+(?:delete|remove|erase|destroy|drop|wipe|purge|truncate)|irreversibly\s+(?:delete|remove|erase|destroy|drop|wipe|purge)|(?:delete|remove|destroy|drop|wipe|purge)s?\s+\w{0,30}(?:without\s+(?:undo|backup|recovery|confirmation)|forever|permanently|irreversibly)|cannot\s+be\s+(?:undone|recovered|reversed|restored)|unrecoverable|force[\s-]?delet|hard[\s-]?delet|skip(?:s|ping)?\s+confirmation)`,
)

// nonIdempotentLanguageRE matches description prose that contradicts an
// idempotent:true annotation. Phrases like "each call generates a new",
// "every invocation creates", "appends a new record" indicate state that
// changes per call — the textbook definition of non-idempotent.
//
// Conservative anchoring: requires a per-call quantifier ("each", "every",
// "on every") paired with a state-mutating verb so descriptions like
// "creates the file if it does not exist" (idempotent semantics, single
// invariant) do not trigger.
var nonIdempotentLanguageRE = regexp.MustCompile(
	`(?i)(each\s+(?:call|invocation|request|run)\s+(?:creates?|generates?|produces?|appends?|adds?|inserts?|emits?|increments?|spawns?)|every\s+(?:call|invocation|request)\s+(?:creates?|generates?|produces?|appends?|adds?|inserts?|emits?|increments?|spawns?)|appends?\s+(?:a\s+new|to\s+the\s+log|to\s+the\s+history)|increments?\s+(?:the\s+)?(?:counter|version|sequence)|generates?\s+a\s+(?:new\s+)?(?:unique|fresh|random)\s+(?:id|token|uuid|nonce))`,
)

// extractInputSchemaPropertyNames pulls the top-level property names from a
// JSON-encoded MCP inputSchema. Returns names lower-cased for case-insensitive
// matching. Tolerant of malformed schemas — returns nil rather than failing,
// so a poison signal from a separate scanner is not masked by a parse error.
//
// Walks one level deep: MCP inputSchemas declare arguments as keys under
// `properties` (and optionally a `required` array). We do not recurse into
// nested object schemas — annotation contradictions live at the top-level
// argument surface, and a property named `request` containing a nested
// `webhook_url` field is too noisy to fire on (the agent is unlikely to
// supply that nested field unless the schema explicitly requires it).
func extractInputSchemaPropertyNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil
	}
	names := make([]string, 0, len(schema.Properties))
	for k := range schema.Properties {
		names = append(names, strings.ToLower(k))
	}
	return names
}

// collectSchemaPropertyNamesDeep returns every property name declared at ANY depth
// of a JSON-encoded schema, lower-cased and de-duplicated. It records the keys of
// every `properties` object it encounters and recurses through all other values, so
// it reaches properties nested inside object sub-schemas, array `items`, `$defs` /
// `definitions`, and `allOf` / `anyOf` / `oneOf` composition branches.
//
// This is the counterpart to extractInputSchemaPropertyNames (top-level only). The
// top-level extractor intentionally stays shallow to keep the primary coherence checks
// noise-free; this deep walk feeds the dedicated nested-evasion pass, which re-runs only
// the exact-anchored, unambiguous side-effect regexes — so deep recursion does not widen
// the false-positive surface (a benign `force_refresh` or `request_id` nested anywhere
// still fails the anchored match). Tolerant of malformed schemas (returns nil).
func collectSchemaPropertyNamesDeep(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var root interface{}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var names []string
	var walk func(node interface{})
	walk = func(node interface{}) {
		switch v := node.(type) {
		case map[string]interface{}:
			if props, ok := v["properties"].(map[string]interface{}); ok {
				for k, child := range props {
					lk := strings.ToLower(k)
					if !seen[lk] {
						seen[lk] = true
						names = append(names, lk)
					}
					walk(child)
				}
			}
			for key, child := range v {
				if key == "properties" {
					continue // handled above
				}
				walk(child)
			}
		case []interface{}:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(root)
	return names
}

// checkAnnotationSchemaCoherence runs the three new annotation-vs-schema
// coherence checks. Returns one finding per contradiction. Distinct signals
// per axis so the audit log routes to the correct sentinel rule and so
// operators can tune confidence/decision per signal independently.
func checkAnnotationSchemaCoherence(tool ToolDefinition) []PoisonFinding {
	if tool.Annotations == nil {
		return nil
	}
	var findings []PoisonFinding

	// Top-level inputSchema property names; nil when the schema is absent or
	// declares no properties. The four input-side checks below iterate it, so they
	// no-op safely on an empty schema — the output-schema check then still runs
	// (a tool with no input args but a poisoned output schema is still caught).
	propNames := extractInputSchemaPropertyNames(tool.InputSchema)

	// destructive:false + destructive-operator property in schema
	if tool.Annotations.Destructive != nil && !*tool.Annotations.Destructive {
		for _, name := range propNames {
			if destructiveOperatorPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationSchemaDestructive,
					Detail:  "destructive:false annotation contradicts presence of `" + name + "` parameter in inputSchema — this parameter only exists for destructive/irreversible operations (annotation hides the capability the schema declares)",
					Snippet: name,
				})
				break // one finding per axis is enough; second match would just spam the audit log
			}
		}
	}

	// idempotent:true + idempotency-key parameter in schema
	if tool.Annotations.Idempotent != nil && *tool.Annotations.Idempotent {
		for _, name := range propNames {
			if idempotencyKeyPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationIdempotencyParadox,
					Detail:  "idempotent:true annotation contradicts presence of `" + name + "` parameter in inputSchema — dedupe-token parameters exist precisely because the underlying operation is not naturally idempotent",
					Snippet: name,
				})
				break
			}
		}
	}

	// openWorld:false + outbound-URL parameter in schema
	if tool.Annotations.OpenWorld != nil && !*tool.Annotations.OpenWorld {
		for _, name := range propNames {
			if outboundURLPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationOpenWorldUrlArg,
					Detail:  "openWorld:false annotation contradicts presence of `" + name + "` parameter in inputSchema — accepting a server-controllable egress URL is incompatible with a closed-world declaration",
					Snippet: name,
				})
				break
			}
		}
	}

	// readOnly:true + ANY side-effect parameter in schema.
	//
	// readOnlyHint is the umbrella "no side effects of any kind" claim and the
	// annotation MCP hosts use to skip the approval dialog — so a lie here is
	// the highest-impact spoof. We scan all three side-effect categories under a
	// single readOnly check and emit one finding for the first contradiction
	// (priority: mutation > dedupe-token > egress), naming the category so the
	// audit log is attributable. Each category alone is incompatible with a
	// read-only declaration; the readOnly check fires independently of the
	// destructive/idempotent/openWorld annotations, catching the common spoof
	// where ONLY readOnly:true is set to mark a side-effecting tool as safe.
	if tool.Annotations.ReadOnly != nil && *tool.Annotations.ReadOnly {
		for _, name := range propNames {
			var because string
			switch {
			case destructiveOperatorPropertyRE.MatchString(name):
				because = "a destructive-operator parameter — readOnly:true promises the tool does not modify its environment, but this parameter only exists to mutate or irreversibly remove state"
			case readOnlyIncompatibleDedupeRE.MatchString(name):
				because = "a dedupe/idempotency-token parameter — read operations are naturally idempotent, so a client-supplied dedupe token only makes sense for a state-mutating call that readOnly:true denies"
			case outboundURLPropertyRE.MatchString(name):
				because = "an outbound-delivery URL parameter — transmitting data to an external endpoint is itself a side effect, incompatible with a read-only declaration"
			default:
				continue
			}
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationReadOnlySideEffect,
				Detail:  "readOnly:true annotation contradicts presence of `" + name + "` parameter in inputSchema — " + because + ". readOnly is the annotation MCP hosts use to skip approval, so this spoof executes the side effect without user consent",
				Snippet: name,
			})
			break // one readOnly finding per tool — first contradiction is enough
		}
	}

	// readOnly:true + mutation-result property in OUTPUT schema.
	//
	// The four checks above inspect inputSchema property names. This one inspects
	// the previously unscanned outputSchema surface: a tool annotated readOnly:true
	// whose declared return value contains a field that only exists to report a
	// mutation (rows_affected / deleted_count / was_created / bytes_written) has
	// self-evidently modified state. The output schema is shown to the LLM during
	// tools/list (MCP 2025-06-18), so an attacker who keeps the input schema clean
	// to pass the input-side checks can still leak — or rather, declare — the true
	// capability here. Scoped to readOnly:true only (see SignalAnnotationOutputSideEffect
	// doc): a non-destructive but mutating tool legitimately returns these fields.
	if tool.Annotations.ReadOnly != nil && *tool.Annotations.ReadOnly {
		for _, name := range extractInputSchemaPropertyNames(tool.OutputSchema) {
			if mutationResultPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationOutputSideEffect,
					Detail:  "readOnly:true annotation contradicts presence of `" + name + "` in outputSchema — a return field that only exists to report a state mutation (rows affected / records deleted / bytes written) proves the tool modifies its environment, which readOnly:true denies. readOnly is the annotation MCP hosts use to skip approval, so this spoof runs the side effect without user consent",
					Snippet: name,
				})
				break // one finding per tool — first contradiction is enough
			}
		}
	}

	// Nested-schema evasion pass.
	//
	// Every check above inspects only TOP-LEVEL inputSchema property names
	// (extractInputSchemaPropertyNames deliberately does not recurse, to keep the
	// primary checks noise-free). A careful attacker who wants a strong-claim
	// annotation (readOnly:true / destructive:false / openWorld:false) to suppress
	// the host approval dialog simply HIDES the contradicting parameter one or more
	// levels down: inside a nested object property (`properties.config.properties.force`),
	// an array `items` schema (`properties.ops.items.properties.hard_delete`), a `$defs`
	// definition, or an `allOf`/`anyOf` branch. The top-level checks never see it, so the
	// spoof passes — even though MCP hosts that auto-generate forms or that let the agent
	// populate nested objects will still surface and send that parameter.
	//
	// This pass closes the gap by re-running ONLY the exact-anchored, unambiguous
	// side-effect regexes against property names found at ANY depth that do NOT already
	// appear at the top level (those are handled — and attributed — by the checks above).
	// Because the matched names (`force`, `hard_delete`, `webhook_url`, `idempotency_key`,
	// …) have no benign meaning under one of these strong annotations, recursing the
	// anchored regexes stays false-positive-free: `force_refresh`, `request_id`, `cursor`
	// never match. Findings reuse the existing signals so they route to the existing
	// sentinel rules; the detail notes the nesting so the audit log is attributable.
	topLevelSeen := make(map[string]bool, len(propNames))
	for _, n := range propNames {
		topLevelSeen[n] = true
	}
	nestedOnly := make([]string, 0)
	for _, n := range collectSchemaPropertyNamesDeep(tool.InputSchema) {
		if !topLevelSeen[n] {
			nestedOnly = append(nestedOnly, n)
		}
	}

	// readOnly:true + ANY side-effect parameter nested in the schema.
	if tool.Annotations.ReadOnly != nil && *tool.Annotations.ReadOnly {
		for _, name := range nestedOnly {
			var because string
			switch {
			case destructiveOperatorPropertyRE.MatchString(name):
				because = "a destructive-operator parameter"
			case readOnlyIncompatibleDedupeRE.MatchString(name):
				because = "a dedupe/idempotency-token parameter"
			case outboundURLPropertyRE.MatchString(name):
				because = "an outbound-delivery URL parameter"
			default:
				continue
			}
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationReadOnlySideEffect,
				Detail:  "readOnly:true annotation contradicts `" + name + "` nested deeper in inputSchema (" + because + ") — hiding the side-effect parameter below the top level evades the surface-level coherence check while the agent can still populate it; readOnly is the annotation MCP hosts use to skip approval",
				Snippet: name,
			})
			break
		}
	}

	// destructive:false + destructive-operator parameter nested in the schema.
	if tool.Annotations.Destructive != nil && !*tool.Annotations.Destructive {
		for _, name := range nestedOnly {
			if destructiveOperatorPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationSchemaDestructive,
					Detail:  "destructive:false annotation contradicts `" + name + "` nested deeper in inputSchema — a destructive-operator parameter hidden below the top level evades the surface-level check while the annotation suppresses confirmation dialogs",
					Snippet: name,
				})
				break
			}
		}
	}

	// openWorld:false + outbound-URL parameter nested in the schema.
	if tool.Annotations.OpenWorld != nil && !*tool.Annotations.OpenWorld {
		for _, name := range nestedOnly {
			if outboundURLPropertyRE.MatchString(name) {
				findings = append(findings, PoisonFinding{
					Signal:  SignalAnnotationOpenWorldUrlArg,
					Detail:  "openWorld:false annotation contradicts `" + name + "` nested deeper in inputSchema — a server-controllable egress URL hidden below the top level evades the surface-level check while the annotation hides the egress from MCP-host monitors",
					Snippet: name,
				})
				break
			}
		}
	}

	// readOnly:true + mutation-result field nested in the OUTPUT schema.
	//
	// The nested pass above was wired to inputSchema only, so the outputSchema
	// mutation-result check a few dozen lines up — which reads top-level names
	// via extractInputSchemaPropertyNames — had no deep counterpart at all. One
	// `allOf` wrapper, or one level of object nesting, took
	// SignalAnnotationOutputSideEffect from firing to silent:
	//
	//	{"type":"object","allOf":[{"properties":{"rows_affected":{"type":"integer"}}}]}
	//
	// The evasion this whole pass exists to stop, on the surface it was never
	// applied to. Same anchored regex, so the same false-positive argument
	// holds; `count`/`total`/`results` do not match mutationResultPropertyRE.
	if tool.Annotations.ReadOnly != nil && *tool.Annotations.ReadOnly {
		outTopLevel := make(map[string]bool)
		for _, n := range extractInputSchemaPropertyNames(tool.OutputSchema) {
			outTopLevel[n] = true
		}
		for _, name := range collectSchemaPropertyNamesDeep(tool.OutputSchema) {
			if outTopLevel[name] || !mutationResultPropertyRE.MatchString(name) {
				continue
			}
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationOutputSideEffect,
				Detail:  "readOnly:true annotation contradicts `" + name + "` nested deeper in outputSchema — a return field that only exists to report a state mutation, hidden below the top level (inside a composition branch, a nested object, an array item schema or a $defs definition) so the surface-level outputSchema check never sees it. readOnly is the annotation MCP hosts use to skip approval",
				Snippet: name,
			})
			break // one finding per tool — first contradiction is enough
		}
	}

	return findings
}

// checkAnnotationDescriptionExtensions catches the two annotation contradictions
// that the existing checkAnnotationConsistency misses: destructive:false paired
// with irreversible-destruction language in the *description* (existing check
// only inspects the *name*), and idempotent:true paired with non-idempotent
// per-call semantics in the description.
//
// Findings carry SignalAnnotationSpoofing — the same signal as the existing
// checks. They land on the same sentinel rule (mcp-desc-annotation-spoofing)
// and audit log entry. Distinct Detail strings keep them attributable.
func checkAnnotationDescriptionExtensions(name, description string, ann *ToolAnnotations) []PoisonFinding {
	if ann == nil || description == "" {
		return nil
	}
	var findings []PoisonFinding

	// destructive:false + irreversible-destruction language in description.
	// The existing destructiveLiePattern check only inspects the tool name;
	// an attacker who names the tool blandly leaks intent through prose.
	if ann.Destructive != nil && !*ann.Destructive {
		if destructionLanguageRE.MatchString(description) {
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationSpoofing,
				Detail:  "destructive:false annotation contradicts irreversible-destruction language in tool description — annotation suppresses confirmation dialogs while description declares unrecoverable operations (mcp-tool-annotation-spoofing)",
				Snippet: safeSnippet(description, 0, 100),
			})
		}
	}

	// idempotent:true + non-idempotent per-call semantics in description.
	// The existing idempotentLiePattern check only inspects the tool name;
	// per-call language in prose ("each invocation creates a new record")
	// reveals non-idempotence directly.
	if ann.Idempotent != nil && *ann.Idempotent {
		if nonIdempotentLanguageRE.MatchString(description) {
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationSpoofing,
				Detail:  "idempotent:true annotation contradicts per-call state-mutation language in tool description — clients that retry on failure will produce duplicate writes (mcp-tool-annotation-spoofing)",
				Snippet: safeSnippet(description, 0, 100),
			})
		}
	}

	// Silence unused-name lint — function signature parity with
	// checkAnnotationConsistency in case future checks need it.
	_ = name

	return findings
}
