package hookentry

import (
	"encoding/json"
	"math"
)

// CursorConfigProblem returns why Cursor would ignore a hooks.json, or ""
// when Cursor would load it (#5113).
//
// Cursor checks the whole file before it runs any hook in it. A file that
// fails runs none of them, so every command runs unevaluated. HookFile.Present
// only looks for AgentShield's entry, so it still finds the hook.
//
// These are Cursor's own top-level rules, read from the Cursor CLI bundle
// (cursor-agent 2026.11.22-e9042b2, dist-package/index.js):
//
//	"number" != typeof t.version                  → "Config version must be a number"
//	!Number.isInteger(t.version) || t.version < 1 → "Config version must be a positive integer"
//	!isObject(t.hooks)                            → "Config hooks must be an object"
//
// Only these rules are mirrored. The entry that setup writes passed Cursor's
// per-hook checks in a live run once "version": 1 was present.
func CursorConfigProblem(data []byte) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return "the file is not a JSON object"
	}
	raw, ok := doc["version"]
	if !ok {
		return `it has no "version"; Cursor requires "version": 1`
	}
	var version interface{}
	_ = json.Unmarshal(raw, &version)
	n, isNumber := version.(float64)
	if !isNumber {
		return `"version" is not a number`
	}
	if n != math.Trunc(n) || n < 1 {
		return `"version" is not a positive integer`
	}
	var hooks interface{}
	_ = json.Unmarshal(doc["hooks"], &hooks)
	if _, isObject := hooks.(map[string]interface{}); !isObject {
		return `"hooks" is not an object`
	}
	return ""
}
