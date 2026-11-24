package mcp

import (
	"reflect"
	"sort"
)

// pathArgAliasNames are the argument names a rule predicate written on `path`
// also reads, in normalizeFieldName's form. Two groups:
//
//   - names for the file a tool reads or edits (#4937, Gary 2026-11-16):
//     file_path and filepath (both fold to "filepath"), file and filename;
//   - names for the file a tool writes its output to (#4942, Gary
//     2026-11-17): dest, destination, output_file, output_path, out_path and
//     save_path. A download or report tool takes the bytes from one argument
//     and the place to write them from another: Kubeshark's download_file
//     has path (the remote file) and dest (GHSA-gj7r-p794-hhq5), awslabs'
//     generate_cost_report has output_file (GHSA-mqm3-w68j-75mw). The value
//     under such a name is a local file path that gets written, so the rules
//     that protect a path under `path` protect it there too.
//
// Rules that match a file path are written on `path` (argument_patterns,
// argument_patterns_any, argument_regex_patterns, exclude_argument_patterns,
// args_match), and a tool that names the same path otherwise was invisible to
// them: 135 of 148 sampled BLOCK rules went quiet under file_path, filepath,
// file or filename, code-graph-rag's read_file takes file_path
// (GHSA-vvr2-h2jp-838m), and Claude Code's Read, Write and Edit send file_path.
//
// The list is closed. Identifier-style names (name, id, target, ...) are
// deliberately not on it, and neither are plurals (file_paths, files), nor
// other write-destination spellings (output, output_dir, dest_path, outfile,
// ...): a new name is Gary's decision, not a code change. Names are compared after
// normalizeFieldName, the folding resolveField's last fallback applies to
// every rule's field name, so filePath, file-path, FILE_PATH and a confusable
// spelling of file_path are aliases too, exactly as `Path` or `p<U+0430>th`
// already resolve as `path`.
//
// This is not the engine's only list of path-carrying names, and it does not
// replace any of them: pathArgNames (selfprotect_paths.go),
// protectedPathArgKeys (protected_paths.go), filesystemPathArgNames
// (content_scanner.go) and filePathArgName (structural.go, #4747's exclude
// alias) each serve their own pass, and none of those passes reads this one.
var pathArgAliasNames = map[string]bool{
	"filepath": true,
	"file":     true,
	"filename": true,

	"dest":        true,
	"destination": true,
	"outputfile":  true,
	"outputpath":  true,
	"outpath":     true,
	"savepath":    true,
}

// isHarnessFileTool reports whether toolName is one of a harness's own file
// tools, by the lists attributeHarnessRead uses (harnessReadTools,
// harnessWriteTools), compared exactly as it compares them. The alias reading
// is not built for those (Gary, 2026-11-16: MCP server tools only), so they
// keep main's decision and its record-only attribution (#4248 option (c),
// #4457). Known ambiguity, not resolved here: an MCP server tool whose bare
// name is view, create or edit is on those lists too, so it gets no alias
// reading either.
func isHarnessFileTool(toolName string) bool {
	if _, ok := harnessReadTools[toolName]; ok {
		return true
	}
	_, ok := harnessWriteTools[toolName]
	return ok
}

// maxPathAliasReadings bounds how many readings one argument map's alias
// values can cost. Each reading is a full evaluation of the rule set (and of
// its case-fold, separator and /private sub-readings), and a call can carry
// any number of keys that fold to an alias name (file_path, filePath,
// f_i_l_e_path, ...). A real tool sends one. Past the bound, the remaining
// values are presented together, as one list under `path`, in one more
// reading, so every alias value is still read as `path` somewhere: each
// pattern predicate then sees each of them, as it sees the elements of a
// batch's `paths`, and an exclusion in that last reading can be satisfied by
// any one of them (the residual, pinned in path_alias_reading_test.go).
const maxPathAliasReadings = 4

// pathAliasArguments returns the argument-name alias readings of arguments
// (#4937): deep copies in which a value carried under an alias name is also
// presented under `path`, or nil when no map in the call carries an alias
// value that its `path` does not already hold.
//
// Every argument map is read, the top level and every object nested in it
// (envelopes, the items of a batch array) down to maxAnyArgumentValueWalkDepth,
// because those are where resolveFieldValues and dotted field names read
// `path` from. In reading i, every map that has an i-th alias value carries it
// under `path`; a map with fewer keeps its own `path`. So a call with path and
// file_path set to different values gets one alias reading with path set to
// the file_path value, while the as-written reading still evaluates path as
// written. The alias keys themselves stay in the copy, so a rule written on
// file_path matches in the alias reading exactly as in the as-written one.
//
// The input is never mutated: the proxy forwards the caller's arguments
// verbatim. The maps and arrays are copied; the value presented under `path`
// is the caller's own value, shared, and no part of the evaluation writes to
// an argument value.
func pathAliasArguments(arguments map[string]interface{}) []map[string]interface{} {
	n := maxPathAliasValues(arguments, 0)
	if n == 0 {
		return nil
	}
	if n > maxPathAliasReadings {
		n = maxPathAliasReadings + 1
	}
	out := make([]map[string]interface{}, n)
	for i := range out {
		out[i] = pathAliasReading(arguments, i, 0).(map[string]interface{})
	}
	return out
}

// pathAliasValues is every value m carries under an alias name, in key order,
// each distinct value once and none equal to the `path` m already resolves
// (that one the as-written reading presents). Keys are sorted so the readings
// are the same run to run: Go map order is not.
func pathAliasValues(m map[string]interface{}) []interface{} {
	var keys []string
	var vals map[string]interface{}
	for k, v := range m {
		if pathArgAliasNames[normalizeFieldName(k)] {
			if vals == nil {
				vals = make(map[string]interface{}, 1)
			}
			keys = append(keys, k)
			vals[k] = v
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	existing, hasPath := resolveField(m, "path")
	var out []interface{}
	for _, k := range keys {
		v := vals[k]
		if hasPath && reflect.DeepEqual(v, existing) {
			continue
		}
		dup := false
		for _, seen := range out {
			if reflect.DeepEqual(v, seen) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}

// maxPathAliasValues is the largest number of alias values (pathAliasValues)
// any map in v carries.
func maxPathAliasValues(v interface{}, depth int) int {
	if depth > maxAnyArgumentValueWalkDepth {
		return 0
	}
	best := 0
	switch t := v.(type) {
	case map[string]interface{}:
		best = len(pathAliasValues(t))
		for _, x := range t {
			if n := maxPathAliasValues(x, depth+1); n > best {
				best = n
			}
		}
	case []interface{}:
		for _, x := range t {
			if n := maxPathAliasValues(x, depth+1); n > best {
				best = n
			}
		}
	}
	return best
}

// pathAliasReading is a copy of v in which every map with an i-th alias value
// carries that value under `path`. Reading maxPathAliasReadings is the
// overflow reading: a map with more alias values than the bound carries the
// rest under `path` as one list (a list value contributes its elements).
func pathAliasReading(v interface{}, i, depth int) interface{} {
	if depth > maxAnyArgumentValueWalkDepth {
		return v
	}
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t)+1)
		for k, x := range t {
			out[k] = pathAliasReading(x, i, depth+1)
		}
		vals := pathAliasValues(t)
		switch {
		case i < maxPathAliasReadings && i < len(vals):
			out["path"] = vals[i]
		case i == maxPathAliasReadings && len(vals) > maxPathAliasReadings:
			var rest []interface{}
			for _, x := range vals[maxPathAliasReadings:] {
				if list, ok := x.([]interface{}); ok {
					rest = append(rest, list...)
				} else {
					rest = append(rest, x)
				}
			}
			out["path"] = rest
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for j, x := range t {
			out[j] = pathAliasReading(x, i, depth+1)
		}
		return out
	}
	return v
}
