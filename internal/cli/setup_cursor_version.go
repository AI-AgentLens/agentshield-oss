package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// cursorHooksContent is the ~/.cursor/hooks.json that `setup cursor` writes.
// Cursor ignores the whole file without a numeric "version"
// (hookentry.CursorConfigProblem). From 4f8c594f (2026-02-08) until #5113,
// setup wrote no version, so Cursor never ran the hook, while status reported
// it active.
const cursorHooksContent = `{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`

// addCursorHooksVersion returns data with a top-level "version": 1 as its
// first member, replacing any "version" it had. It keeps every other
// top-level member in order and byte for byte, apart from indentation. It
// refuses anything that is not a single JSON object (#5113).
func addCursorHooksVersion(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("hooks.json is not a JSON object")
	}
	var obj bytes.Buffer
	obj.WriteString(`{"version":1`)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if key == "version" {
			continue
		}
		name, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		obj.WriteByte(',')
		obj.Write(name)
		obj.WriteByte(':')
		obj.Write(value)
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("hooks.json has data after its JSON object")
	}
	obj.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, obj.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
