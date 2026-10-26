package policy

import (
	"fmt"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"gopkg.in/yaml.v3"
)

// OptInSwitch is a boolean policy switch that can never fail a policy load.
//
// It exists for network.enforce_allowlist (#4437). A plain `bool` field makes
// `enforce_allowlist: yes` a YAML type error, and a policy that fails to load
// turns every command into an eval-error AUDIT (a BLOCK under fail_closed).
// A typo in an opt-in switch must cost the opt-in, not the whole policy. So
// the raw node is kept, Enabled is true only for a YAML boolean true, and
// any other value is reported by Policy.ConfigWarnings and treated as off.
//
// The node is written back unchanged, so `agentshield rule disable`, which
// re-marshals the user's policy file, keeps the operator's switch as written;
// IsZero drops the key when it was never set.
type OptInSwitch struct {
	node *yaml.Node
}

// UnmarshalYAML keeps the node as written and never returns an error. A YAML
// null never reaches it (yaml.v3 zeroes the field instead), so `key:` and
// `key: ~` read as absent.
func (s *OptInSwitch) UnmarshalYAML(n *yaml.Node) error {
	c := *n
	s.node = &c
	return nil
}

// MarshalYAML writes the node back as it was read.
func (s OptInSwitch) MarshalYAML() (interface{}, error) {
	if s.node == nil {
		return nil, nil
	}
	return s.node, nil
}

// IsZero reports an absent switch, for omitempty.
func (s OptInSwitch) IsZero() bool { return s.node == nil }

// Enabled reports whether the switch is a YAML boolean true.
func (s OptInSwitch) Enabled() bool {
	on, _ := s.state()
	return on
}

// state returns the switch value and whether the written value is valid.
// Absent is valid and off. Only a plain YAML boolean scalar is a value:
// a quoted "true", `yes`, `1`, a list or a map are invalid, and off.
func (s OptInSwitch) state() (on, valid bool) {
	if s.node == nil {
		return false, true
	}
	if s.node.Kind != yaml.ScalarNode || s.node.ShortTag() != "!!bool" {
		return false, false
	}
	var b bool
	if err := s.node.Decode(&b); err != nil {
		return false, false
	}
	return b, true
}

// written renders the switch value for a warning.
func (s OptInSwitch) written() string {
	if s.node == nil {
		return ""
	}
	if s.node.Kind == yaml.ScalarNode {
		return fmt.Sprintf("%q", s.node.Value)
	}
	return "a " + map[yaml.Kind]string{
		yaml.SequenceNode: "list",
		yaml.MappingNode:  "mapping",
		yaml.AliasNode:    "alias",
		yaml.DocumentNode: "document",
	}[s.node.Kind]
}

// EgressAllowlistEnforced reports whether the opt-in outbound allowlist is on.
func (p *Policy) EgressAllowlistEnforced() bool {
	return p != nil && p.Network.EnforceAllowlist.Enabled()
}

// OperatorAllowDomains returns network.allow_domains exactly as the
// operator's policy file wrote it — not the built-in defaults, not pack
// entries. nil when the policy did not come from Load with a user file.
func (p *Policy) OperatorAllowDomains() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.Network.operatorAllowDomains...)
}

// egressAllowlistAnalyzer returns the conditional pipeline stage, or nil when
// the switch is off. Entries it cannot read are ignored here and reported by
// ConfigWarnings.
func egressAllowlistAnalyzer(p *Policy) analyzer.Analyzer {
	if !p.EgressAllowlistEnforced() {
		return nil
	}
	list, _ := analyzer.NewEgressAllowlist(p.Network.operatorAllowDomains)
	return analyzer.NewEgressAllowlistAnalyzer(list)
}

// ConfigWarnings returns problems with settings that load leniently instead of
// failing the policy. Each is one line, suitable for stderr. Empty when there
// is nothing to say; never consulted by a decision.
func (p *Policy) ConfigWarnings() []string {
	if p == nil {
		return nil
	}
	var out []string
	on, valid := p.Network.EnforceAllowlist.state()
	if !valid {
		out = append(out, fmt.Sprintf("network.enforce_allowlist is %s, not true or false — the outbound allowlist is OFF", p.Network.EnforceAllowlist.written()))
	}
	if !on {
		return out
	}
	if len(p.Network.operatorAllowDomains) == 0 {
		out = append(out, "network.enforce_allowlist is true but network.allow_domains in your policy file is empty — every network command whose destination Shield can name, other than loopback, will be blocked")
	}
	if _, invalid := analyzer.NewEgressAllowlist(p.Network.operatorAllowDomains); len(invalid) > 0 {
		quoted := make([]string, len(invalid))
		for i, e := range invalid {
			quoted[i] = fmt.Sprintf("%q", e)
		}
		out = append(out, fmt.Sprintf("network.allow_domains entries %s are not a host, *.host or IP address — ignored by the outbound allowlist", strings.Join(quoted, ", ")))
	}
	return out
}
