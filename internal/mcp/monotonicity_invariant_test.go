package mcp

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4204 — adding an AUDIT-tier trigger to an input never lowers its decision.
//
// #4169 (a new route skipped the old scanners) and #4190 → #4193 (a new AUDIT
// return pre-empted the BLOCK checks below it) were each classed "additive" and
// each lowered a BLOCK. Both were found only by a before/after probe. This is
// that probe, table-driven from the scanners' own TP tables
// (elicitationUnsafeTargetURLs, iconBlockTierSources), so a new TP is covered
// without editing this file. Attack strings come from those tables; the
// internal-network addresses are assembled at runtime.

// elicitationBlockSignals returns the BLOCK-tier signals in a scan.
func elicitationBlockSignals(r ElicitationScanResult) []string {
	set := map[string]bool{}
	for _, f := range r.Findings {
		if elicitationURLSignalBlocks(f.Signal) {
			set[string(f.Signal)] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func elicitationNestingPad() string {
	pad := "https://example.com/done"
	for i := 0; i < maxDeeplinkNesting+2; i++ {
		pad = "https://example.com/r?next=" + url.QueryEscape(pad)
	}
	return url.QueryEscape(pad)
}

// elicitationAuditTriggers are the transforms that add an AUDIT-tier trigger
// (nesting past the cap, cleartext http, an IDN host) to a URL. A transform
// that does not apply to a URL returns it unchanged and is skipped.
var elicitationAuditTriggers = map[string]func(u string) string{
	"nesting padding": func(u string) string {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		return u + sep + "next=" + elicitationNestingPad()
	},
	"cleartext http": func(u string) string {
		if strings.HasPrefix(u, "https://") {
			return "http://" + strings.TrimPrefix(u, "https://")
		}
		return u
	},
	"idn host": func(u string) string {
		at := strings.Index(u, "@")
		if at < 0 || !strings.HasPrefix(u, "http") {
			return u
		}
		end := strings.IndexAny(u[at:], "/?#")
		if end < 0 {
			return u[:at+1] + "xn--e1afmkfd.example"
		}
		return u[:at+1] + "xn--e1afmkfd.example" + u[at+end:]
	},
}

func TestMonotonicity_ElicitationURL_AuditTriggerNeverLowersBlock(t *testing.T) {
	var applied int
	for _, base := range elicitationUnsafeTargetURLs {
		control := ScanElicitationCreate(urlElicitation(base))
		want := elicitationBlockSignals(control)
		if !control.Blocked || len(want) == 0 {
			t.Fatalf("control %q must BLOCK unmodified: %+v", base, control)
		}
		for name, trig := range elicitationAuditTriggers {
			u := trig(base)
			if u == base {
				continue
			}
			applied++
			r := ScanElicitationCreate(urlElicitation(u))
			got := elicitationBlockSignals(r)
			if !r.Blocked || strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s on %q lowered the verdict: want BLOCK %v, got blocked=%v %v (%+v)", name, base, want, r.Blocked, got, r.Findings)
			}
		}
	}
	// Vacuity floor: every trigger must have applied to at least one URL.
	if applied < len(elicitationAuditTriggers) {
		t.Fatalf("only %d trigger applications; the probe is vacuous", applied)
	}
	for name, trig := range elicitationAuditTriggers {
		hit := false
		for _, base := range elicitationUnsafeTargetURLs {
			if trig(base) != base {
				hit = true
			}
		}
		if !hit {
			t.Errorf("trigger %q applied to no BLOCK-tier URL; it tests nothing", name)
		}
	}
	// Positive control: each trigger on a benign https URL does produce its
	// AUDIT finding, so "no lowering" is not "the trigger never fired".
	for name, u := range map[string]string{
		"nesting padding": elicitationAuditTriggers["nesting padding"]("https://example.com/cb"),
		"cleartext http":  "http://intranet.corp.example/sso",
		"idn host":        "https://xn--e1afmkfd.example/login",
	} {
		r := ScanElicitationCreate(urlElicitation(u))
		if r.Blocked || len(findingsBySignal(r, SignalElicitationURLWeakTarget)) == 0 {
			t.Errorf("positive control %q: want AUDIT weak-target, got %+v", name, r)
		}
	}
}

// internalIconIPs spells the metadata address every way #4200 recognises.
func internalIconHosts() []string {
	return []string{
		"169.254." + "169.254", "2852039166", "0xa9fea9fe", "0251.0376.0251.0376",
		"169.254.43774", "10.0.0.5", "192.168.1.1", "[fd00::1]", "metadata.google" + ".internal",
	}
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestMonotonicity_IconSrc_InternalHostNeverLowersBlock(t *testing.T) {
	hosts := internalIconHosts()
	// Positive control: the internal hosts really are AUDIT-tier icons.
	for _, h := range hosts {
		if internalIconHost("http://"+h+"/i.png") == "" {
			t.Fatalf("positive control: http://%s/ is not an internal icon host", h)
		}
	}
	for _, name := range sortedStringKeys(iconBlockTierSources) {
		b := iconBlockTierSources[name]
		if len(scanIconsFor("tool", []ToolIcon{{Src: b}})) != 1 {
			t.Fatalf("control %q must be BLOCK-tier", name)
		}
		for _, h := range hosts {
			// Same entry, internal icon first and last: the BLOCK finding stays.
			for label, icons := range map[string][]ToolIcon{
				"before": {{Src: "http://" + h + "/i.png"}, {Src: b}},
				"after":  {{Src: b}, {Src: "http://" + h + "/i.png"}},
			} {
				if got := scanIconsFor("tool", icons); len(got) != 1 || got[0].Signal != SignalIconUnsafeSource {
					t.Errorf("internal icon %s %q (host %s) lowered the BLOCK: %+v", label, name, h, got)
				}
			}
		}
	}
	// An internal-network address as the HOST of a BLOCK-tier target.
	for _, h := range hosts {
		for _, src := range []string{
			"smb://" + h + "/share/i.png",
			"file://" + h + "/share/i.png",
			`\\` + h + `\share\i.png`,
		} {
			if got := scanIconsFor("tool", []ToolIcon{{Src: src}}); len(got) != 1 {
				t.Errorf("%q: internal host lowered the BLOCK-tier target: %+v", src, got)
			}
		}
	}
}

// The wire form of the same invariant: an entry carrying an internal-network
// icon BEFORE a BLOCK-tier icon is still hidden, on every listing surface.
func TestMonotonicity_IconListing_InternalIconDoesNotKeepEntry(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	internal := "http://" + internalIconHosts()[0] + "/i.png"
	for _, s := range iconSurfaces {
		for _, name := range sortedStringKeys(iconBlockTierSources) {
			b := iconBlockTierSources[name]
			t.Run(s.key+"/"+name, func(t *testing.T) {
				ia, _ := json.Marshal(internal)
				ba, _ := json.Marshal(b)
				icons := `[{"src":` + string(ia) + `},{"src":` + string(ba) + `}]`
				var audits []AuditEntry
				out := s.filter(iconPackHandler(t, &audits))(iconRawWire(s.list(s.entry("p", `"icons":`+icons))))
				if out == nil || strings.Contains(string(out), `"p"`) {
					t.Fatalf("entry must be hidden, got %s", out)
				}
				var blocks int
				for _, a := range audits {
					if a.Decision == "BLOCK" {
						blocks++
					}
				}
				if blocks != 1 {
					t.Errorf("want exactly one BLOCK receipt, got %+v", audits)
				}
			})
		}
	}
}
