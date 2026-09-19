// Package mountspec splits container bind-mount specifications into the host
// paths they name.
//
// `docker run -v <hostdir>:/mnt image` hands the container the bytes of
// <hostdir> as surely as `cat` does, but the argv token is `<hostdir>:/mnt`
// and the trailing `:` defeats every protected-path glob. Measured on main
// 2026-09-05 (issue #3630) across the 22 protected_paths patterns the shipped
// community pack declares, crossed with 13 spellings: 286/286 probes that
// mounted a protected credential directory into a container escaped the
// protected-path layer entirely, and 254/286 were not blocked by anything.
//
// This package is deliberately a leaf: it knows how docker/podman spell a
// mount and nothing about policy. Three callers decide what a source means:
//
//   - internal/normalize — adds literal sources to the extracted path list, so
//     the engine's pre-pipeline protected-path check sees them.
//   - internal/analyzer/substitution — adds sources that only become concrete
//     after variable substitution (`V=$HOME/…; docker run -v $V:/mnt img`).
//   - internal/policy/consumers — counts a source as a NON-consumer use, so a
//     designated consumer elsewhere in the same command (`ssh -i key host &&
//     docker run -v <creddir>:/mnt img`) cannot launder the mount into the
//     protected-path-consumer downgrade.
//
// Scope, stated so it is reviewable rather than assumed:
//
//   - Only the SOURCE (host) side is a read. The container-side target is a
//     path inside the container's namespace and is deliberately ignored.
//   - No subcommand filter. `run`/`create` are the shapes that matter today,
//     but `-v <a>:<b>` is meaningless on docker's other subcommands, so the
//     spec shape is the filter — and a subcommand allowlist would be one
//     `docker container run` away from a bypass.
//   - A source with no `/` (a named volume, `-v myvol:/data`) is not a host
//     path and is dropped here rather than at the glob, which keeps the
//     candidate list small.
package mountspec

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// containerRuntimes are the CLIs whose run/create verbs take host bind-mount
// specs in the docker spelling. Keep this list to tools that share docker's
// `-v src:dst` and `--mount type=bind,source=…` grammar; anything with a
// different grammar needs its own extractor, not an entry here.
var containerRuntimes = map[string]bool{
	"docker":  true,
	"podman":  true,
	"nerdctl": true,
}

// IsContainerRuntime reports whether exe is such a CLI. The path is stripped
// so /usr/bin/docker and docker both match.
func IsContainerRuntime(exe string) bool {
	if i := strings.LastIndexByte(exe, '/'); i >= 0 {
		exe = exe[i+1:]
	}
	return containerRuntimes[exe]
}

// Sources returns the host-side paths named by bind-mount flags in args.
//
// args is one command segment's own argv with the executable EXCLUDED (the
// shape shellparse.CommandSegment.RawWords already has). Words keep their
// quote characters; they are stripped here.
//
// A flag's value is read from the next word without consuming it, so a
// malformed line (`docker run -v -v <spec>`) still surfaces the real spec on
// the following iteration instead of swallowing it.
func Sources(args []string) []string {
	var out []string
	for i, arg := range args {
		flag, inlineVal, hasInline := strings.Cut(arg, "=")
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}

		var spec string
		var parse func(string) string

		switch flag {
		case "-v", "--volume":
			parse = volumeSource
		case "--mount":
			parse = mountSource
		default:
			continue
		}
		if hasInline {
			spec = inlineVal
		} else {
			spec = next
		}
		if spec == "" {
			continue
		}
		if src := parse(spec); src != "" {
			out = append(out, src)
		}
	}
	return out
}

// volumeSource returns the host side of a `src:dst[:opts]` volume spec, or ""
// when the spec names no host path (an anonymous volume `-v /data`, a named
// volume `-v myvol:/data`, or a flag that landed here by accident).
func volumeSource(spec string) string {
	parts := strings.Split(normalizeToken(spec), ":")
	if len(parts) < 2 {
		// `-v /data` is an anonymous container volume, not a host mount.
		return ""
	}
	return hostPath(parts[0])
}

// mountSource returns the `source=`/`src=` value of a `--mount` spec.
//
// The mount type is not checked: `type=volume,source=myvol` names a volume,
// not a path, and hostPath drops it — one fewer keyword to keep in sync with
// docker, and no way for a novel type to slip a real host path past.
func mountSource(spec string) string {
	for _, field := range strings.Split(normalizeToken(spec), ",") {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "source", "src":
			return hostPath(val)
		}
	}
	return ""
}

// normalizeToken resolves a spec the way a shell would spell it: quote
// splices removed, surrounding quotes dropped, a leading $HOME read as ~.
// Mirrors the order in policy.isProtectedToken so the two surfaces agree.
func normalizeToken(s string) string {
	s = pathnorm.StripShellQuotes(s)
	s = strings.Trim(s, `"'`)
	return pathnorm.FoldHomeVar(s)
}

// hostPath returns s when it names a filesystem location, "" otherwise. It
// re-normalizes because a source may be quoted on its own inside an otherwise
// unquoted spec (`-v "$HOME/dir":/mnt`), which the whole-spec pass leaves with
// a stray quote — StripShellQuotes returns any token containing `$`
// unchanged, quotes included.
func hostPath(s string) string {
	s = normalizeToken(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "~") || strings.Contains(s, "/") {
		return s
	}
	return ""
}
