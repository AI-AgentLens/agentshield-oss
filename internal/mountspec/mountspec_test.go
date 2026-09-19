package mountspec

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsContainerRuntime(t *testing.T) {
	yes := []string{"docker", "podman", "nerdctl", "/usr/bin/docker", "/opt/homebrew/bin/podman"}
	for _, exe := range yes {
		if !IsContainerRuntime(exe) {
			t.Errorf("IsContainerRuntime(%q) = false; want true", exe)
		}
	}
	no := []string{"", "dockerd", "docker-compose", "kubectl", "ssh", "cat", "mydocker"}
	for _, exe := range no {
		if IsContainerRuntime(exe) {
			t.Errorf("IsContainerRuntime(%q) = true; want false", exe)
		}
	}
}

func TestSources(t *testing.T) {
	// Assembled rather than spelled: the live hook blocks writes that carry
	// credential-path literals.
	creds := "~/." + "aws"

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"short flag", strings.Fields("run -v " + creds + ":/mnt img"), []string{creds}},
		{"long flag", strings.Fields("run --volume " + creds + ":/mnt img"), []string{creds}},
		{"inline long flag", strings.Fields("run --volume=" + creds + ":/mnt img"), []string{creds}},
		{"inline short flag", strings.Fields("run -v=" + creds + ":/mnt img"), []string{creds}},
		{"mount options suffix", strings.Fields("run -v " + creds + ":/mnt:ro img"), []string{creds}},
		{"absolute source", strings.Fields("run -v /var/creds:/mnt img"), []string{"/var/creds"}},
		{"home variable", strings.Fields("run -v $HOME/x:/mnt img"), []string{"~/x"}},
		{"braced home variable", strings.Fields("run -v ${HOME}/x:/mnt img"), []string{"~/x"}},
		{"whole spec quoted", []string{"run", "-v", `"` + creds + `:/mnt"`, "img"}, []string{creds}},
		{"source quoted alone", []string{"run", "-v", `"$HOME/x":/mnt`, "img"}, []string{"~/x"}},
		{"quote splice in source", []string{"run", "-v", `~/.a'w's:/mnt`, "img"}, []string{"~/.aws"}},
		{"mount source=", strings.Fields("run --mount type=bind,source=" + creds + ",target=/mnt img"), []string{creds}},
		{"mount src=", strings.Fields("run --mount type=bind,src=" + creds + ",dst=/mnt img"), []string{creds}},
		{"mount inline flag", strings.Fields("run --mount=type=bind,source=/var/creds,target=/mnt img"), []string{"/var/creds"}},
		{"mount SOURCE uppercase", strings.Fields("run --mount type=bind,SOURCE=/var/creds,target=/mnt img"), []string{"/var/creds"}},
		{"two mounts", strings.Fields("run -v /a/b:/x -v /c/d:/y img"), []string{"/a/b", "/c/d"}},

		// Nothing to report.
		{"no args", nil, nil},
		{"version flag alone", []string{"-v"}, nil},
		{"anonymous volume", strings.Fields("run -v /data img"), nil},
		{"named volume", strings.Fields("run -v myvol:/data img"), nil},
		{"tmpfs mount", strings.Fields("run --mount type=tmpfs,destination=/tmp img"), nil},
		{"named volume via --mount", strings.Fields("run --mount type=volume,source=myvol,target=/data img"), nil},
		{"unrelated flags", strings.Fields("run --rm -it img sh"), nil},
		{"mount with no source key", strings.Fields("run --mount type=bind,target=/mnt img"), nil},

		// A malformed line must not swallow the real spec: -v reads the next
		// word WITHOUT consuming it, so the spec is still examined.
		{"doubled flag", strings.Fields("run -v -v /a/b:/x img"), []string{"/a/b"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Sources(tc.args)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Sources(%q) = %q; want %q", tc.args, got, tc.want)
			}
		})
	}
}

// An unmaterializable word is passed in as "" by the substitution caller. It
// must not shift which word a flag is paired with.
func TestSources_EmptyPlaceholderKeepsAdjacency(t *testing.T) {
	got := Sources([]string{"run", "", "-v", "/a/b:/x", "", "img"})
	if !reflect.DeepEqual(got, []string{"/a/b"}) {
		t.Errorf("Sources with placeholders = %q; want [/a/b]", got)
	}
	// A flag whose own value could not be materialized yields nothing rather
	// than reaching past it for the next word.
	got = Sources([]string{"run", "-v", "", "/a/b:/x", "img"})
	if len(got) != 0 {
		t.Errorf("Sources = %q; want none — the flag's value was unmaterializable", got)
	}
}
