package shellparse

import "testing"

func TestStripGitGlobalOptions(t *testing.T) {
	cases := []struct{ in, want string }{
		{`git -C /tmp/repo commit -n -m "msg"`, `git commit -n -m "msg"`},
		{`git -c user.name=x commit -n -m msg`, `git commit -n -m msg`},
		{`git -C /a -c k=v commit -n`, `git commit -n`},
		{`git --git-dir /a/.git --work-tree /a commit -n`, `git commit -n`},
		{`sudo git -C /r commit -n`, `sudo git commit -n`},
		{`cd x && git -C /r commit -n`, `cd x && git commit -n`},
		// nothing to strip
		{`git commit -n -m msg`, ``},
		{`git --no-pager commit -n`, ``},
		{`git --git-dir=/a/.git commit -n`, ``},
		// an option AFTER the subcommand is the subcommand's own (git commit -C <commit>)
		{`git commit -C HEAD -n`, ``},
		{`git log -c abc`, ``},
		// not git
		{`echo -C /tmp commit -n`, ``},
		{`ls`, ``},
	}
	for _, c := range cases {
		if got := StripGitGlobalOptions(c.in); got != c.want {
			t.Errorf("StripGitGlobalOptions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
