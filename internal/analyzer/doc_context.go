package analyzer

// DocContextExcludePattern is the canonical regex for suppressing security rule
// matches that fire on documentation/message text rather than executable code.
//
// SAFE to exclude: git -m, gh --body/--title, echo/printf, logger, say,
//   notify-send, npm/yarn version -m, aws sns --message, gcloud --description,
//   kubectl annotate/label, docker --label, buildkite-agent annotate,
//   bash comments (^#), tee heredocs, agentshield management subcommands.
//
// NOT excluded (UNSAFE): bash -c, ssh "cmd", curl -d, osascript -e, eval, exec,
//   kubectl exec, docker exec — these are execution vectors.
//
// NOT excluded (DELIBERATE): `git clone <url>`, `gh api ...`, `gh repo sync` —
//   these are real network operations that rules should still evaluate.
//   Rules needing a broader gh/git exclude should hand-roll their own pattern.
//
// Rules reference this via command_regex_exclude: "{{DOC_CONTEXT}}" in YAML,
// which the policy loader expands at load time.
const DocContextExcludePattern = `` +
	// Bash comment — ^# is a no-op; content never executes.
	`^\s*#` +
	// echo/printf — all args are display text
	`|^(echo|printf)\s` +
	// git commit/tag/notes/stash/merge -m/-F/--message/--file
	// Handles compound commands like `cd /dir && git commit -m "..."`.
	// -F/--file reads the message from a file (commit/tag/notes), still doc-context.
	`|(?:^|&&\s*|;\s*)git\s+(?:commit|tag|notes\s+(?:add|edit|append)|stash(?:\s+(?:push|save))?|merge)\b.*(?:\s-[mF]\s|\s--(?:message|file)[\s=])` +
	// gh issue/pr/release/gist/repo --body/--title/--notes/--description
	// Handles both standalone (`gh issue create --body ...`) and compound commands
	// (`cd /dir && gh issue create --body ...`) where gh appears after && or ;.
	`|(?:^|&&\s*|;\s*)gh\s+(?:issue|pr|release|gist|repo)\s+\S+\b.*\s--(?:body(?:-file)?|title|notes|description)(?:\s|=)` +
	// gh short flags -b -t
	`|(?:^|&&\s*|;\s*)gh\s+.*\s-[bt]\s` +
	// System messaging
	`|^(logger|wall|say|notify-send|terminal-notifier)\s` +
	// npm/yarn version -m/--message
	`|^(npm|yarn)\s+version\s.*(?:\s-m\s|\s--message[\s=])` +
	// AWS SNS publish --message
	`|^aws\s+sns\s+publish\s+.*--message[\s=]` +
	// gcloud --description
	`|^gcloud\s+.*\s--description\s` +
	// docker build/run --label, kubectl annotate/label
	`|^docker\s+(?:build|run)\s+.*--label\s` +
	`|^kubectl\s+(?:annotate|label)\s` +
	// buildkite annotation
	`|^buildkite-agent\s+annotate\s` +
	// heredoc (cat or tee) — content after << is documentation/data, not code.
	// Symmetric: `cat > file << EOF` and `tee /path/to/file << EOF` are both write-
	// via-heredoc; the body is data, not an execution vector.
	`|^\s*(cat|tee)\s+.*<<` +
	// agentshield management subcommands — all are local self-management, not threats.
	// Explicit allowlist: `agentshield run` is excluded (removed; was an execution vector).
	// Uses (?:\s|$) so bare subcommands (e.g. `agentshield scan`) match too.
	`|agentshield\s+(?:mcp-eval|scan|setup|setup-mcp|pack|log|watchdog|update|login)(?:\s|$)`
