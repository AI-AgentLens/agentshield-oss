package analyzer

// DocContextExcludePattern is the canonical regex for suppressing security rule
// matches that fire on documentation/message text rather than executable code.
//
// SAFE to exclude: git -m, gh --body/--title, echo/printf, logger, say,
//   notify-send, npm/yarn version -m, aws sns --message, gcloud --description,
//   kubectl annotate/label, docker --label, buildkite-agent annotate.
//
// NOT excluded (UNSAFE): bash -c, ssh "cmd", curl -d, osascript -e, eval, exec,
//   kubectl exec, docker exec — these are execution vectors.
//
// Rules reference this via command_regex_exclude: "{{DOC_CONTEXT}}" in YAML,
// which the policy loader expands at load time.
const DocContextExcludePattern = `` +
	// echo/printf — all args are display text
	`^(echo|printf)\s` +
	// git commit/tag/notes/stash/merge -m/--message
	`|^git\s+(?:commit|tag|notes\s+(?:add|edit|append)|stash(?:\s+(?:push|save))?|merge)\b.*(?:\s-m\s|\s--message[\s=])` +
	// gh issue/pr/release/gist/repo --body/--title/--notes/--description
	`|^gh\s+(?:issue|pr|release|gist|repo)\s+\S+\b.*\s--(?:body(?:-file)?|title|notes|description)(?:\s|=)` +
	// gh short flags -b -t
	`|^gh\s+.*\s-[bt]\s` +
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
	// heredoc — content after << is documentation text (both cat > file << and cat << EOF > file)
	`|^\s*cat\s+.*<<` +
	// agentshield internal eval (always safe)
	`|agentshield\s+mcp-eval\s`
