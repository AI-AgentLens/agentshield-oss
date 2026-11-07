# AgentShield — Notice

AgentShield is installed on this machine, but **it is not evaluating your
commands in this OpenClaw session**. OpenClaw has no integration that sends
its shell commands or tool calls to AgentShield, so nothing you run is
checked, logged or blocked by it.

Do not assume a command is safe because no AgentShield message appeared.
Apply your own judgement to destructive or credential-touching commands, and
ask the user before running them.

> **Historical note.** Earlier AgentShield builds exposed an
> `agentshield run -- <cmd>` subcommand. It was removed. Do not invoke it.
