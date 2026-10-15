<#
AgentShield remote hook - agentless PowerShell thin client (issue #4244).

Statement of purpose (point of coupling): the PowerShell twin of
clients/agentshield-remote-hook.py. It exists so a Windows host can have its
agent's tool calls evaluated with NOTHING installed - no AgentShield binary
(releases are darwin/linux only) and no Python - by POSTing each call to a
shield-server. It speaks the same PreToolUse contract as `agentshield hook`
(internal/cli/hook.go) and the Python client; keep the three in lock-step.
cmd/shield-server/hook_client_pwsh_integration_test.go pins this script's
contract against the real server, including parity with the Python client.

Harness support:
  GitHub Copilot CLI - both hook dialects:
    * Claude-compatible ("PreToolUse", PascalCase event): snake_case
      hook_event_name / tool_name / tool_input; Copilot maps its tools to Claude
      names, and BOTH `bash` and `powershell` arrive as tool_name "Bash".
    * native ("preToolUse", camelCase event): toolName / toolArgs, with runtime
      tool names (bash, powershell, view, create, edit, ...).
  Claude Code / Codex CLI payloads are accepted too (same Claude shape).

Verdict output (works for every harness above):
  BLOCK -> stdout {"permissionDecision":"deny","permissionDecisionReason":...},
           human-readable reason on stderr, exit 2. Copilot treats exit 2 as a
           deny and merges the stdout JSON; Claude Code reads stderr on exit 2.
  ALLOW / AUDIT -> nothing on stdout, exit 0.

Fail-open by default - and why exit codes need care here: Copilot DENIES on
any non-zero hook exit other than 2 ("hook errored"), the opposite of Claude
Code. So every failure path below (unparseable input, server down, HTTP error,
bad response) ends in an explicit `exit 0` with a stderr warning, unless
AGENTSHIELD_REMOTE_FAIL_CLOSED=1 asks for a block.

Configuration (environment):
  AGENTSHIELD_SERVER_URL              default http://127.0.0.1:8383
  AGENTSHIELD_SERVER_TOKEN            bearer token, if the server requires one
  AGENTSHIELD_REMOTE_TIMEOUT_SECONDS  default 5 (Copilot's hook timeout is 30)
  AGENTSHIELD_REMOTE_FAIL_CLOSED      "1" = block when the server is unreachable
  AGENTSHIELD_AGENT_ID                identity recorded on the verdict; default
                                      "copilot-cli" ("codex" when turn_id is set)

Copilot hook entry (.github/hooks/agentshield.json or ~/.copilot/hooks/):
  {"version": 1, "hooks": {"PreToolUse": [{"type": "command",
    "powershell": "pwsh -NoProfile -NonInteractive -File C:\\path\\agentshield-remote-hook.ps1",
    "timeoutSec": 30}]}}
Use -File, not -Command: -File is what makes `exit 2` the process exit code.

Compatibility: Windows PowerShell 5.1 and PowerShell 7+. No 7-only syntax
(no ??, ternary, &&, -AsHashtable). The source is ASCII-only because 5.1 reads
a BOM-less script as the ANSI code page.

Limitation (#4245): PowerShell COMMAND TEXT is sent to the server's shell
pipeline, whose analyzers parse POSIX shell. Most PowerShell attack shapes get
the default AUDIT - recorded, not blocked. File and MCP tool calls are fully
evaluated (Windows paths included, #4243).

This client EVALUATES via the server and never executes anything.
#>

$ErrorActionPreference = 'Stop'
$BlockExit = 2
$Shield = [char]::ConvertFromUtf32(0x1F6E1)

function Write-Warn([string]$Message) {
    [Console]::Error.WriteLine("[AgentShield] warning: $Message")
}

function Get-EnvOr([string]$Name, [string]$Default) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($v)) { return $Default }
    return $v
}

# Property lookup that works for PSCustomObject (ConvertFrom-Json) and
# hashtables, and returns $null instead of throwing under StrictMode.
function Get-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Test-Field($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Write-Block([string]$Header, $Verdict) {
    $rules = @(Get-Field $Verdict 'rules')
    $reasons = @(Get-Field $Verdict 'reasons')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("$Shield AgentShield $Header")
    if ($rules.Count -gt 0 -and $null -ne $rules[0]) { $lines.Add("   Rule: " + ($rules -join ', ')) }
    foreach ($r in $reasons) { if ($null -ne $r) { $lines.Add("   Reason: $r") } }
    foreach ($l in $lines) { [Console]::Error.WriteLine($l) }
    $remediation = Get-Field $Verdict 'remediation'
    if (-not [string]::IsNullOrEmpty($remediation)) { [Console]::Error.Write($remediation) }

    # Copilot surfaces permissionDecisionReason to the agent; it is required
    # when denying. Plain ASCII header so it renders on any console code page.
    $reasonText = (@("AgentShield $Header") + @($lines | Select-Object -Skip 1 | ForEach-Object { $_.Trim() })) -join ' | '
    $out = @{ permissionDecision = 'deny'; permissionDecisionReason = $reasonText }
    [Console]::Out.Write(($out | ConvertTo-Json -Compress))
}

function Exit-FailOpenOrClosed([string]$Message) {
    if ((Get-EnvOr 'AGENTSHIELD_REMOTE_FAIL_CLOSED' '') -eq '1') {
        $verdict = @{ reasons = @("shield-server unreachable and fail-closed is enabled ($Message)") }
        Write-Block 'BLOCKED this action' $verdict
        exit $BlockExit
    }
    Write-Warn "$Message - allowing (fail open; set AGENTSHIELD_REMOTE_FAIL_CLOSED=1 to block instead)"
    exit 0
}

function Invoke-Evaluate($Body) {
    $url = (Get-EnvOr 'AGENTSHIELD_SERVER_URL' 'http://127.0.0.1:8383').TrimEnd('/') + '/v1/evaluate'
    $timeout = [int][double](Get-EnvOr 'AGENTSHIELD_REMOTE_TIMEOUT_SECONDS' '5')
    if ($timeout -lt 1) { $timeout = 1 }
    $headers = @{}
    $token = Get-EnvOr 'AGENTSHIELD_SERVER_TOKEN' ''
    if ($token -ne '') { $headers['Authorization'] = "Bearer $token" }
    if ($url.StartsWith('https:', [StringComparison]::OrdinalIgnoreCase)) {
        # Windows PowerShell 5.1 does not offer TLS 1.2 by default.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $json = $Body | ConvertTo-Json -Depth 64 -Compress
    # Send UTF-8 BYTES: 5.1 encodes a string body as ISO-8859-1, which would
    # mangle any non-ASCII command or path before the server ever saw it.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    return Invoke-RestMethod -Method Post -Uri $url -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers $headers -TimeoutSec $timeout
}

# --- read the payload -------------------------------------------------------
try {
    try { [Console]::InputEncoding = New-Object System.Text.UTF8Encoding $false } catch { Write-Verbose "console input encoding not settable: $($_.Exception.Message)" }
    $raw = [Console]::In.ReadToEnd()
    $payload = $raw | ConvertFrom-Json
} catch {
    Write-Warn "could not parse hook input: $($_.Exception.Message)"
    exit 0  # fail open, mirroring the local hook
}

# --- normalise the two Copilot dialects (and Claude Code / Codex) -----------
$hookEvent = Get-Field $payload 'hook_event_name'
if ($null -ne $hookEvent) {
    $toolName = [string](Get-Field $payload 'tool_name')
    $toolInput = Get-Field $payload 'tool_input'
    $sessionId = [string](Get-Field $payload 'session_id')
} else {
    $hookEvent = Get-Field $payload 'hookEventName'
    $toolName = [string](Get-Field $payload 'toolName')
    $toolInput = Get-Field $payload 'toolArgs'
    $sessionId = [string](Get-Field $payload 'sessionId')
    if ($null -eq $hookEvent -and -not [string]::IsNullOrEmpty($toolName)) { $hookEvent = 'preToolUse' }
    if ($toolInput -is [string]) {
        # toolArgs is usually an object. A JSON-encoded string is decoded; any
        # other string (apply_patch sends the raw patch text) is kept as-is and
        # forwarded below rather than dropped.
        try {
            $decoded = $toolInput | ConvertFrom-Json
            if ($null -ne $decoded -and -not ($decoded -is [string])) { $toolInput = $decoded }
        } catch { Write-Verbose "toolArgs is a plain string, not JSON" }
    }
}

if ([string]::IsNullOrEmpty([string]$hookEvent) -or ([string]$hookEvent) -notmatch '^(?i)pretooluse$') {
    exit 0  # not a pre-tool payload this client understands - pass through
}

$isCodex = -not [string]::IsNullOrEmpty([string](Get-Field $payload 'turn_id'))
$defaultAgent = 'copilot-cli'
if ($isCodex) { $defaultAgent = 'codex' }
$agentId = Get-EnvOr 'AGENTSHIELD_AGENT_ID' $defaultAgent
$identity = @{
    session_id = $sessionId
    agent_id   = $agentId
    principal  = [Environment]::UserName
    source     = "$agentId-remote-hook"
}

# --- shell surface ----------------------------------------------------------
if ($toolName -eq 'Bash' -or $toolName -eq 'bash' -or $toolName -eq 'powershell') {
    if (-not (Test-Field $toolInput 'command')) {
        # Not an empty command: a payload with NO command field means the
        # harness's argument shape is not the one this client was built for.
        # Say so rather than pass through silently.
        Write-Warn "shell tool call has no 'command' argument (tool '$toolName') - payload shape not recognised, allowing"
        exit 0
    }
    $command = [string](Get-Field $toolInput 'command')
    if ([string]::IsNullOrEmpty($command)) { exit 0 }
    $cwd = [string](Get-Field $payload 'cwd')
    if ([string]::IsNullOrEmpty($cwd)) { $cwd = (Get-Location).Path }
    $body = @{ command = $command; cwd = $cwd }
    foreach ($k in $identity.Keys) { $body[$k] = $identity[$k] }
    try {
        $verdict = Invoke-Evaluate $body
    } catch {
        Exit-FailOpenOrClosed "shield-server evaluation failed: $($_.Exception.Message)"
    }
    if ([string](Get-Field $verdict 'decision') -eq 'BLOCK') {
        Write-Block 'BLOCKED this command' $verdict
        exit $BlockExit
    }
    exit 0
}

# --- every other tool goes through MCP policy (mirrors hook.go) -------------
$arguments = @{}
if ($toolInput -is [string]) {
    # Observed live (Copilot CLI 1.0.93): edits through apply_patch arrive with
    # tool_input/toolArgs as the raw patch TEXT, not an object. Sending an empty
    # map would evaluate nothing; forward the text so key-agnostic rules see it.
    # Per-file evaluation of a patch (target paths, added content) is a
    # server-side job, tracked separately.
    $key = 'input'
    if ($toolInput.StartsWith('*** Begin Patch')) { $key = 'patch' }
    $arguments = @{ $key = $toolInput }
} elseif ($null -ne $toolInput) {
    $arguments = $toolInput
}
$body = @{ tool_name = $toolName; arguments = $arguments }
foreach ($k in $identity.Keys) { $body[$k] = $identity[$k] }
try {
    $verdict = Invoke-Evaluate $body
} catch {
    Exit-FailOpenOrClosed "shield-server evaluation failed: $($_.Exception.Message)"
}
$decision = [string](Get-Field $verdict 'decision')
if ($decision -eq 'BLOCK') {
    Write-Block "BLOCKED MCP tool call: $toolName" $verdict
    exit $BlockExit
}
if ($decision -eq 'AUDIT' -and [string]::IsNullOrEmpty([string](Get-Field $verdict 'original_decision'))) {
    # Real AUDIT stays visible; audit-only-mode downgrades stay silent (#1952).
    [Console]::Error.WriteLine("[AgentShield] AUDIT MCP tool: $toolName")
    $rules = @(Get-Field $verdict 'rules')
    if ($rules.Count -gt 0 -and $null -ne $rules[0]) { [Console]::Error.WriteLine("   Rule: " + ($rules -join ', ')) }
}
exit 0
