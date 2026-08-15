package testdata

// AllTestCases returns every test case across all kingdoms.
// Used by the accuracy metrics test to compute aggregate TP/FP/FN/TN counts.
func AllTestCases() []TestCase {
	var all []TestCase
	all = append(all, AllDestructiveOpsCases()...)
	all = append(all, AllCredentialExposureCases()...)
	all = append(all, AllDataExfiltrationCases()...)
	all = append(all, AllUnauthorizedExecutionCases()...)
	all = append(all, AllPrivilegeEscalationCases()...)
	all = append(all, AllPersistenceEvasionCases()...)
	all = append(all, AllSupplyChainCases()...)
	all = append(all, AllReconnaissanceCases()...)
	all = append(all, AllGovernanceRiskCases()...)
	// Edge Case Deep Dive — hard link cases (history/alias cases in AllPersistenceEvasionCases)
	all = append(all, HardlinkCredentialCases...)
	// Opus deep-dive (2026-04-22): macOS Keychain file-level exfil, Python chr() obfuscation,
	// getattr(__import__) indirect dispatch, OSC 52 terminal clipboard hijack.
	all = append(all, KeychainFileExfilCases...)
	all = append(all, PythonChrObfuscationCases...)
	all = append(all, PythonGetattrImportCases...)
	all = append(all, OSC52ClipboardHijackCases...)
	// Agent-generated credential commit cases (issue #471)
	all = append(all, AgentGeneratedCredentialCommitCases...)
	// Build diagnostic prompt injection cases (issue #467)
	all = append(all, BuildDiagnosticPromptInjectionCases...)
	// Opus deep-dive (2026-04-25): bash hash -p PATH-bypass, getent NSS-bypass
	// (shadow read + DNS exfil), shell rcfile / ZDOTDIR override.
	all = append(all, BashHashRebindCases...)
	all = append(all, GetentCredentialDBCases...)
	all = append(all, GetentDNSExfilCases...)
	all = append(all, ShellRcfileOverrideCases...)
	// Opus deep-dive (2026-04-26): cloud SDK config redirection / poisoning —
	// AWS_CONFIG_FILE/KUBECONFIG/GAC env hijack, credential_process directive,
	// kubeconfig users.exec plugin poison, AKIA static-key replacement.
	all = append(all, CloudConfigRedirectCases...)
	all = append(all, AwsCredentialProcessPoisonCases...)
	all = append(all, KubeconfigExecPluginPoisonCases...)
	all = append(all, AwsCredentialsStaticKeyPoisonCases...)
	// Opus deep-dive (2026-05-03): SSHD server-config backdoor, SSLKEYLOGFILE
	// TLS key dump, macOS tccutil reset, launchctl bootstrap from /tmp.
	all = append(all, SSHDServerConfigBackdoorCases...)
	all = append(all, SSLKeyLogFileExfilCases...)
	all = append(all, MacOSTCCUtilResetCases...)
	all = append(all, LaunchctlVolatilePlistCases...)
	// Opus deep-dive (2026-05-03 batch 2): /etc/ld.so.preload direct write,
	// GCONV_PATH glibc charset module hijack, macOS networksetup DNS/proxy
	// hijack, macOS Gatekeeper quarantine-flag strip.
	all = append(all, LdSoPreloadWriteCases...)
	all = append(all, GconvPathHijackCases...)
	all = append(all, MacOSNetworksetupHijackCases...)
	all = append(all, MacOSQuarantineStripCases...)
	// Cloud function weaponization (issue #1782): AWS Lambda, GCP Cloud Functions/Cloud Run,
	// Azure Functions, Serverless Framework deployment rules.
	all = append(all, CloudFunctionWeaponizationCases...)
	// Opus deep-dive (2026-05-05): four LOLBIN edge cases —
	//   tar --checkpoint-action=exec= direct invocation,
	//   sed s///e GNU execute-flag substitution,
	//   vim/nvim/ex/view -c '!CMD' editor shell-escape,
	//   zip --unzip-command= archive-tester override.
	all = append(all, TarCheckpointActionExecCases...)
	all = append(all, SedExecuteFlagCases...)
	all = append(all, VimShellEscapeCLICases...)
	all = append(all, ZipUnzipCommandExecCases...)
	// Opus deep-dive (2026-05-05 batch 2): four more LOLBIN edge cases —
	//   gdb -ex 'shell|pi|python|pipe' direct shell-escape,
	//   tcpdump -z postrotate-command exec,
	//   man -P / --pager= shell-pager override,
	//   emacs --batch --eval '(shell-command ...)' Lisp shell-spawn.
	all = append(all, GdbExShellEscapeCases...)
	all = append(all, TcpdumpPostrotateExecCases...)
	all = append(all, ManPagerShellOverrideCases...)
	all = append(all, EmacsBatchEvalShellExecCases...)
	// Opus deep-dive (2026-05-05 batch 3): four edge cases —
	//   logrotate prerotate/postrotate config injection,
	//   PAM pam_exec/pam_script/pam_python module injection,
	//   GitHub Actions ACTIONS_RUNNER_HOOK_JOB_(STARTED|COMPLETED) env var,
	//   macOS chflags schg/uchg malware-lock + chflags noschg system unlock.
	all = append(all, LogrotateScriptInjectionCases...)
	all = append(all, PamExecScriptInjectionCases...)
	all = append(all, ActionsRunnerHookJobCases...)
	all = append(all, ChflagsImmutableTmpCases...)
	all = append(all, ChflagsClearImmutableSystemCases...)
	// Agentic attack rules (issues #1804, #1786):
	//   roleplay/persona jailbreak (DAN/Developer Mode activation + compliance sigs),
	//   sycophancy-driven safety bypass (authority-claim override detection).
	all = append(all, RoleplayPersonaJailbreakCases...)
	all = append(all, SycophancyAuthorityClaimCases...)
	// Agent-attack runtime rules (issue #1802 — taxonomy run 186):
	//   CAPTCHA/antibot bypass egress + stealth package install,
	//   voice-clone toolchain AUDIT,
	//   account-takeover chain TN (MCP-only threat, no shell TP),
	//   fake-UI injection TN (MCP-only threat, no shell TP).
	all = append(all, AgentCaptchaAntibotBypassCases...)
	all = append(all, AgentSyntheticIdentityCreationCases...)
	all = append(all, AgentAccountTakeoverChainCases...)
	all = append(all, AgentFakeUIInjectionCases...)
	// Opus deep-dive (2026-04-22): install(1) -m setuid/setgid mode SUID-binary drop —
	// atomic primitive bypassing chmod-based detectors. Maps to existing
	// privilege-escalation/file-permissions/suid-bit-set taxonomy.
	all = append(all, InstallSetuidCases...)
	// Issue #2170: git commit history prompt injection — git log with full body format
	// (%B / --pretty=raw/fuller/email) feeds adversarial commit messages into agent context.
	all = append(all, GitCommitHistoryInjectionCases...)
	// Issue #2234: AI deepfake authentication bypass — voice cloning API egress,
	// deepfake video tool invocation, and audio-retrieval + voice-synthesis chain.
	all = append(all, DeepfakeVoiceCloneAPIEgressCases...)
	all = append(all, DeepfakeVideoToolCases...)
	all = append(all, DeepfakeVoiceSampleSynthesisChainCases...)
	// Issue #2442: AI agent automated vishing — Retell AI outbound call creation (BLOCK)
	// and Twilio CLI outbound call initiation (AUDIT).
	all = append(all, RetellAIVishingCases...)
	all = append(all, TwilioCLIVishingCases...)
	// Issue #2363: guardian safeCallerRe compound bypass FN fix — leading git/gh
	// in a top-level compound must not shield a trailing interpreter-exec payload.
	all = append(all, GuardianSafeCallerCompoundFNCases...)
	// Issue #2427: cross-language safety bypass via training distribution gap —
	// bracketed language-injection syntax in low-resource languages exploits the
	// gap between the model's multilingual comprehension and safety-alignment coverage.
	all = append(all, CrossLanguageSafetyBypassCases...)

	// Issue #2432: env-var prompt injection — poisoning an env var the agent
	// consumes as its system prompt (WRITE/SET direction); taxonomy seeded by #2601.
	all = append(all, EnvVarPromptInjectionCases...)

	// Issue #2475: application log prompt injection — AI agent reads HTTP logs
	// containing attacker instructions and executes them as a compound command.
	all = append(all, ApplicationLogPromptInjectionCases...)
	// Issue #2505: policy puppetry jailbreak (HiddenLayer, Apr 2025) — fake config/policy
	// XML or JSON structures injected to override safety constraints.
	all = append(all, PolicyPuppetryJailbreakCases...)
	// Issue #2505: best-of-n jailbreak (Anthropic, NeurIPS 2025) — meta-instruction to
	// retry with randomized capitalization or character scrambling to evade filters.
	all = append(all, BestOfNJailbreakCases...)
	// Issue #2508: structured-output constraint compilation DoS — catastrophic nested-quantifier
	// regex in guided_regex crashes vLLM/XGrammar/Outlines constraint compiler (CVE-2025-29770).
	all = append(all, StructuredOutputCompilationDosCases...)
	// Issue #2529: threat intelligence feed prompt injection — AI SOC agent queries threat
	// intel APIs (VirusTotal, NVD, AbuseIPDB) whose free-text fields may carry agent directives.
	all = append(all, ThreatIntelFeedInjectionCases...)
	// Issue #2540: AI SRE agent metric poisoning — agent writes to CloudWatch/Prometheus/InfluxDB
	// metric pipelines, the terminal step of a data integrity attack that fools SRE agents into
	// closing genuine incidents by feeding false "nominal" metric values.
	all = append(all, SREMetricPoisoningCases...)
	// Issue #2567: AI agent securities trading abuse — agent executes unauthorized buy/sell orders
	// via Python SDK one-liners or curl calls to broker REST APIs (Alpaca, IB, Schwab, OANDA).
	all = append(all, SecuresTradingAbuseCases...)
	// Opus deep-dive (2026-06-21): execution-wrapper evasion — env/nice/nohup/
	// setsid/timeout/ionice/taskset/command/`time`/sudo-nesting prefixing a
	// destructive command dodged every structural rule (Executable=="nice", not
	// "rm"). Closed by StripExecWrappers + TimeClause handling in shellparse.
	all = append(all, ExecWrapperEvasionCases...)
	// Opus deep-dive (2026-07-21): compound-command evasion — `{ ...; }`, if,
	// while, for, case, function bodies and coproc contributed ZERO parsed
	// segments, silently disabling the structural/semantic/dataflow/stateful
	// analyzers (20.8% of BLOCKing commands downgraded when brace-wrapped),
	// plus the ^-anchor prefix bypass ("cd /tmp && mkfs..."). See #3045.
	all = append(all, CompoundCommandEvasionCases...)
	// Opus deep-dive (2026-06-21): executable-name obfuscation — \rm, "rm",
	// 'rm', r""m, rm'', r\m all run rm but kept their quoting in the parsed
	// executable, dodging every rule keyed on "rm". Closed by NormalizeExecName.
	all = append(all, ExecNameObfuscationCases...)
	// Opus deep-dive (2026-06-21): root/system target path evasion — "/", '/',
	// \/, /., /./, //, /home/../ all resolve to root/system dirs but the raw
	// string compare missed them. Closed by normalizeTargetPath (unquote +
	// path.Clean) in isRootTarget/isSystemDir/isSystemPath.
	all = append(all, RootTargetPathEvasionCases...)
	// Issue #2596: lethal-trifecta composite — a single compound command that
	// fetches untrusted content, reads a secret, and egresses it (all three
	// trifecta capability classes, ordered). Detected by the two stateful rules
	// ts-sf-lethal-trifecta-file-secret (BLOCK) + -env-secret (AUDIT).
	all = append(all, LethalTrifectaCompositeCases...)
	// Issue #2704: IoT platform tool weaponization — AI agents manipulated via
	// prompt injection into sending actuation commands to physical devices via
	// mosquitto_pub, aws iot-data publish, aws iot-data update-thing-shadow,
	// az iot hub invoke-device-method, and OTA firmware push commands.
	all = append(all, IoTPlatformWeaponizationCases...)
	// Issue #2712: LLM benchmark contamination — detect standard evaluation benchmark
	// datasets (MMLU, GSM8K, HumanEval, etc.) being loaded or referenced in training
	// pipelines without decontamination, inflating capability scores.
	all = append(all, LLMBenchmarkContaminationCases...)
	// Distributed trace context prompt injection via crafted W3C tracestate headers
	// passed to OTel-instrumented services, stored in trace spans, and retrieved by AI SRE agents.
	all = append(all, DistributedTraceContextInjectionCases...)
	// Agent orchestration server fail-open auth: PraisonAI legacy api_server.py
	// entrypoint (CVE-2026-44338) binds 0.0.0.0:8080 with auth hardcoded disabled.
	all = append(all, AgentOrchestrationServerFailOpenAuthCases...)
	// Agent control server cross-origin WebSocket hijack: fail-open secret check
	// anti-pattern (CVE-2026-44211 Cline, CVE-2026-59723 Cline Hub, CVE-2026-22812 OpenCode).
	all = append(all, AgentControlServerFailOpenSecretCheckCases...)
	// Terminal allowlist bypass via shell-builtin env poisoning (CVE-2026-22708
	// class): Go toolchain -toolexec wraps every compile/link step with an
	// attacker command, settable via the -toolexec flag or GOFLAGS env var.
	all = append(all, TerminalAllowlistBuiltinBypassCases...)
	// Data-label stage visibility: exercises the conditional Layer 7
	// registration in BuildAnalyzerPipeline via the fixture label appended by
	// loadTestPolicy (see datalabel_cases.go — not a shipped pack rule).
	all = append(all, DataLabelFixtureCases...)
	// Issue #2927: refusal & reasoning-token suppression (CrowdStrike PT0197 —
	// Cognitive Token Suppression). Refusal-vocabulary suppression (BLOCK) +
	// reasoning-trace suppression (AUDIT).
	all = append(all, RefusalReasoningTokenSuppressionCases...)
	// Issue #2965: LiteLLM MCP test-endpoint command injection (CVE-2026-42271,
	// CISA KEV) — curl to /mcp-rest/test/connection|tools/list carrying an
	// MCP stdio command+args payload with an inline-eval flag smuggled into args.
	all = append(all, LiteLLMMCPTestEndpointRCECases...)
	// Issue #3055: backslash-newline line continuations are whitespace the
	// shell deletes before tokenizing, but the regex layer matches raw text —
	// 52.5% of BLOCKing commands degraded behind a two-character edit.
	all = append(all, LineContinuationCases...)
	// Issue #3060: two eval BLOCK rules missing the #2843 doc-text/heredoc
	// attestation fired on commands that WRITE a file describing an attack.
	all = append(all, EvalDocTextCases...)
	// Issue #3057: exec-wrapper transparency — an absolute path defeated the
	// wrapper table, `exec` was absent from it, and the regex layer never had
	// wrapper transparency at all (a hard 11.1% floor).
	all = append(all, ExecWrapperTransparencyCases...)
	// Issue #3221: the sequel to #3057 — wrappers were transparent, but their
	// operands were modelled by token shape alone, so any option taking its
	// value as a separate token ("sudo -u root", "strace -o log") handed the
	// analyzer that value as the executable. 21.3% of BLOCKing commands,
	// against a 1.1% floor for the same wrappers with no value flag.
	all = append(all, WrapperValueFlagCases...)
	// Issue #3223: `su -c 'CMD'` / `runuser -u USER -c 'CMD'` were never treated
	// as inline-code carriers, so the oldest privilege-escalation idiom on Unix
	// reached no layer that could decompose its payload — 34.3% of BLOCKing
	// commands, against a 2.4% `bash -c` control.
	all = append(all, SuInlineCodeCases...)
	// Issue #3059: eval was never treated as an inline-code carrier, and a
	// value-taking flag before "-c" (bash -O expand_aliases -c '...') shifted
	// the extracted payload away from the real code — both leaked 34%+ of
	// BLOCKing commands.
	all = append(all, EvalAndFlagBeforeCCases...)
	// Issue #3241: the residual of #3050. Carrier payloads were reconstructed
	// by stripping one outer quote pair rather than by quote removal, so a
	// payload whose word boundaries were hidden INSIDE the word (escaped
	// space, interior quote splice) survived verbatim and re-parsed as a
	// single word. 75.4% of BLOCKing commands, on all eight carrier surfaces.
	all = append(all, CarrierPayloadQuotingCases...)
	// Issue #3069: authority-framing text ("pre-approved", "no need to
	// re-verify") co-occurring with a credential-harvest-to-network payload
	// laundered as telemetry — the pattern shown to defeat LLM security-scan
	// and approval agents in multi-agent CI/CD pipelines.
	all = append(all, AuthorityFramedVerificationBypassCases...)
		// Issue #3358/#3359 taxonomy addition: agent browser launched with
		// same-origin-policy/CSP enforcement disabled — the config precondition
		// for a runtime SOP-collapse prompt-injection chain against a browser
		// driving an LLM perceive-act loop.
		all = append(all, BrowserAgentWebSecurityDisabledCases...)
	// Issue #3076: command substitution ($(...), legacy `...`) and process
	// substitution (<(...), >(...)) were never decomposed into segments no
	// matter which AST node embedded them (CallExpr arg, DeclClause/
	// LetClause/ArithmCmd/TestClause, redirect target) — the payload was
	// invisible to every AST-based analyzer, downgrading a bare BLOCK all the
	// way to ALLOW behind "echo $(...)".
	all = append(all, CmdSubstEvasionCases...)
	// Array-based executable-name indirection (#3091): the array sibling of the
	// scalar/cmdsubst indirection above — "a=(rm -rf /); ${a[@]}" runs the same
	// command as writing it directly.
	all = append(all, ArrayIndirectExecCases...)
	// Runtime-populated array indirection via `read -a` (#3193): the
	// here-string sibling of the constant array literal above — "read -ra
	// parts <<< 'rm -rf /'; ${parts[@]}" runs the same command as writing it
	// directly, through an AST shape #3091 didn't look at.
	all = append(all, ReadArrayIndirectExecCases...)
	// Scalar/mapfile siblings of the read -a here-string binding above
	// (#3239): "read NAME <<< 'rm -rf /'; $NAME" and "mapfile -t NAME <<<
	// 'rm -rf /'; ${NAME[0]}" bind a variable through the same runtime shape
	// #3193 covers, via an AST shape (no -a flag, or a different builtin
	// entirely) the #3193 gate didn't recognize.
	all = append(all, ReadScalarMapfileIndirectExecCases...)
	// Escape-splice command-guard bypass (#3208): a backslash escaping an
	// ASCII alphanumeric, or bash's $"..." locale-translated quoting, both
	// survive quote/escape removal in a real shell but previously survived
	// unresolved in the guard's view — 60.5%/58.9% of the BLOCKing corpus.
	all = append(all, EscapeSpliceCommandGuardBypassCases...)
	// Shell-source carriers (#3232): programs that take shell source as a flag
	// VALUE (man -P, sort --compress-program, flock -c, env -S, tar -I,
	// rsync -e, fzf --preview) or a trailing POSITIONAL operand (watch), which
	// fit none of ExecWrappers / PrivilegeShellCarriers / CodeInterpreters —
	// fifteen such programs leaked 31-34% of the BLOCKing corpus apiece.
	all = append(all, ShellSourceCarrierCases...)
	// Stdin-source decomposition (#3242): a here-string (any interpreter
	// flag) or a stdin redirect from a literal-only process substitution are
	// two more spellings of "shell interpreter reads its source via stdin",
	// alongside the heredoc (#3081) and argument-position process
	// substitution (#3190) forms already covered — plus a structural rule
	// for the non-decomposable network-fetch-via-redirect shape.
	all = append(all, StdinSourceDecompositionCases...)
	return all
}
