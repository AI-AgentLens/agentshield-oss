# AgentShield Coverage Report

*Auto-generated on 2026-03-15 by `go run ./cmd/coverage`*

## Summary

| Metric | Count |
|--------|-------|
| Terminal rules | 106 |
| MCP rules | 36 |
| Total rules | 142 |
| Test cases (TP+TN) | 234 |
| Kingdoms covered | 9 |

## Runtime Rules by Kingdom

### credential-exposure (13 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sec-block-ssh-private` | BLOCK | regex | Direct access to private key files is blocked. |
| `sec-block-etc-shadow` | BLOCK | regex | Access to system password database is blocked. |
| `sec-block-keychain` | BLOCK | regex | macOS Keychain extraction is blocked. |
| `sec-block-history-grep-password` | BLOCK | regex | Searching shell history for credentials is suspicious. |
| `sec-audit-env-dump` | AUDIT | prefix | Environment dump may expose secrets (API keys, tokens, passwords). |
| `sec-audit-env-grep-secret` | AUDIT | regex | Targeted access to secret environment variables flagged for review. |
| `sec-audit-dotenv` | AUDIT | regex | .env files often contain secrets. Flagged for review. |
| `sec-audit-config-files` | AUDIT | regex | Configuration file access flagged — may contain secrets. |
| `sec-audit-clipboard` | AUDIT | prefix | Clipboard operations flagged — may leak secrets. |
| `sec-audit-git-credential` | AUDIT | prefix | Git credential access flagged for review. |
| `sec-block-archive-ssh-dir` | BLOCK | structural | Archiving a credential directory captures all private keys and secrets. |
| `ts-block-git-credential-modify` | BLOCK | regex | Modifying git credential helper can redirect stored credentials. |
| `ts-block-git-credential-fill` | BLOCK | regex | git credential fill/approve can extract or inject stored credentials. |

### data-exfiltration (30 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-block-netcat` | BLOCK | regex | Netcat/socat can open reverse shells or exfiltrate data. |
| `ne-block-telnet` | BLOCK | prefix | Telnet is unencrypted and commonly used for reverse shells. |
| `ne-block-dev-tcp` | BLOCK | regex | Bash /dev/tcp and /dev/udp are used for reverse shells. |
| `ne-block-dns-tunnel` | BLOCK | regex | DNS TXT lookups can be used for data exfiltration via DNS tunneling. |
| `ne-audit-curl` | AUDIT | prefix | HTTP request flagged for network egress review. |
| `ne-audit-wget` | AUDIT | prefix | HTTP download flagged for network egress review. |
| `ne-audit-httpie` | AUDIT | prefix | HTTPie request flagged for network egress review. |
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

### destructive-ops (29 rules)

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
| `ts-block-kubectl-delete-namespace` | BLOCK | regex | Kubernetes namespace deletion destroys all resources in the namespace. |
| `ts-block-kubectl-delete-all` | BLOCK | regex | Kubernetes bulk deletion of resources is destructive. |
| `ts-block-git-force-push-main` | BLOCK | regex | Force pushing to main/master can destroy shared commit history. |
| `ts-block-git-force-push-main-alt` | BLOCK | regex | Force pushing to main/master can destroy shared commit history. |

### persistence-evasion (5 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-pipe-to-crontab` | BLOCK | regex | Piping to crontab installs persistent scheduled tasks. Use 'crontab -e' interactively. |
| `ts-audit-crontab` | AUDIT | prefix | Crontab modification flagged for persistence review. |
| `ts-audit-systemctl` | AUDIT | prefix | Service management flagged for review. |
| `ts-block-cicd-write` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |
| `ts-block-cicd-write-reverse` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |

### privilege-escalation (5 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-audit-sudo` | AUDIT | prefix | Sudo command flagged for privilege escalation review. |
| `ts-audit-chown` | AUDIT | prefix | Ownership change flagged for review. |
| `ts-block-docker-privileged` | BLOCK | regex | Running a privileged Docker container disables security boundaries. |
| `ts-block-docker-host-mount` | BLOCK | regex | Mounting host root filesystem into a container enables full host access. |
| `ts-block-docker-exec` | AUDIT | regex | docker exec into a container may enable lateral movement or escape. |

### reconnaissance (1 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-audit-dns` | AUDIT | prefix | DNS lookup flagged for reconnaissance review. |

### supply-chain (18 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sc-block-npm-registry-override` | BLOCK | regex | npm install with non-standard registry override blocked. May be dependency confusion attack. |
| `sc-block-pip-extra-index` | BLOCK | regex | pip install with --extra-index-url blocked. Risk of dependency confusion. |
| `sc-block-pip-trusted-host` | BLOCK | regex | pip install with --trusted-host bypasses TLS verification. |
| `sc-block-pip-url-install` | BLOCK | regex | pip install from URL bypasses PyPI. Download and inspect first. |
| `sc-block-npm-url-install` | BLOCK | regex | npm install from URL bypasses registry verification. |
| `sc-block-npmrc-edit` | BLOCK | regex | Modification of .npmrc blocked — may redirect package resolution. |
| `sc-block-pypirc-edit` | BLOCK | regex | Modification of .pypirc blocked — may redirect package resolution. |
| `sc-block-npm-ignore-scripts-off` | BLOCK | regex | Re-enabling npm post-install scripts is risky. Keep ignore-scripts=true in agent context. |
| `sc-audit-npm-install` | AUDIT | prefix | npm package install flagged for supply-chain review. |
| `sc-audit-pip-install` | AUDIT | prefix | pip package install flagged for supply-chain review. |
| `sc-audit-yarn-add` | AUDIT | prefix | Yarn/pnpm package install flagged for supply-chain review. |
| `sc-audit-brew-install` | AUDIT | prefix | Homebrew install flagged for supply-chain review. |
| `sc-audit-go-get` | AUDIT | prefix | Go module fetch flagged for supply-chain review. |
| `sc-audit-cargo-install` | AUDIT | prefix | Cargo package install flagged for supply-chain review. |
| `sc-audit-gem-install` | AUDIT | prefix | RubyGems install flagged for supply-chain review. |
| `sc-audit-lockfile-edit` | AUDIT | regex | Lock file modification flagged — may indicate supply-chain tampering. |
| `sc-audit-global-install` | AUDIT | regex | Global package install has wider system impact. Flagged for review. |
| `ts-struct-block-npm-registry` | BLOCK | structural | Structural: package install with custom registry override is a supply chain risk. |

### unauthorized-execution (3 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-pipe-to-shell` | BLOCK | regex | Pipe-to-shell executes unreviewed remote code. |
| `ts-struct-block-pipe-to-shell` | BLOCK | structural | Structural: download piped to interpreter. Download and inspect first. |
| `ts-sf-block-download-execute` | BLOCK | stateful | Stateful: download-then-execute chain detected. |

### uncategorized (2 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-allow-readonly` | ALLOW | prefix | Read-only or informational command. |
| `ts-sem-block-high-risk` | BLOCK | semantic | Semantic: any command with critical risk intent is blocked. |

## MCP Rules

### credential-exposure (13 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
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

### destructive-ops (15 rules)

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

## Test Coverage

| Kingdom | TP | TN | Total |
|---------|----|----|-------|
| credential-exposure | 25 | 12 | 37 |
| data-exfiltration | 26 | 12 | 38 |
| destructive-ops | 59 | 35 | 94 |
| persistence-evasion | 9 | 4 | 13 |
| privilege-escalation | 10 | 6 | 16 |
| reconnaissance | 3 | 2 | 5 |
| supply-chain | 15 | 6 | 21 |
| unauthorized-execution | 7 | 3 | 10 |
| **Total** | **154** | **80** | **234** |

