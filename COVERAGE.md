Generated /Users/garyzeng/dev/baby-kai/shield-workspace/COVERAGE.md (202 terminal rules, 42 MCP rules)
 Metric | Count |
|--------|-------|
| Terminal rules | 202 |
| MCP rules | 42 |
| Total rules | 244 |
| Test cases (TP+TN) | 564 |
| Kingdoms covered | 9 |

## Runtime Rules by Kingdom

### credential-exposure (25 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sec-block-ssh-private` | BLOCK | regex | Direct access to private key files is blocked. Excludes commands where the SSH path appears as a text payload in a named flag value (e.g. gh --body, git commit -m). |
| `sec-block-etc-shadow` | BLOCK | regex | Access to system password database is blocked. |
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
| `sec-block-kubectl-config-view-raw` | BLOCK | regex | kubectl config view --raw exports all cluster credentials including embedded certificates and bearer tokens. MITRE T1552.001. |
| `sec-block-kubeconfig-file-access` | BLOCK | regex | Direct read or copy of ~/.kube/config exposes cluster credentials (embedded certs, bearer tokens, client keys). Excludes matches where the path appears as prose text in a named flag value (e.g. git commit -m, gh issue --body). MITRE T1552.001. |
| `sec-block-kubeconfig-structural` | BLOCK | structural | Structural detection of kubeconfig file access — catches path variations not covered by regex. |
| `sec-block-cloud-cred-regex` | BLOCK | regex | Direct read or copy of a cloud provider credential file (~/.aws/credentials, ~/.config/gcloud/application_default_credentials.json, ~/.azure/accessTokens.json) exposes full cloud account access. MITRE T1552.005. |
| `sec-block-cloud-cred-structural` | BLOCK | structural | Structural detection of cloud credential file access — catches path variations not covered by the regex rule. |
| `sec-block-gpg-export-secret` | BLOCK | regex | Exporting GPG secret keys exposes private key material enabling forgery of signed commits and decryption of secrets. MITRE T1552.004. |
| `sec-block-gpg-connect-agent-keyinfo` | BLOCK | regex | gpg-connect-agent keyinfo enumerates GPG key IDs, enabling targeted key extraction. MITRE T1552.004. |
| `sec-block-gpg-secret-structural` | BLOCK | structural | Structural detection of GPG secret key export flags — catches flag variations not caught by regex. |
| `sec-block-archive-ssh-dir` | BLOCK | structural | Archiving a credential directory captures all private keys and secrets. |
| `ts-block-git-credential-modify` | BLOCK | regex | Modifying git credential helper can redirect stored credentials. |
| `ts-block-git-credential-fill` | BLOCK | regex | git credential fill/approve can extract or inject stored credentials. |

### data-exfiltration (37 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ne-block-netcat` | BLOCK | regex | Netcat/socat can open reverse shells or exfiltrate data. |
| `ne-block-telnet` | BLOCK | prefix | Telnet is unencrypted and commonly used for reverse shells. |
| `ne-block-dev-tcp` | BLOCK | regex | Bash /dev/tcp and /dev/udp are used for reverse shells. |
| `ne-block-dns-tunnel` | BLOCK | regex | DNS TXT lookups can be used for data exfiltration via DNS tunneling. |
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

### persistence-evasion (21 rules)

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
| `ts-audit-systemctl` | AUDIT | prefix | Service management flagged for review. |
| `ts-struct-block-crontab-modify` | BLOCK | structural | crontab -e (edit) or -r (remove/reinstall) modifies cron schedules. AI agents must not manage persistent scheduled tasks. |
| `ts-struct-block-ssh-keygen-noninteractive` | BLOCK | structural | ssh-keygen with -N flag runs non-interactively. AI agents generating SSH keys is a persistence and lateral movement risk. |
| `ts-block-ssh-keygen-piped` | BLOCK | regex | Piping empty passphrase to ssh-keygen bypasses interactive prompt, generating passwordless SSH keys for lateral movement. |
| `ts-block-authorized-keys-write` | BLOCK | regex | Writing to authorized_keys injects an SSH public key for persistent backdoor access. AI agents must never modify the authorized keys list (MITRE T1098.004). |
| `ts-block-ssh-config-write` | BLOCK | regex | Writing to the SSH client config can inject ProxyCommand directives, disable host key checking, or enable agent forwarding — enabling MITM attacks and credential theft on all subsequent SSH connections. |
| `ts-block-cicd-write` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |
| `ts-block-cicd-write-reverse` | BLOCK | regex | Modifying CI/CD pipeline configuration files is a persistence/supply-chain risk. |
| `ts-block-cicd-cp-mv` | BLOCK | regex | Copying or moving files to CI/CD configuration paths is a supply-chain tampering risk. |
| `ts-block-history-tamper` | BLOCK | regex | Shell history tampering detected — disabling or clearing HISTFILE/HISTSIZE destroys audit evidence of agent activity (LLM02, LLM08). MITRE T1070.003. |
| `ts-block-history-file-clear` | BLOCK | regex | Truncating shell history file — destroys forensic record of agent commands (LLM02). MITRE T1070.003. |
| `ts-block-log-file-clear` | BLOCK | regex | System log file truncation or clearing detected — destroys authentication, audit, and security event records (LLM02, LLM08). MITRE T1070.002. |

### privilege-escalation (19 rules)

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
| `ts-block-docker-privileged` | BLOCK | regex | Running a privileged Docker container disables security boundaries. |
| `ts-block-docker-host-mount` | BLOCK | regex | Mounting host root filesystem into a container enables full host access. |
| `ts-block-docker-exec` | AUDIT | regex | docker exec into a container may enable lateral movement or escape. |
| `ts-block-namespace-escape` | BLOCK | regex | Creating or entering Linux namespaces is used for container escape and user namespace privilege escalation. |

### reconnaissance (23 rules)

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

### supply-chain (29 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `sc-block-npm-registry-override` | BLOCK | regex | npm install with non-standard registry override blocked. May be dependency confusion attack. |
| `sc-block-pip-extra-index` | BLOCK | structural | pip install with --extra-index-url blocked. Risk of dependency confusion. |
| `sc-block-pip-index-url` | BLOCK | structural | pip install with --index-url replaces the primary PyPI index entirely, routing all package downloads to an attacker-controlled server. More severe than --extra-index-url. |
| `sc-block-git-url-rewrite` | BLOCK | regex | git config url.*.insteadOf silently rewrites all subsequent git fetch/clone URLs in the session. Used in supply chain attacks to redirect trusted repositories to attacker-controlled sources. |
| `sc-audit-conda-channel` | AUDIT | regex | conda/mamba install from a URL-based channel bypasses verified conda-forge/defaults channels. Review before allowing. |
| `sc-block-pip-trusted-host` | BLOCK | regex | pip install with --trusted-host bypasses TLS verification. |
| `sc-block-pip-url-install` | BLOCK | regex | pip install from URL bypasses PyPI. Download and inspect first. |
| `sc-block-npm-url-install` | BLOCK | regex | npm install from URL bypasses registry verification. |
| `sc-block-npmrc-edit` | BLOCK | regex | Modification of .npmrc blocked — may redirect package resolution. |
| `sc-block-pypirc-edit` | BLOCK | regex | Modification of .pypirc blocked — may redirect package resolution. |
| `sc-block-go-mod-replace` | BLOCK | regex | go mod edit -replace redirects a Go module to an attacker-controlled path or repository, silently substituting a trusted dependency. AI agents have no legitimate need to replace module mappings. |
| `sc-block-npm-ignore-scripts-off` | BLOCK | regex | Re-enabling npm post-install scripts is risky. Keep ignore-scripts=true in agent context. |
| `sc-audit-npm-install` | AUDIT | prefix | npm package install flagged for supply-chain review. |
| `sc-audit-pip-install` | AUDIT | prefix | pip package install flagged for supply-chain review. |
| `sc-audit-yarn-add` | AUDIT | prefix | Yarn/pnpm package install flagged for supply-chain review. |
| `sc-audit-brew-install` | AUDIT | prefix | Homebrew install flagged for supply-chain review. |
| `sc-audit-go-get` | AUDIT | prefix | Go module fetch flagged for supply-chain review. |
| `sc-audit-cargo-install` | AUDIT | prefix | Cargo package install flagged for supply-chain review. |
| `sc-audit-gem-install` | AUDIT | prefix | RubyGems install flagged for supply-chain review. |
| `sc-audit-lockfile-edit` | AUDIT | regex | Lock file modification flagged — may indicate supply-chain tampering. |
| `sc-block-ml-dataset-write` | BLOCK | regex | Writing to ML training dataset files blocked. May introduce poisoned examples into fine-tuning pipeline (LLM04). |
| `sc-block-ml-dataset-append` | BLOCK | regex | Appending data to training dataset file blocked. Risk of training data poisoning (LLM04). |
| `sc-block-ml-checkpoint-replace` | BLOCK | regex | Writing to ML model checkpoint file blocked. PyTorch .pt/.pkl files can contain pickle exploits. Risk of checkpoint substitution attack (LLM04). |
| `sc-audit-ml-checkpoint-write` | AUDIT | regex | Model checkpoint file copy or move flagged. Verify source integrity before deploying (LLM04). |
| `sc-block-hf-cli-download` | BLOCK | regex | huggingface-cli download pulls a model repo from the HF Hub. Untrusted repos can ship pickle-exploit payloads that execute on load. Human review of the source required (LLM04, AML.T0010). |
| `sc-audit-hf-from-pretrained` | AUDIT | regex | Python command calling from_pretrained() to download a model from HF Hub or a remote path. Verify the source repo is trusted before execution (LLM04). |
| `sc-audit-hf-hub-download` | AUDIT | regex | Python command calling hf_hub_download() to pull a specific model file from HF Hub. Ensure the repo and revision are trusted before execution (LLM04). |
| `sc-audit-global-install` | AUDIT | regex | Global package install has wider system impact. Flagged for review. |
| `ts-struct-block-npm-registry` | BLOCK | structural | Structural: package install with custom registry override is a supply chain risk. |

### unauthorized-execution (17 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `ts-block-pipe-to-shell` | BLOCK | regex | Pipe-to-shell executes unreviewed remote code. |
| `ts-block-eval-subshell-rce` | BLOCK | regex | eval with remote command substitution executes unreviewed remote code — evades pipe-to-shell detection. |
| `ts-block-shell-c-remote-subshell` | BLOCK | regex | shell -c with remote subshell executes unreviewed remote code — pipe-to-shell evasion via -c flag. |
| `ts-block-source-process-sub-rce` | BLOCK | regex | source/dot with process substitution from remote downloader executes unreviewed remote code — pipe-to-shell evasion. |
| `ts-block-interpreter-inline-rce` | BLOCK | regex | Interpreter inline download-execute: fetches remote code via HTTP module and runs it with exec/eval — pipe-to-shell evasion without a pipe (OWASP LLM02). |
| `ts-audit-llm-agent-import` | AUDIT | regex | Python one-liner importing an AI agent orchestration framework. Multi-step autonomous execution without human approval is an LLM06 risk. |
| `ts-audit-llm-sdk-direct-import` | AUDIT | regex | Python one-liner directly importing an LLM SDK client. Direct invocations outside a governance wrapper are an LLM06 risk. |
| `ts-struct-block-pipe-to-shell` | BLOCK | structural | Structural: download piped to interpreter. Download and inspect first. |
| `ts-sf-block-download-execute` | BLOCK | stateful | Stateful: direct pipe from downloader to interpreter detected (download-then-execute via pipe). |
| `ts-block-gdb-process-attach` | BLOCK | regex | gdb attached to a running process can inject arbitrary code via call system() or memory writes. Agents have no legitimate need to debug live processes. |
| `ts-block-proc-mem-write` | BLOCK | regex | Writing to /proc/PID/mem or /dev/mem injects code directly into a running process's address space, bypassing all filesystem execution controls. |
| `ts-audit-vercel-ai-sdk-install` | AUDIT | regex | Installation of the Vercel AI SDK ('ai' package). Direct model invocations without a governance wrapper are an LLM06 risk. |
| `ts-audit-vercel-ai-sdk-provider-install` | AUDIT | regex | Installation of a Vercel AI SDK provider package (@ai-sdk/openai, @ai-sdk/anthropic, @ai-sdk/google, etc.). Flags for AI governance review — LLM06 risk. |
| `ts-audit-vercel-ai-sdk-node-inline` | AUDIT | regex | Node.js inline script importing the Vercel AI SDK ('ai' package). Direct LLM invocations outside a governance wrapper are an LLM06 risk. |
| `ts-audit-git-commit-security-doc` | AUDIT | regex | git commit targeting SECURITY.md — AI-generated security documentation requires human review before committing (LLM09: misinformation propagation). |
| `ts-audit-git-commit-audit-path` | AUDIT | regex | git commit targeting audit/compliance/runbook path — AI-generated compliance content must be human-verified before it can be referenced by auditors (LLM09). |
| `ts-audit-append-security-doc` | AUDIT | regex | Shell append to compliance-sensitive documentation file — AI-generated content should be reviewed before persisting (LLM09: hallucination injection). |

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

### unauthorized-execution (4 rules)

| Rule ID | Decision | Match Type | Description |
|---------|----------|------------|-------------|
| `mcp-content-audit-security-doc-write` | AUDIT | mcp_rule | AI-generated write to SECURITY file — requires human review before committing (LLM09: misinformation propagation risk) |
| `mcp-content-audit-compliance-dir-write` | AUDIT | mcp_rule | AI-generated write to audit directory — fabricated audit results are a compliance liability (LLM09) |
| `mcp-content-audit-compliance-file-write` | AUDIT | mcp_rule | AI-generated write to compliance directory — unverified compliance claims require human sign-off (LLM09) |
| `mcp-content-audit-runbook-write` | AUDIT | mcp_rule | AI-generated write to runbook — incorrect incident response procedures are a safety risk (LLM09) |

## Test Coverage

| Kingdom | TP | TN | Total |
|---------|----|----|-------|
| credential-exposure | 56 | 42 | 98 |
| data-exfiltration | 43 | 21 | 64 |
| destructive-ops | 59 | 35 | 94 |
| persistence-evasion | 47 | 24 | 71 |
| privilege-escalation | 38 | 24 | 62 |
| reconnaissance | 45 | 16 | 61 |
| supply-chain | 33 | 21 | 54 |
| unauthorized-execution | 37 | 23 | 60 |
| **Total** | **358** | **206** | **564** |

