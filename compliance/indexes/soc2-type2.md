# SOC 2 Type II Trust Service Criteria (AI-Relevant)

> Auto-generated from taxonomy weakness entries. Do not edit manually.
> Source: [SOC 2 Type II Trust Service Criteria (AI-Relevant)](https://www.aicpa.org/soc2)

## C1.1: Confidentiality of Information

- **Cloud Credential Access** — Access to cloud provider credential directories (~/.aws, ~/.config/gcloud) exposes
full cloud account access, potentially granting control over all resources, data
stores, and services in the cloud account. (Risk: critical)
- **GPG Key Access** — Access to GPG key directories exposes private keys used for signing, encryption,
and authentication, enabling an attacker to impersonate the key owner, decrypt
encrypted data, or forge signed commits. (Risk: critical)
- **Database Credential Access** — Direct database access via MCP URIs (mysql://, postgres://) bypasses application-level
access controls, exposing raw customer data and allowing unauthorized reads, writes,
or schema modifications. (Risk: critical)
- **History Credential Grep** — A command searches shell history files for previously entered credentials,
tokens, passwords, or API keys that were accidentally typed in interactive sessions. (Risk: high)
- **Keychain Extraction** — A command extracts credentials from macOS Keychain using the `security`
command-line tool, exposing stored passwords, certificates, and tokens. (Risk: critical)
- **System Shadow File Read** — A command reads system password database files (/etc/shadow, /etc/master.passwd),
exposing hashed credentials for all local and service accounts. (Risk: critical)
- **SSH Private Key Read** — A command reads or copies SSH private key files, enabling impersonation
of the key owner for remote access. (Risk: critical)
- **Environment Variable Dump** — A command dumps all environment variables, potentially exposing API keys,
tokens, passwords, and cloud credentials stored in the environment. (Risk: high)
- **Base64 Credential Encoding** — A command base64-encodes credential files (SSH keys, AWS credentials, GPG keys),
transforming them into a format suitable for exfiltration via HTTP, DNS, or
clipboard channels. (Risk: critical)
- **Hex Dump of Sensitive Files** — A command hex-dumps credential files (SSH keys, AWS credentials, GPG keys),
converting binary key material into a hexadecimal representation that can
be reconstructed elsewhere. (Risk: high)
- **Customer Data Sent to LLM** — Customer PII or sensitive data flowing into LLM API calls creates data privacy and
regulatory compliance risks by transmitting regulated information to third-party
AI service providers. (Risk: high)
- **System Prompt Exfiltration** — An AI agent reading system prompt files or environment variables containing
system prompt content, and transmitting that data via network requests or
writing it to exfiltration paths, exposes confidential operator instructions
and security configurations. (Risk: high)
- **Cloud CLI Data Access** — Cloud CLI tools (aws, gcloud, az) can access and exfiltrate cloud-stored data and
credentials, using the ambient cloud credentials available to the agent's execution
environment. (Risk: high)
- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)
- **Lateral Movement via SSH/SCP** — SSH, SCP, rsync, and SFTP can be used to move laterally across systems or
exfiltrate data to remote hosts, leveraging existing trust relationships and
stored credentials. (Risk: high)
- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Git Data Exfiltration** — Git push can exfiltrate source code or sensitive data to remote repositories,
including attacker-controlled forks or mirrors, using the authentication already
configured in the local git credential store. (Risk: medium)

## CC6.1: Logical and Physical Access Controls

- **AI API Key Exposure** — AI API key references in code or environment variables can lead to credential theft
and unauthorized model access, resulting in financial losses, data leakage, and
exhaustion of rate limits. (Risk: high)
- **Clipboard Data Exposure** — Clipboard operations can expose sensitive data previously copied by the user,
including passwords, API tokens, credit card numbers, or other secrets that were
temporarily held in the system clipboard. (Risk: medium)
- **Cloud Credential Access** — Access to cloud provider credential directories (~/.aws, ~/.config/gcloud) exposes
full cloud account access, potentially granting control over all resources, data
stores, and services in the cloud account. (Risk: critical)
- **AWS IMDS IAM Credential Theft** — An AI agent queries the AWS Instance Metadata Service (IMDS) to retrieve
temporary IAM credentials attached to the EC2 instance role, enabling
AWS API access with the instance's full permissions. (Risk: critical)
- **.env File Read** — Reading `.env` files typically exposes API keys, database credentials, and other
secrets stored for local development, providing an attacker with a broad set of
application credentials in a single operation. (Risk: high)
- **Generic Config File Access** — Access to generic configuration files (config.json, settings.json, credentials)
may expose secrets, connection strings, or other sensitive values stored outside
of dedicated secret management systems. (Risk: medium)
- **Kubernetes Config Access** — Access to ~/.kube/config exposes cluster credentials and API server endpoints,
granting full control over Kubernetes clusters including all workloads, secrets,
and namespaces the user's credentials can access. (Risk: critical)
- **GPG Key Access** — Access to GPG key directories exposes private keys used for signing, encryption,
and authentication, enabling an attacker to impersonate the key owner, decrypt
encrypted data, or forge signed commits. (Risk: critical)
- **Database Credential Access** — Direct database access via MCP URIs (mysql://, postgres://) bypasses application-level
access controls, exposing raw customer data and allowing unauthorized reads, writes,
or schema modifications. (Risk: critical)
- **History Credential Grep** — A command searches shell history files for previously entered credentials,
tokens, passwords, or API keys that were accidentally typed in interactive sessions. (Risk: high)
- **Keychain Extraction** — A command extracts credentials from macOS Keychain using the `security`
command-line tool, exposing stored passwords, certificates, and tokens. (Risk: critical)
- **System Shadow File Read** — A command reads system password database files (/etc/shadow, /etc/master.passwd),
exposing hashed credentials for all local and service accounts. (Risk: critical)
- **SSH Private Key Read** — A command reads or copies SSH private key files, enabling impersonation
of the key owner for remote access. (Risk: critical)
- **Environment Variable Dump** — A command dumps all environment variables, potentially exposing API keys,
tokens, passwords, and cloud credentials stored in the environment. (Risk: high)
- **Git Credential Access** — Accessing git credentials can expose authentication tokens stored in the git
credential helper, providing access to all repositories the user is authorized
to access on platforms like GitHub, GitLab, and Bitbucket. (Risk: high)
- **Git Credential Store Extraction** — An AI agent reads the Git credential store or helper output to extract
stored usernames and passwords/tokens for remote repositories. (Risk: high)
- **Git Credential Configuration Modification** — An AI agent modifies Git credential configuration to redirect authentication
to an attacker-controlled helper or store credentials in a more accessible
location, enabling future credential theft. (Risk: high)
- **AWS IAM User or Role Deletion** — An AI agent deletes an AWS IAM user or role, potentially breaking authentication,
authorization chains, and service-to-service trust relationships. (Risk: high)
- **CI/CD Pipeline Configuration Write** — An AI agent writes or modifies CI/CD pipeline configuration files
(e.g., `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`),
potentially injecting malicious steps that execute during automated builds. (Risk: high)
- **SSH Key Generation for Lateral Movement** — An AI agent generates SSH key pairs using automated/piped methods that
bypass passphrase requirements, creating passwordless keys that can be
used to establish persistent access or enable lateral movement. (Risk: high)
- **AT/Batch Job Scheduling** — An AI agent schedules a deferred or background job using `at` or `batch`,
creating a persistent task that executes outside the current session context. (Risk: high)
- **Docker Exec into Running Container** — An AI agent uses `docker exec` to execute commands inside a running container,
potentially escalating privileges or interfering with isolated workloads. (Risk: high)
- **Docker Host Filesystem Mount** — An AI agent mounts the host filesystem root (`/`) into a Docker container,
providing unrestricted read/write access to all host files from within
the container. (Risk: critical)
- **Docker Privileged Container Run** — An AI agent runs a Docker container with the `--privileged` flag, granting
it full host capabilities and effectively removing all container isolation. (Risk: critical)

## CC6.2: System Credential Management

- **AI API Key Exposure** — AI API key references in code or environment variables can lead to credential theft
and unauthorized model access, resulting in financial losses, data leakage, and
exhaustion of rate limits. (Risk: high)
- **Cloud Credential Access** — Access to cloud provider credential directories (~/.aws, ~/.config/gcloud) exposes
full cloud account access, potentially granting control over all resources, data
stores, and services in the cloud account. (Risk: critical)
- **.env File Read** — Reading `.env` files typically exposes API keys, database credentials, and other
secrets stored for local development, providing an attacker with a broad set of
application credentials in a single operation. (Risk: high)
- **Generic Config File Access** — Access to generic configuration files (config.json, settings.json, credentials)
may expose secrets, connection strings, or other sensitive values stored outside
of dedicated secret management systems. (Risk: medium)
- **Kubernetes Config Access** — Access to ~/.kube/config exposes cluster credentials and API server endpoints,
granting full control over Kubernetes clusters including all workloads, secrets,
and namespaces the user's credentials can access. (Risk: critical)
- **GPG Key Access** — Access to GPG key directories exposes private keys used for signing, encryption,
and authentication, enabling an attacker to impersonate the key owner, decrypt
encrypted data, or forge signed commits. (Risk: critical)
- **History Credential Grep** — A command searches shell history files for previously entered credentials,
tokens, passwords, or API keys that were accidentally typed in interactive sessions. (Risk: high)
- **Keychain Extraction** — A command extracts credentials from macOS Keychain using the `security`
command-line tool, exposing stored passwords, certificates, and tokens. (Risk: critical)
- **System Shadow File Read** — A command reads system password database files (/etc/shadow, /etc/master.passwd),
exposing hashed credentials for all local and service accounts. (Risk: critical)
- **SSH Private Key Read** — A command reads or copies SSH private key files, enabling impersonation
of the key owner for remote access. (Risk: critical)
- **Environment Variable Dump** — A command dumps all environment variables, potentially exposing API keys,
tokens, passwords, and cloud credentials stored in the environment. (Risk: high)
- **Git Credential Access** — Accessing git credentials can expose authentication tokens stored in the git
credential helper, providing access to all repositories the user is authorized
to access on platforms like GitHub, GitLab, and Bitbucket. (Risk: high)

## CC6.3: Authorization and Access Control

- **Crontab Modification** — Modifying crontab allows an agent to establish persistence by scheduling commands
for future execution, surviving process restarts and remaining active after the
original session ends. (Risk: high)
- **Systemctl Service Manipulation** — Using systemctl or launchctl to start, stop, or enable services allows an agent to
establish persistence or disrupt system operations by controlling the service manager
lifecycle. (Risk: high)
- **Environment Variable Injection** — An AI agent that manipulates `LD_PRELOAD` or `LD_LIBRARY_PATH` can inject
malicious shared libraries into privileged processes, bypassing authentication
and security controls at the dynamic linker level. (Risk: high)
- **Kernel Module Loading** — Loading a kernel module grants ring-0 (kernel-space) access to the system,
enabling complete bypass of all userspace security controls, rootkit installation,
and persistent system compromise. (Risk: critical)
- **Sudo Invocation** — An AI agent invoking `sudo` to elevate privileges can bypass application-level
access controls and gain root-level access to the system. (Risk: high)
- **Linux Namespace Escape** — Creating or entering Linux namespaces via `unshare` or `nsenter` enables container
escape and user namespace privilege escalation, allowing an agent to break out of
process isolation boundaries. (Risk: high)
- **Linux Capabilities Manipulation** — Linux capabilities allow fine-grained privilege delegation without full root access.
Setting capabilities such as `cap_setuid` or `cap_net_admin` on a binary is a stealthy
privilege escalation technique that bypasses sudo audit trails. (Risk: critical)
- **File Ownership Change** — Changing file ownership with `chown` or `chgrp` can grant unauthorized access to
sensitive files or enable privilege escalation by transferring control of privileged
resources to the agent's user. (Risk: high)
- **SUID/SGID Bit Set** — Setting the SUID or SGID permission bit on an executable creates a persistent
privilege escalation backdoor: any user who runs the file gains the file owner's
(typically root's) privileges for the duration of the process. (Risk: critical)
- **Package Config File Edit** — Modification of package registry config files (.npmrc, .pypirc) can redirect package
resolution to malicious sources, enabling dependency confusion, supply chain injection,
or credential theft from registry tokens stored in these files. (Risk: high)
- **Global Package Install** — Installing packages globally affects the entire system environment, amplifying the
impact of any supply chain compromise by making malicious code available to all
users and processes on the system. (Risk: high)
- **Package Security Control Bypass** — Disabling npm post-install scripts protection or tampering with lockfiles removes
critical supply chain safeguards, directly enabling malicious package execution
and dependency integrity bypass. (Risk: critical)
- **Standard Package Install** — Package install commands (npm, pip, yarn, brew, go get, cargo, gem) introduce
third-party code that may contain vulnerabilities, malicious payloads, or known
CVEs without explicit human review. (Risk: medium)
- **Uncontrolled Agent/Orchestration Execution** — Agent orchestration frameworks (LangChain, CrewAI, AutoGen) enable autonomous
multi-step execution with broad tool access, increasing the attack surface
significantly compared to single-shot LLM calls. (Risk: high)
- **Uncontrolled Model Invocation** — Unaudited LLM API client imports allow uncontrolled model invocations that may
incur costs, process sensitive data, or bypass policy controls by enabling
arbitrary LLM calls without governance or audit logging. (Risk: medium)

## CC6.6: System Boundary Protection

- **AWS IMDS IAM Credential Theft** — An AI agent queries the AWS Instance Metadata Service (IMDS) to retrieve
temporary IAM credentials attached to the EC2 instance role, enabling
AWS API access with the instance's full permissions. (Risk: critical)
- **Git Credential Store Extraction** — An AI agent reads the Git credential store or helper output to extract
stored usernames and passwords/tokens for remote repositories. (Risk: high)
- **Git Credential Configuration Modification** — An AI agent modifies Git credential configuration to redirect authentication
to an attacker-controlled helper or store credentials in a more accessible
location, enabling future credential theft. (Risk: high)
- **Base64 Credential Encoding** — A command base64-encodes credential files (SSH keys, AWS credentials, GPG keys),
transforming them into a format suitable for exfiltration via HTTP, DNS, or
clipboard channels. (Risk: critical)
- **Hex Dump of Sensitive Files** — A command hex-dumps credential files (SSH keys, AWS credentials, GPG keys),
converting binary key material into a hexadecimal representation that can
be reconstructed elsewhere. (Risk: high)
- **Customer Data Sent to LLM** — Customer PII or sensitive data flowing into LLM API calls creates data privacy and
regulatory compliance risks by transmitting regulated information to third-party
AI service providers. (Risk: high)
- **System Prompt Exfiltration** — An AI agent reading system prompt files or environment variables containing
system prompt content, and transmitting that data via network requests or
writing it to exfiltration paths, exposes confidential operator instructions
and security configurations. (Risk: high)
- **Cloud CLI Data Access** — Cloud CLI tools (aws, gcloud, az) can access and exfiltrate cloud-stored data and
credentials, using the ambient cloud credentials available to the agent's execution
environment. (Risk: high)
- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)
- **Lateral Movement via SSH/SCP** — SSH, SCP, rsync, and SFTP can be used to move laterally across systems or
exfiltrate data to remote hosts, leveraging existing trust relationships and
stored credentials. (Risk: high)
- **Network HTTP Request** — HTTP/HTTPS requests via curl, wget, or HTTPie can be used to exfiltrate data or
communicate with external services outside of the application's intended network
boundary. (Risk: medium)
- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Git Data Exfiltration** — Git push can exfiltrate source code or sensitive data to remote repositories,
including attacker-controlled forks or mirrors, using the authentication already
configured in the local git credential store. (Risk: medium)
- **SSH Key Generation for Lateral Movement** — An AI agent generates SSH key pairs using automated/piped methods that
bypass passphrase requirements, creating passwordless keys that can be
used to establish persistent access or enable lateral movement. (Risk: high)
- **Docker Exec into Running Container** — An AI agent uses `docker exec` to execute commands inside a running container,
potentially escalating privileges or interfering with isolated workloads. (Risk: high)
- **Docker Host Filesystem Mount** — An AI agent mounts the host filesystem root (`/`) into a Docker container,
providing unrestricted read/write access to all host files from within
the container. (Risk: critical)
- **Docker Privileged Container Run** — An AI agent runs a Docker container with the `--privileged` flag, granting
it full host capabilities and effectively removing all container isolation. (Risk: critical)
- **Context Window Probe** — Commands that enumerate environment variables, shell variables, or process
state specifically to discover injected system prompt content, operator
secrets, or AI agent configuration constitute LLM introspection
reconnaissance that may precede a targeted attack. (Risk: medium)
- **DNS Lookup** — DNS lookups can be used for network reconnaissance to discover internal
infrastructure, enumerate hosts, and prepare for lateral movement or data
exfiltration. (Risk: low)
- **Host Discovery / Network Sweep** — Active host discovery tools and ARP sweeping commands enumerate live hosts on
a network segment, enabling an attacker to map the local network, identify
targets, and prepare for lateral movement or data exfiltration. (Risk: high)
- **Port Scanning** — Port scanning commands enumerate open ports and running services on remote
hosts, enabling an attacker to map network topology and identify targets
for exploitation. AI agents performing unsolicited port scans violate
authorization boundaries and may constitute illegal computer access. (Risk: high)

## CC6.7: Restriction of Information Transmission

- **Base64 Credential Encoding** — A command base64-encodes credential files (SSH keys, AWS credentials, GPG keys),
transforming them into a format suitable for exfiltration via HTTP, DNS, or
clipboard channels. (Risk: critical)
- **Hex Dump of Sensitive Files** — A command hex-dumps credential files (SSH keys, AWS credentials, GPG keys),
converting binary key material into a hexadecimal representation that can
be reconstructed elsewhere. (Risk: high)
- **Cloud CLI Data Access** — Cloud CLI tools (aws, gcloud, az) can access and exfiltrate cloud-stored data and
credentials, using the ambient cloud credentials available to the agent's execution
environment. (Risk: high)
- **DNS Tunneling** — A command uses DNS queries (especially TXT records) to exfiltrate data
or establish covert communication channels through DNS infrastructure. (Risk: high)
- **Lateral Movement via SSH/SCP** — SSH, SCP, rsync, and SFTP can be used to move laterally across systems or
exfiltrate data to remote hosts, leveraging existing trust relationships and
stored credentials. (Risk: high)
- **Data Exfiltration via LLM API** — An AI agent sends sensitive local data (credentials, source code, internal
documents) to an external LLM API endpoint, causing unintended data exfiltration
through a seemingly legitimate channel. (Risk: high)
- **Network HTTP Request** — HTTP/HTTPS requests via curl, wget, or HTTPie can be used to exfiltrate data or
communicate with external services outside of the application's intended network
boundary. (Risk: medium)
- **Reverse Shell** — A command opens a reverse shell connection to a remote host, enabling
an attacker to execute commands on the local machine. (Risk: critical)
- **Git Mirror Clone to External Repository** — An AI agent performs a mirror clone of a repository to an external destination,
copying the full git history including all branches, tags, and potentially
sensitive commits that were intended to be purged. (Risk: high)
- **Host Discovery / Network Sweep** — Active host discovery tools and ARP sweeping commands enumerate live hosts on
a network segment, enabling an attacker to map the local network, identify
targets, and prepare for lateral movement or data exfiltration. (Risk: high)
- **Port Scanning** — Port scanning commands enumerate open ports and running services on remote
hosts, enabling an attacker to map network topology and identify targets
for exploitation. AI agents performing unsolicited port scans violate
authorization boundaries and may constitute illegal computer access. (Risk: high)

## CC6.8: Prevention of Unauthorized Software

- **Environment Variable Injection** — An AI agent that manipulates `LD_PRELOAD` or `LD_LIBRARY_PATH` can inject
malicious shared libraries into privileged processes, bypassing authentication
and security controls at the dynamic linker level. (Risk: high)
- **Kernel Module Loading** — Loading a kernel module grants ring-0 (kernel-space) access to the system,
enabling complete bypass of all userspace security controls, rootkit installation,
and persistent system compromise. (Risk: critical)
- **Sudo Invocation** — An AI agent invoking `sudo` to elevate privileges can bypass application-level
access controls and gain root-level access to the system. (Risk: high)
- **Linux Namespace Escape** — Creating or entering Linux namespaces via `unshare` or `nsenter` enables container
escape and user namespace privilege escalation, allowing an agent to break out of
process isolation boundaries. (Risk: high)
- **Linux Capabilities Manipulation** — Linux capabilities allow fine-grained privilege delegation without full root access.
Setting capabilities such as `cap_setuid` or `cap_net_admin` on a binary is a stealthy
privilege escalation technique that bypasses sudo audit trails. (Risk: critical)
- **File Ownership Change** — Changing file ownership with `chown` or `chgrp` can grant unauthorized access to
sensitive files or enable privilege escalation by transferring control of privileged
resources to the agent's user. (Risk: high)
- **SUID/SGID Bit Set** — Setting the SUID or SGID permission bit on an executable creates a persistent
privilege escalation backdoor: any user who runs the file gains the file owner's
(typically root's) privileges for the duration of the process. (Risk: critical)
- **Non-Standard Package Registry** — A command installs packages from a non-standard registry, enabling
dependency confusion attacks where malicious packages shadow legitimate ones. (Risk: high)
- **Pipe to Shell** — A command downloads content from a remote URL and pipes it directly
into a shell interpreter, executing unreviewed code. (Risk: medium)
- **Process Memory Injection** — An agent injects arbitrary code or shellcode into a running process using
debugging interfaces (ptrace, gdb) or direct /proc filesystem access. (Risk: critical)

## CC7.1: Detection of Changes and Vulnerabilities

- **Data Exfiltration via LLM API** — An AI agent sends sensitive local data (credentials, source code, internal
documents) to an external LLM API endpoint, causing unintended data exfiltration
through a seemingly legitimate channel. (Risk: high)
- **Git Mirror Clone to External Repository** — An AI agent performs a mirror clone of a repository to an external destination,
copying the full git history including all branches, tags, and potentially
sensitive commits that were intended to be purged. (Risk: high)
- **AWS IAM User or Role Deletion** — An AI agent deletes an AWS IAM user or role, potentially breaking authentication,
authorization chains, and service-to-service trust relationships. (Risk: high)
- **AWS EC2 Instance Termination** — An AI agent terminates one or more AWS EC2 instances using the AWS CLI,
causing immediate and irreversible shutdown and data loss for ephemeral storage. (Risk: critical)
- **AWS RDS Database Deletion** — An AI agent deletes an AWS RDS database instance or cluster,
causing irreversible loss of all stored data unless a final snapshot is taken. (Risk: critical)
- **AWS S3 Recursive Deletion or Bucket Removal** — An AI agent recursively deletes all objects in an S3 bucket or removes the
bucket itself, causing irreversible loss of cloud storage data. (Risk: critical)
- **AWS EC2 Snapshot Deletion** — An AI agent deletes AWS EC2 EBS snapshots, removing backup and recovery points
for cloud volumes and potentially violating data retention policies. (Risk: high)
- **Azure Resource Group Deletion** — An AI agent deletes an Azure resource group, destroying ALL resources within
it — VMs, databases, storage, networking, and every other Azure service in scope. (Risk: critical)
- **Azure SQL Database Deletion** — An AI agent deletes an Azure SQL database, permanently destroying managed
relational data unless a recent backup exists within the retention window. (Risk: critical)
- **Azure Storage Blob Batch Deletion** — An AI agent uses `az storage blob delete-batch` to delete all blobs in an
Azure storage container, causing irreversible loss of cloud storage data. (Risk: critical)
- **Azure VM Deletion** — An AI agent deletes an Azure Virtual Machine, permanently terminating the
compute instance and potentially its associated OS disk and NIC. (Risk: critical)
- **GCloud Compute Instance Deletion** — An AI agent deletes a Google Cloud Compute Engine instance,
permanently destroying the VM and its attached boot disk. (Risk: critical)
- **GCloud Project Deletion** — An AI agent deletes an entire Google Cloud project, destroying ALL resources
within it — VMs, databases, storage, APIs, IAM, and billing configurations. (Risk: critical)
- **GCloud Cloud SQL Instance Deletion** — An AI agent deletes a Google Cloud SQL managed database instance,
permanently destroying all stored data and automated backups within the instance. (Risk: critical)
- **GCloud Storage Deletion** — An AI agent recursively deletes objects from Google Cloud Storage using
`gcloud storage rm`, causing irreversible loss of cloud storage data. (Risk: critical)
- **Kubernetes Bulk Resource Deletion** — An AI agent uses `kubectl delete --all` or wildcard patterns to bulk-delete
Kubernetes resources, disrupting workloads and potentially causing data loss. (Risk: high)
- **Kubernetes Namespace Deletion** — An AI agent deletes a Kubernetes namespace, terminating all workloads,
services, config maps, secrets, and persistent volume claims within it. (Risk: critical)
- **Disk Overwrite** — A command uses dd or similar tool to overwrite disk data with zeros
or random bytes, causing irreversible data loss. (Risk: critical)
- **Filesystem Format** — A command creates a new filesystem on a disk or partition, destroying
all existing data on that device. (Risk: critical)
- **Recursive Root Delete** — A command recursively deletes files starting from the filesystem root,
causing irreversible destruction of the entire operating system and data. (Risk: critical)
- **System Directory Delete** — A command recursively deletes critical system directories such as /etc,
/usr, /var, /boot, /sys, or /proc, causing system instability or failure. (Risk: critical)
- **World-Writable Permissions** — A command sets world-writable permissions (777) on root or system paths,
removing all file access protections. (Risk: high)
- **Unbounded Financial Transfer** — An AI agent executes a financial transfer or resource commitment without
enforcing value limits, risking catastrophic loss from parsing errors,
misinterpreted instructions, or social engineering. (Risk: critical)
- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)
- **System Shutdown/Reboot** — Issuing shutdown, reboot, halt, or poweroff commands causes immediate service
disruption and potential data loss, constituting a denial-of-service attack
against the host system. (Risk: critical)
- **Git Force Push** — An AI agent performs a force push (`git push --force` or `git push -f`) to a
remote repository, overwriting remote history and potentially causing permanent
loss of commits for collaborators. (Risk: high)
- **Non-Standard Package Registry** — A command installs packages from a non-standard registry, enabling
dependency confusion attacks where malicious packages shadow legitimate ones. (Risk: high)
- **Package Security Control Bypass** — Disabling npm post-install scripts protection or tampering with lockfiles removes
critical supply chain safeguards, directly enabling malicious package execution
and dependency integrity bypass. (Risk: critical)

## CC7.2: Monitoring for Anomalies and Security Events

- **Training Data Tampering** — Writing malicious examples into fine-tuning datasets or training data files
can introduce backdoors, biases, or capability degradation into AI models
that are subsequently trained on the poisoned data. (Risk: critical)
- **AI Hallucination Injection** — An AI agent outputs fabricated facts, URLs, package names, or code references
without grounding checks, and these outputs are persisted or acted upon by
downstream systems without human verification. (Risk: high)
- **AI Misinformation Propagation** — An AI agent writes or commits misleading, false, or unverified content
(documentation, code comments, changelogs, config) that persists in the
codebase or downstream systems without human review, causing teams to rely
on incorrect information. (Risk: high)
- **Pipe to Shell** — A command downloads content from a remote URL and pipes it directly
into a shell interpreter, executing unreviewed code. (Risk: medium)
- **Process Memory Injection** — An agent injects arbitrary code or shellcode into a running process using
debugging interfaces (ptrace, gdb) or direct /proc filesystem access. (Risk: critical)

## CC8.1: Change Management Controls

- **AWS IMDS IAM Credential Theft** — An AI agent queries the AWS Instance Metadata Service (IMDS) to retrieve
temporary IAM credentials attached to the EC2 instance role, enabling
AWS API access with the instance's full permissions. (Risk: critical)
- **Uncontrolled Model Selection** — Hardcoded or unvalidated model references allow arbitrary LLM selection, bypassing
governance controls and potentially sending data to unapproved or unvetted AI models. (Risk: medium)
- **AWS IAM User or Role Deletion** — An AI agent deletes an AWS IAM user or role, potentially breaking authentication,
authorization chains, and service-to-service trust relationships. (Risk: high)
- **AWS EC2 Instance Termination** — An AI agent terminates one or more AWS EC2 instances using the AWS CLI,
causing immediate and irreversible shutdown and data loss for ephemeral storage. (Risk: critical)
- **AWS RDS Database Deletion** — An AI agent deletes an AWS RDS database instance or cluster,
causing irreversible loss of all stored data unless a final snapshot is taken. (Risk: critical)
- **AWS S3 Recursive Deletion or Bucket Removal** — An AI agent recursively deletes all objects in an S3 bucket or removes the
bucket itself, causing irreversible loss of cloud storage data. (Risk: critical)
- **AWS EC2 Snapshot Deletion** — An AI agent deletes AWS EC2 EBS snapshots, removing backup and recovery points
for cloud volumes and potentially violating data retention policies. (Risk: high)
- **Azure Resource Group Deletion** — An AI agent deletes an Azure resource group, destroying ALL resources within
it — VMs, databases, storage, networking, and every other Azure service in scope. (Risk: critical)
- **Azure SQL Database Deletion** — An AI agent deletes an Azure SQL database, permanently destroying managed
relational data unless a recent backup exists within the retention window. (Risk: critical)
- **Azure Storage Blob Batch Deletion** — An AI agent uses `az storage blob delete-batch` to delete all blobs in an
Azure storage container, causing irreversible loss of cloud storage data. (Risk: critical)
- **Azure VM Deletion** — An AI agent deletes an Azure Virtual Machine, permanently terminating the
compute instance and potentially its associated OS disk and NIC. (Risk: critical)
- **GCloud Compute Instance Deletion** — An AI agent deletes a Google Cloud Compute Engine instance,
permanently destroying the VM and its attached boot disk. (Risk: critical)
- **GCloud Project Deletion** — An AI agent deletes an entire Google Cloud project, destroying ALL resources
within it — VMs, databases, storage, APIs, IAM, and billing configurations. (Risk: critical)
- **GCloud Cloud SQL Instance Deletion** — An AI agent deletes a Google Cloud SQL managed database instance,
permanently destroying all stored data and automated backups within the instance. (Risk: critical)
- **GCloud Storage Deletion** — An AI agent recursively deletes objects from Google Cloud Storage using
`gcloud storage rm`, causing irreversible loss of cloud storage data. (Risk: critical)
- **Kubernetes Bulk Resource Deletion** — An AI agent uses `kubectl delete --all` or wildcard patterns to bulk-delete
Kubernetes resources, disrupting workloads and potentially causing data loss. (Risk: high)
- **Kubernetes Namespace Deletion** — An AI agent deletes a Kubernetes namespace, terminating all workloads,
services, config maps, secrets, and persistent volume claims within it. (Risk: critical)
- **Disk Overwrite** — A command uses dd or similar tool to overwrite disk data with zeros
or random bytes, causing irreversible data loss. (Risk: critical)
- **Filesystem Format** — A command creates a new filesystem on a disk or partition, destroying
all existing data on that device. (Risk: critical)
- **Recursive Root Delete** — A command recursively deletes files starting from the filesystem root,
causing irreversible destruction of the entire operating system and data. (Risk: critical)
- **System Directory Delete** — A command recursively deletes critical system directories such as /etc,
/usr, /var, /boot, /sys, or /proc, causing system instability or failure. (Risk: critical)
- **World-Writable Permissions** — A command sets world-writable permissions (777) on root or system paths,
removing all file access protections. (Risk: high)
- **Unbounded Financial Transfer** — An AI agent executes a financial transfer or resource commitment without
enforcing value limits, risking catastrophic loss from parsing errors,
misinterpreted instructions, or social engineering. (Risk: critical)
- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)
- **Git Force Push** — An AI agent performs a force push (`git push --force` or `git push -f`) to a
remote repository, overwriting remote history and potentially causing permanent
loss of commits for collaborators. (Risk: high)
- **CI/CD Pipeline Configuration Write** — An AI agent writes or modifies CI/CD pipeline configuration files
(e.g., `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`),
potentially injecting malicious steps that execute during automated builds. (Risk: high)
- **SSH Key Generation for Lateral Movement** — An AI agent generates SSH key pairs using automated/piped methods that
bypass passphrase requirements, creating passwordless keys that can be
used to establish persistent access or enable lateral movement. (Risk: high)
- **AT/Batch Job Scheduling** — An AI agent schedules a deferred or background job using `at` or `batch`,
creating a persistent task that executes outside the current session context. (Risk: high)
- **Crontab Modification** — Modifying crontab allows an agent to establish persistence by scheduling commands
for future execution, surviving process restarts and remaining active after the
original session ends. (Risk: high)
- **Systemctl Service Manipulation** — Using systemctl or launchctl to start, stop, or enable services allows an agent to
establish persistence or disrupt system operations by controlling the service manager
lifecycle. (Risk: high)
- **Docker Host Filesystem Mount** — An AI agent mounts the host filesystem root (`/`) into a Docker container,
providing unrestricted read/write access to all host files from within
the container. (Risk: critical)
- **Docker Privileged Container Run** — An AI agent runs a Docker container with the `--privileged` flag, granting
it full host capabilities and effectively removing all container isolation. (Risk: critical)
- **Package Config File Edit** — Modification of package registry config files (.npmrc, .pypirc) can redirect package
resolution to malicious sources, enabling dependency confusion, supply chain injection,
or credential theft from registry tokens stored in these files. (Risk: high)
- **Non-Standard Package Registry** — A command installs packages from a non-standard registry, enabling
dependency confusion attacks where malicious packages shadow legitimate ones. (Risk: high)
- **Model Checkpoint Substitution** — Replacing a legitimate model checkpoint file with a malicious one causes
any system that loads the checkpoint to execute attacker-controlled model
weights or embedded code (e.g., pickle exploits in PyTorch .pt files). (Risk: critical)
- **Training Data Tampering** — Writing malicious examples into fine-tuning datasets or training data files
can introduce backdoors, biases, or capability degradation into AI models
that are subsequently trained on the poisoned data. (Risk: critical)
- **Global Package Install** — Installing packages globally affects the entire system environment, amplifying the
impact of any supply chain compromise by making malicious code available to all
users and processes on the system. (Risk: high)
- **Package Security Control Bypass** — Disabling npm post-install scripts protection or tampering with lockfiles removes
critical supply chain safeguards, directly enabling malicious package execution
and dependency integrity bypass. (Risk: critical)
- **Standard Package Install** — Package install commands (npm, pip, yarn, brew, go get, cargo, gem) introduce
third-party code that may contain vulnerabilities, malicious payloads, or known
CVEs without explicit human review. (Risk: medium)
- **AI Hallucination Injection** — An AI agent outputs fabricated facts, URLs, package names, or code references
without grounding checks, and these outputs are persisted or acted upon by
downstream systems without human verification. (Risk: high)
- **AI Misinformation Propagation** — An AI agent writes or commits misleading, false, or unverified content
(documentation, code comments, changelogs, config) that persists in the
codebase or downstream systems without human review, causing teams to rely
on incorrect information. (Risk: high)
- **Uncontrolled Agent/Orchestration Execution** — Agent orchestration frameworks (LangChain, CrewAI, AutoGen) enable autonomous
multi-step execution with broad tool access, increasing the attack surface
significantly compared to single-shot LLM calls. (Risk: high)
- **Uncontrolled Model Invocation** — Unaudited LLM API client imports allow uncontrolled model invocations that may
incur costs, process sensitive data, or bypass policy controls by enabling
arbitrary LLM calls without governance or audit logging. (Risk: medium)

## CC9.1: Risk Mitigation Activities

- **Data Exfiltration via LLM API** — An AI agent sends sensitive local data (credentials, source code, internal
documents) to an external LLM API endpoint, causing unintended data exfiltration
through a seemingly legitimate channel. (Risk: high)
- **AWS EC2 Instance Termination** — An AI agent terminates one or more AWS EC2 instances using the AWS CLI,
causing immediate and irreversible shutdown and data loss for ephemeral storage. (Risk: critical)
- **AWS RDS Database Deletion** — An AI agent deletes an AWS RDS database instance or cluster,
causing irreversible loss of all stored data unless a final snapshot is taken. (Risk: critical)
- **AWS S3 Recursive Deletion or Bucket Removal** — An AI agent recursively deletes all objects in an S3 bucket or removes the
bucket itself, causing irreversible loss of cloud storage data. (Risk: critical)
- **Azure Resource Group Deletion** — An AI agent deletes an Azure resource group, destroying ALL resources within
it — VMs, databases, storage, networking, and every other Azure service in scope. (Risk: critical)
- **Azure SQL Database Deletion** — An AI agent deletes an Azure SQL database, permanently destroying managed
relational data unless a recent backup exists within the retention window. (Risk: critical)
- **Azure Storage Blob Batch Deletion** — An AI agent uses `az storage blob delete-batch` to delete all blobs in an
Azure storage container, causing irreversible loss of cloud storage data. (Risk: critical)
- **Azure VM Deletion** — An AI agent deletes an Azure Virtual Machine, permanently terminating the
compute instance and potentially its associated OS disk and NIC. (Risk: critical)
- **GCloud Compute Instance Deletion** — An AI agent deletes a Google Cloud Compute Engine instance,
permanently destroying the VM and its attached boot disk. (Risk: critical)
- **GCloud Project Deletion** — An AI agent deletes an entire Google Cloud project, destroying ALL resources
within it — VMs, databases, storage, APIs, IAM, and billing configurations. (Risk: critical)
- **GCloud Cloud SQL Instance Deletion** — An AI agent deletes a Google Cloud SQL managed database instance,
permanently destroying all stored data and automated backups within the instance. (Risk: critical)
- **GCloud Storage Deletion** — An AI agent recursively deletes objects from Google Cloud Storage using
`gcloud storage rm`, causing irreversible loss of cloud storage data. (Risk: critical)
- **Kubernetes Namespace Deletion** — An AI agent deletes a Kubernetes namespace, terminating all workloads,
services, config maps, secrets, and persistent volume claims within it. (Risk: critical)
- **Disk Overwrite** — A command uses dd or similar tool to overwrite disk data with zeros
or random bytes, causing irreversible data loss. (Risk: critical)
- **Filesystem Format** — A command creates a new filesystem on a disk or partition, destroying
all existing data on that device. (Risk: critical)
- **Recursive Root Delete** — A command recursively deletes files starting from the filesystem root,
causing irreversible destruction of the entire operating system and data. (Risk: critical)
- **System Directory Delete** — A command recursively deletes critical system directories such as /etc,
/usr, /var, /boot, /sys, or /proc, causing system instability or failure. (Risk: critical)
- **World-Writable Permissions** — A command sets world-writable permissions (777) on root or system paths,
removing all file access protections. (Risk: high)
- **Unbounded Financial Transfer** — An AI agent executes a financial transfer or resource commitment without
enforcing value limits, risking catastrophic loss from parsing errors,
misinterpreted instructions, or social engineering. (Risk: critical)
- **Fork Bomb** — A command spawns processes recursively until system resources are
exhausted, causing a denial-of-service condition. (Risk: critical)
- **System Shutdown/Reboot** — Issuing shutdown, reboot, halt, or poweroff commands causes immediate service
disruption and potential data loss, constituting a denial-of-service attack
against the host system. (Risk: critical)
- **CI/CD Pipeline Configuration Write** — An AI agent writes or modifies CI/CD pipeline configuration files
(e.g., `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`),
potentially injecting malicious steps that execute during automated builds. (Risk: high)

## PI1.3: Processing Integrity — Data Accuracy

_No weaknesses mapped yet._

