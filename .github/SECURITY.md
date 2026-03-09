# Security Policy

## Supported Versions
| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current         |
| < 0.1   | ❌ Not supported   |

## Reporting a Vulnerability

### Private Reporting (Preferred)
For security vulnerabilities, please report privately:

1. **GitHub Security Advisories**
   - Go to: https://github.com/security-researcher-ca/AI_Agent_Shield/security/advisories
   - Click "Report a vulnerability"
   - Follow the guided process

2. **Email**
   - Send to: security@security-researcher-ca.com  # TODO: update with actual team email
   - Include "AgentShield Security" in subject
   - Use PGP key if available (request via email)

### Public Reporting
If you're comfortable with public disclosure:
- Use the [Security Vulnerability Issue Template](.github/ISSUE_TEMPLATE/security_vulnerability.md)
- Mark with `[SECURITY]` label

### What to Include
- Vulnerability type and severity
- Affected versions
- Proof of concept (steps to reproduce)
- Potential impact
- Any mitigation workarounds

## Response Timeline
- **Initial response**: Within 48 hours
- **Detailed assessment**: Within 7 days  
- **Fix timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: Next release cycle

## Security Best Practices

### For Users
1. **Keep Updated**: Always use the latest version
2. **Review Policies**: Audit your policy configurations
3. **Least Privilege**: Run with minimal required permissions
4. **Audit Logs**: Regularly review AgentShield audit logs

### For Developers
1. **Input Validation**: All user inputs should be validated
2. **Policy Testing**: Test policies against bypass scenarios
3. **Secure Defaults**: Default policies should be restrictive
4. **Dependency Updates**: Keep dependencies updated

## Security Scope

### In Scope
- AgentShield binary and source code
- Default policy configurations
- Integration with OpenClaw and other hooks
- Build and distribution processes

### Out of Scope
- User-defined policy configurations
- Third-party integrations not maintained by us
- Issues in underlying Go runtime or dependencies

## Security Acknowledgments
We follow responsible disclosure principles and will:
- Acknowledge reports promptly
- Coordinate disclosure timeline
- Credit researchers (with permission)
- Share fix details after disclosure

## Threat Model
AgentShield is designed to protect against:
- **Command Injection**: Malicious commands to LLM agents
- **Data Exfiltration**: Unauthorized data transfers
- **System Compromise**: Privilege escalation attempts
- **Policy Bypass**: Attempts to circumvent security controls

For detailed threat modeling, see: [docs/threat-model.md](docs/threat-model.md)
