# Contributing to AgentShield

Thank you for your interest in contributing to AgentShield! This document provides guidelines for contributors.

## Getting Started

### Prerequisites
- Go 1.23 or later
- Git
- Make

### Setup
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/agentshield-oss.git
   cd agentshield-oss
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/AI-AgentLens/agentshield-oss.git
   ```
4. Install dependencies:
   ```bash
   make deps
   ```
5. Set up pre-commit hooks:
   ```bash
   make setup-hooks
   ```

## Development Workflow

### 1. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Follow existing code style
- Add tests for new functionality
- Update documentation if needed
- Run pre-commit checks automatically:
  ```bash
  make check  # Manual check before commit
  ```

### 3. Testing
- All tests must pass: `make test`
- Add tests for new features
- Test edge cases and security scenarios

### 4. Commit
```bash
git commit -m "feat: add your feature description"
```
The pre-commit hook will automatically run tests, linting, and build checks.

### 5. Push and Create PR
```bash
git push origin feature/your-feature-name
```
Create a Pull Request using the provided template.

## Code Guidelines

### Security First
- All changes must maintain security boundaries
- Test for policy bypass scenarios
- Consider attack vectors for new features
- Never reduce security for convenience

### Code Style
- Follow Go conventions and idioms
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

### Testing
- Write unit tests for all new code
- Test error conditions and edge cases
- Include security-focused tests
- Maintain test coverage

### Policy Rules
- New policy rules should be defensive
- Test against legitimate use cases
- Document rule intent and scope
- Consider false positive/negative impacts

## Types of Contributions

### 🐛 Bug Fixes
- Use issue template to report bugs
- Include reproduction steps
- Add tests that prevent regression
- Fix the root cause, not symptoms

### ✨ New Features
- Open an issue for discussion first
- Consider security implications
- Design for extensibility
- Include comprehensive tests

### 📚 Documentation
- Update README for user-facing changes
- Add inline code comments
- Update policy documentation
- Include examples and use cases

### 🔒 Security
- Report vulnerabilities privately
- Follow responsible disclosure
- Test for bypass scenarios
- Consider threat modeling

## Review Process

### Pull Request Requirements
- [ ] All tests pass
- [ ] Linting passes
- [ ] Build succeeds
- [ ] Security review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

### Review Focus Areas
- **Security**: Does this introduce vulnerabilities?
- **Correctness**: Does the code work as intended?
- **Testing**: Are tests comprehensive?
- **Documentation**: Is it well documented?
- **Performance**: Any performance implications?

## Release Process

### Versioning
- Follow Semantic Versioning (SemVer)
- MAJOR.MINOR.PATCH format
- Breaking changes increment MAJOR
- New features increment MINOR
- Bug fixes increment PATCH

### Changelog
- Update CHANGELOG.md for all user-facing changes
- Categorize changes: Added, Changed, Deprecated, Removed, Fixed, Security
- Include migration notes for breaking changes

## Community Guidelines

### Code of Conduct
- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Prioritize security and user safety

### Communication
- Use GitHub issues for discussions
- Ask questions before implementing
- Share knowledge and experiences
- Consider security implications

## Getting Help

### Resources
- [README.md](README.md) - Project overview
- [docs/](docs/) - Detailed documentation
- [packs/](packs/) - Policy rule examples
- Issues - Q&A and discussions

### Contact
- Create an issue for questions
- Tag maintainers for specific expertise
- Use security template for vulnerability reports

## Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes for significant contributions
- Security acknowledgments for vulnerability reports

Thank you for contributing to AgentShield! 🛡️
