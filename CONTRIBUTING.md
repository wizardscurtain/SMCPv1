# Contributing to SMCP v1

We welcome contributions to the Secure Model Context Protocol (SMCP) v1 project! This document provides guidelines for contributing to ensure a smooth collaboration process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Poetry for dependency management
- Git for version control
- Basic understanding of security principles
- Familiarity with the Model Context Protocol (MCP)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/smcp-v1.git
   cd smcp-v1
   ```

2. **Install Dependencies**
   ```bash
   cd code
   poetry install
   poetry install --group dev
   ```

3. **Activate Virtual Environment**
   ```bash
   poetry shell
   ```

4. **Run Tests**
   ```bash
   pytest tests/ -v
   ```

5. **Run Security Checks**
   ```bash
   python -m pytest tests/security/ -v
   ```

## Contributing Process

### 1. Issue Creation

- **Bug Reports**: Use the bug report template
- **Feature Requests**: Use the feature request template
- **Security Issues**: Follow our [Security Policy](SECURITY.md)

### 2. Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number
   ```

2. **Make Changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run all tests
   pytest
   
   # Run specific test categories
   pytest tests/unit/
   pytest tests/integration/
   pytest tests/security/
   pytest tests/performance/
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new security layer validation"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### 3. Pull Request Guidelines

- **Title**: Use conventional commit format
- **Description**: Clearly explain changes and motivation
- **Tests**: Include comprehensive test coverage
- **Documentation**: Update relevant documentation
- **Security**: Consider security implications

#### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] Performance impact assessed
- [ ] Breaking changes documented

## Coding Standards

### Python Style

- **PEP 8**: Follow Python style guide
- **Type Hints**: Use type annotations
- **Docstrings**: Use Google-style docstrings
- **Line Length**: Maximum 88 characters (Black formatter)

### Code Quality Tools

```bash
# Format code
black code/

# Lint code
flake8 code/

# Type checking
mypy code/

# Security linting
bandit -r code/
```

### Security-Specific Guidelines

1. **Input Validation**
   - Always validate and sanitize inputs
   - Use whitelist approach when possible
   - Document validation rules

2. **Cryptography**
   - Use established cryptographic libraries
   - Follow current best practices
   - Document key management procedures

3. **Error Handling**
   - Don't expose sensitive information in errors
   - Log security events appropriately
   - Use custom exception types

4. **Testing**
   - Test both positive and negative cases
   - Include edge cases and boundary conditions
   - Test security controls thoroughly

## Testing Requirements

### Test Categories

1. **Unit Tests** (`tests/unit/`)
   - Test individual components
   - Mock external dependencies
   - Aim for >95% code coverage

2. **Integration Tests** (`tests/integration/`)
   - Test component interactions
   - Test end-to-end workflows
   - Validate security layer integration

3. **Security Tests** (`tests/security/`)
   - Test attack prevention
   - Validate security controls
   - Test failure scenarios

4. **Performance Tests** (`tests/performance/`)
   - Benchmark security overhead
   - Test scalability
   - Validate performance requirements

### Test Writing Guidelines

```python
def test_feature_description():
    """Test description following Given-When-Then pattern.
    
    Given: Initial conditions
    When: Action performed
    Then: Expected outcome
    """
    # Arrange
    setup_data = create_test_data()
    
    # Act
    result = function_under_test(setup_data)
    
    # Assert
    assert result.is_valid
    assert result.security_level == "HIGH"
```

### Security Test Examples

```python
def test_command_injection_prevention():
    """Test that command injection attempts are blocked."""
    malicious_input = {"command": "ls; rm -rf /"}
    
    with pytest.raises(SecurityError):
        validator.validate_input(malicious_input)

def test_rate_limiting_enforcement():
    """Test that rate limits are properly enforced."""
    # Simulate rapid requests
    for _ in range(100):
        rate_limiter.check_rate_limit("user123")
    
    # Next request should be blocked
    with pytest.raises(RateLimitError):
        rate_limiter.check_rate_limit("user123")
```

## Security Considerations

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security@smcp-project.org
2. Include detailed description
3. Provide reproduction steps
4. Allow 90 days for response

See [SECURITY.md](SECURITY.md) for full details.

### Security Review Process

All contributions undergo security review:

1. **Automated Scanning**: CI/CD security checks
2. **Code Review**: Manual security assessment
3. **Testing**: Security test validation
4. **Documentation**: Security impact documentation

### Sensitive Areas

Extra care required for:

- Authentication mechanisms
- Cryptographic operations
- Input validation logic
- Authorization controls
- Rate limiting algorithms
- Audit logging systems

## Documentation

### Required Documentation

1. **Code Documentation**
   - Comprehensive docstrings
   - Type annotations
   - Usage examples

2. **API Documentation**
   - Function/method descriptions
   - Parameter specifications
   - Return value documentation
   - Exception handling

3. **Security Documentation**
   - Threat model updates
   - Security control descriptions
   - Configuration guidelines
   - Deployment considerations

### Documentation Standards

```python
def validate_input(data: Dict[str, Any], context: str = None) -> Dict[str, Any]:
    """Validate MCP request input against security policies.
    
    This function performs comprehensive input validation including
    command injection prevention, prompt injection detection, and
    context-aware sanitization.
    
    Args:
        data: MCP request data to validate
        context: Validation context (file_system, database, api, shell)
        
    Returns:
        Validated and sanitized request data
        
    Raises:
        ValidationError: If input fails validation
        SecurityError: If malicious patterns detected
        
    Example:
        >>> validator = InputValidator()
        >>> clean_data = validator.validate_input({
        ...     "method": "tools/call",
        ...     "params": {"command": "ls -la"}
        ... })
    """
```

## Community

### Communication Channels

- **GitHub Discussions**: General questions and discussions
- **GitHub Issues**: Bug reports and feature requests
- **Security Email**: security@smcp-project.org
- **Documentation**: Project wiki and docs/

### Getting Help

1. **Check Documentation**: README, docs/, and code comments
2. **Search Issues**: Existing issues and discussions
3. **Ask Questions**: GitHub Discussions
4. **Join Community**: Follow project updates

### Recognition

Contributors are recognized through:

- **Contributors List**: README.md acknowledgments
- **Release Notes**: Contribution highlights
- **Security Hall of Fame**: Security researchers
- **Commit Attribution**: Proper git attribution

## Development Guidelines

### Branch Naming

- `feature/description`: New features
- `fix/issue-number`: Bug fixes
- `security/description`: Security improvements
- `docs/description`: Documentation updates
- `test/description`: Test improvements

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security improvement
- `docs`: Documentation
- `test`: Testing
- `refactor`: Code refactoring
- `perf`: Performance improvement

### Release Process

1. **Version Bumping**: Semantic versioning (MAJOR.MINOR.PATCH)
2. **Changelog**: Update CHANGELOG.md
3. **Testing**: Full test suite validation
4. **Security Review**: Security team approval
5. **Documentation**: Update version-specific docs

## License

By contributing to SMCP v1, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE)).

## Questions?

If you have questions about contributing, please:

1. Check this document and project documentation
2. Search existing GitHub issues and discussions
3. Create a new GitHub Discussion
4. Contact maintainers through appropriate channels

Thank you for contributing to SMCP v1! Your efforts help make AI agent interactions more secure for everyone.
