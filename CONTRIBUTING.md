# Contributing to Attack Pattern Classification Engine

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/attack-pattern-classifier.git`
3. Create a virtual environment: `python -m venv venv`
4. Install dev dependencies: `pip install -r requirements.txt`
5. Install pre-commit hooks: `pre-commit install`

## Code Standards

- **Python 3.10+** required
- Follow **PEP 8** style guide
- Use **black** for formatting: `black .`
- Use **mypy** for type checking: `mypy .`
- Maximum line length: 100 characters
- All functions must have type hints and docstrings

## Testing

- Write tests for all new functionality
- Maintain minimum **90% code coverage**
- Run tests before submitting: `pytest tests/ -v --cov=.`
- Include integration tests for pipeline changes

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Make your changes with clear, atomic commits
3. Add/update tests as needed
4. Update documentation (README, docstrings)
5. Run full test suite: `pytest tests/`
6. Submit PR with clear description of changes

## Commit Message Format

```
type(scope): subject

body (optional)

footer (optional)
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(models): add HDBSCAN clustering support

- Implement HDBSCAN wrapper class
- Add silhouette score computation
- Include comprehensive unit tests
```

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include Python version, OS, and steps to reproduce
- Attach relevant log excerpts (sanitized)

## Security

- Never commit API keys, passwords, or credentials
- Report security vulnerabilities privately to [your-email@example.com]
