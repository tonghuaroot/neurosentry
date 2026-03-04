# Contributing to NeuroSentry

Thank you for your interest in contributing to NeuroSentry! This document provides guidelines for contributing.

## Development Environment

### Requirements
- Go 1.21+
- Clang 12+ (for eBPF compilation)
- Linux 5.10+ (for eBPF functionality)
- Docker (optional, for containerized development)

### Quick Start

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## Code Style

### Go Code
- Follow standard Go conventions
- Use `gofmt` for formatting
- Run `golangci-lint` before submitting
- Add tests for new features

### eBPF C Code
- Use kernel coding style
- Keep programs under 4096 instructions (verifier limit)
- Add helpful bpf_printk statements for debugging
- Remove debug prints before submitting

### Commit Messages
```
<type>: <short description>

<details>

Longer description of the change.

</details>
```

## Testing

### Unit Tests
```bash
go test ./pkg/...
go test -race ./pkg/...
go test -cover ./pkg/...
```

### Integration Tests
```bash
make test
./demos/demo-test.sh
```

### eBPF Testing
eBPF programs require Linux kernel 5.10+. Use:
- VM for testing
- Docker Linux container
- CI provides Linux runners

## Adding New Features

1. **Model FIM Extensions**: Add to `protected_extensions` in config
2. **Network Rules**: Update `allowed_egress` CIDRs
3. **Dangerous Symbols**: Add to `dangerous_symbols` list
4. **Uprobe Targets**: Add new framework monitoring

## Pull Request Process

1. Update documentation
2. Add/update tests
3. Ensure CI checks pass
4. Request review
5. Address feedback

## Review Criteria

- Code quality passes linting
- Tests pass
- Documentation updated
- No breaking changes without discussion
- eBPF verifier happy

## Areas for Contribution

We welcome contributions in:
- Additional AI framework support (Hugging Face, vLLM, etc.)
- Windows/macOS support via alternative mechanisms
- Enhanced policy language
- GPU memory monitoring
- SBOM integration for model provenance
- More integration tests
- Performance optimizations
- Documentation improvements

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
