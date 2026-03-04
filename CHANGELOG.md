# Changelog

All notable changes to NeuroSentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SECURITY.md with responsible disclosure guidelines
- Dependabot configuration for automated dependency updates
- Additional golangci-lint linters (gosec, stylecheck, unconvert, exhaustive)
- Proper CIDR matching using `net.ParseCIDR()` in policy evaluation
- Process chain tracking via `/proc/[pid]/status` parsing
- TC cleanup error logging for better debugging
- GitHub issue and PR templates
- CODEOWNERS file for PR review automation
- .gitattributes for proper binary file handling

### Changed
- Fixed typo: `DisableCOHRE` renamed to `DisableCORE` in BPF config
- Improved TC filter cleanup with proper error handling
- Updated documentation to clarify TC vs XDP usage

### Fixed
- `GetProcessChain()` now actually reads `/proc` to build process tree
- `matchCIDR()` now uses proper CIDR parsing instead of string matching
- TC cleanup errors are now logged instead of silently ignored

## [1.0.0] - 2025-02-06

### Added
- Initial release of NeuroSentry
- LSM-based file integrity monitoring for AI model files
- TC/XDP-based network containment for data exfiltration prevention
- Uprobe-based PyTorch and pickle monitoring
- Prometheus metrics endpoint
- Kubernetes deployment manifests
- Docker support with multi-stage builds
- Comprehensive policy engine with YAML configuration
- Support for multiple model file formats (.safetensors, .gguf, .pth, .pt, .pkl, .bin, .h5)

### Security
- Protection against pickle deserialization attacks
- Model file access control and auditing
- Network egress filtering with allowlist support

[Unreleased]: https://github.com/neurosentry/neurosentry/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/neurosentry/neurosentry/releases/tag/v1.0.0
