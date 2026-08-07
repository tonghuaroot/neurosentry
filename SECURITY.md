# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of NeuroSentry seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Responsible Disclosure

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **tonghuaroot@gmail.com** with subject prefix `[NeuroSentry Security]`.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., buffer overflow, privilege escalation, injection, etc.)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability and potential attack scenarios

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours.
- **Communication**: We will keep you informed of the progress toward a fix.
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous).
- **Timeline**: We aim to resolve critical vulnerabilities within 90 days.

### Scope

The following are in scope for security reports:

- NeuroSentry agent (`cmd/neurosentry`)
- eBPF programs (`pkg/bpf/*.c`)
- Go packages (`pkg/*`)
- Docker images (`deploy/docker/`)
- Kubernetes manifests (`deploy/kubernetes/`)
- Configuration files that could lead to security issues

### Out of Scope

- Vulnerabilities in third-party dependencies (report to the respective project)
- Social engineering attacks
- Physical attacks
- Denial of service attacks that only affect availability

## Security Best Practices

When deploying NeuroSentry:

1. **Run with minimal privileges**: Use the principle of least privilege. Only grant CAP_BPF, CAP_NET_ADMIN, and CAP_SYS_ADMIN when necessary.

2. **Protect configuration files**: Ensure `config.yaml` and policy files have appropriate permissions (e.g., `chmod 600`).

3. **Network isolation**: Deploy NeuroSentry in isolated network segments where possible.

4. **Monitor logs**: Enable logging and monitor for suspicious activity.

5. **Keep updated**: Regularly update to the latest version to receive security patches.

6. **Validate policies**: Review and test security policies before deployment.

## Security Features

NeuroSentry provides the following security features:

- **Model File Integrity Monitoring (FIM)**: Protects AI model files from unauthorized access
- **Network Containment**: Monitors network egress via TC eBPF programs and raises exfiltration findings (monitor-only in v1.0 — does not drop packets)
- **Pickle Bomb Protection**: Detects and correlates malicious pickle deserialization via uprobes (observe-only — does not block the call)
- **PyTorch Observability**: Monitors model loading operations

## Supply-chain provenance

NeuroSentry runs a privileged eBPF agent in the kernel, so the integrity of what
you deploy matters as much as what it does. Every release build produces a
**CycloneDX software bill of materials (SBOM)** enumerating all Go module
dependencies and their licenses:

```
make sbom      # writes bin/neurosentry.cdx.json (CycloneDX 1.6)
```

CI generates and publishes the SBOM as a build artifact alongside the binary
(see `.github/workflows/ci.yml`). The agent is built `CGO_ENABLED=0` as a static
binary — including the pure-Go SQLite dependency — so there is no dynamic
system-library surface to audit separately.

### Signed releases (keyless / Sigstore)

CI signs both the binary and the SBOM with **cosign keyless signing**: the
signing identity is the GitHub Actions workflow's OIDC token (no long-lived
keys), and the signatures are recorded in the public **Rekor** transparency log.
The `.sig` and `.pem` files are published as build artifacts. Verify a download
with:

```
cosign verify-blob \
  --certificate neurosentry.pem \
  --signature neurosentry.sig \
  --certificate-identity-regexp 'https://github.com/.*/neurosentry.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  neurosentry
```

## Acknowledgments

We would like to thank the following individuals for responsibly disclosing security vulnerabilities:

- (Your name could be here!)
