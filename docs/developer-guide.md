# NeuroSentry Developer Guide

## Building from Source

### Prerequisites

- Go 1.25+
- Clang 12+
- LLVM toolchain
- libbpf development headers
- Linux kernel headers

### Build Process

```bash
# Install dependencies
./scripts/install-deps.sh

# Build all components
./scripts/build.sh

# Build with Docker image
./scripts/build.sh --docker
```

### Project Structure

```
NeuroSentry/
├── cmd/neurosentry/     # Main application entry point
├── pkg/
│   ├── bpf/             # eBPF C programs
│   ├── agent/           # User-space agent logic
│   ├── config/          # Configuration handling
│   └── policy/          # Policy engine
├── deploy/
│   ├── docker/          # Docker builds
│   └── kubernetes/      # K8s manifests
├── docs/                # Documentation
└── scripts/             # Build and test scripts
```

## eBPF Development

### Adding New LSM Hooks

1. Define the hook in `pkg/bpf/neurosentry_lsm.c`:

```c
SEC("lsm/new_hook_name")
int BPF_PROG(my_new_hook, struct relevant_struct *arg) {
    // Your logic here
    return 0;  // Return 0 for allow, -EPERM for deny
}
```

2. Generate Go bindings:

```bash
cd pkg/bpf
go generate ./...
```

3. Attach from Go code in `pkg/bpf/bpf.go`:

```go
l, err := link.AttachLSM(link.LSMOptions{
    Program: objs.MyNewHook,
})
if err != nil {
    return fmt.Errorf("attaching hook: %w", err)
}
m.links = append(m.links, l)
```

### Adding New Uprobes

1. Define the uprobe in `pkg/bpf/neurosentry_uprobe.c`:

```c
SEC("uprobe")
int uprobe_my_function(struct pt_regs *ctx) {
    // Access arguments via PT_REGS_PARM1(ctx), etc.
    return 0;
}
```

2. Attach from Go:

```go
exe, err := link.OpenExecutable("/path/to/binary")
if err != nil {
    return err
}

uprobe, err := exe.Uprobe("function_name", objs.UprobeMyFunction, nil)
if err != nil {
    return err
}
m.links = append(m.links, uprobe)
```

## Go Development

### Adding a New Agent Component

1. Define the component interface in `pkg/agent/`:

```go
type MyComponent struct {
    cfg *config.Config
    // Add fields
}

func NewMyComponent(cfg *config.Config) *MyComponent {
    return &MyComponent{cfg: cfg}
}

func (c *MyComponent) Name() string {
    return "my-component"
}

func (c *MyComponent) Start(ctx context.Context) error {
    // Start logic
    return nil
}

func (c *MyComponent) Stop() error {
    // Stop logic
    return nil
}
```

2. Register in controller:

```go
// In Controller.initComponents()
myComp := NewMyComponent(c.cfg)
c.components = append(c.components, myComp)
```

### Adding New Metrics

```go
// In MetricsCollector
customMetric := prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "neurosentry_custom_metric",
        Help: "Description of metric",
    },
    []string{"label1", "label2"},
)

// Register
prometheus.MustRegister(customMetric)

// Use
customMetric.WithLabelValues("value1", "value2").Inc()
```

## Testing

### Unit Tests

```bash
# Run all tests
./scripts/test.sh

# Run with coverage
./scripts/test.sh --coverage

# Run with linters
./scripts/test.sh --lint
```

### eBPF Testing

Use VM or container for eBPF testing:

```bash
# Start test VM
vagrant up

# Run tests in VM
vagrant ssh -c "cd /vagrant && sudo ./scripts/test.sh"
```

### Integration Testing

```bash
# Start test environment
cd demos/test-environment
docker-compose up -d

# Run integration tests
go test -v ./tests/integration/...
```

## Code Style

### Go Code

- Follow standard Go conventions
- Use `gofmt` for formatting
- Run `golangci-lint` before submitting PRs

```bash
go fmt ./...
golangci-lint run ./...
```

### eBPF Code

- Use kernel coding style
- Keep programs under 4096 instructions ( verifier limit)
- Use helper functions for code reuse
- Add bpf_printk for debugging (remove in production)

## Debugging

### eBPF Verifier Debugging

```bash
# Enable verifier logs
echo 1 > /sys/kernel/debug/tracing/options/trace_printk

# View verifier output
bpftool prog dump xlated id <prog_id>
bpftool prog dump jited id <prog_id>
```

### Runtime Debugging

```bash
# Enable debug logs
sudo ./bin/neurosentry --log-level debug

# View ring buffer events
sudo bpftool map dump name events

# Check map contents
sudo bpftool map dump name trusted_pids
```

### BPF Tracing

```bash
# Trace BPF programs
bpftrace -e 'kprobe:bpf_prog_run_xdp { printf("XDP prog run\n"); }'
```

## Contributing

### Workflow

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run linting and tests
5. Submit pull request

### Pull Request Checklist

- [ ] Tests pass
- [ ] Code formatted (`go fmt`)
- [ ] Linter passes (`golangci-lint`)
- [ ] Documentation updated
- [ ] eBPF verifier happy
- [ ] No new security issues

### Security Issues

For security vulnerabilities, email: tonghuaroot@gmail.com (subject prefix `[NeuroSentry Security]`). See [SECURITY.md](../SECURITY.md) for details.

Do not open public issues for security problems.

## Release Process

1. Update version in `cmd/neurosentry/main.go`
2. Update CHANGELOG.md
3. Create git tag
4. Build release binaries
5. Push to GitHub releases
6. Build and push Docker images

```bash
# Tag release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Build release binaries
./scripts/build-release.sh

# Build Docker images
docker build -t neurosentry:v1.0.0 .
docker push neurosentry:v1.0.0
```

## Performance Optimization

### eBPF Optimizations

1. **Use per-CPU maps** to avoid lock contention
2. **Batch operations** when updating maps
3. **Use ring buffers** instead of perf arrays
4. **Minimize string operations** in kernel

### Go Optimizations

1. **Use sync.Pool** for frequently allocated objects
2. **Buffer channels** appropriately
3. **Use binary unmarshaling** for ring buffer data
4. **Profile with pprof**

```bash
# Enable pprof
import _ "net/http/pprof"

# Analyze
go tool pprof http://localhost:2112/debug/pprof/profile
```

## Resources

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
