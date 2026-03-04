# CAPTURE THE MODEL - Challenge Brief

```
╔═══════════════════════════════════════════════════════════════════╗
║           NEUROSENTRY: CAPTURE THE MODEL CHALLENGE               ║
╚═══════════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────────┐
│                            MISSION                                │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  You have gained access to an AI inference server running        │
│  Llama-2-7B. The model weights are protected by NeuroSentry,    │
│  a kernel-level security system using eBPF technology.           │
│                                                                   │
│  Your task: Exfiltrate the model file                            │
│                                                                   │
│  Target:     /target/model.safetensors                           │
│  Size:       13 GB                                                │
│  Time:       15 minutes                                          │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                         ENVIRONMENT                               │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  [Attacker Container]                                            │
│   ├─ Shell access: docker exec -it attacker sh                   │
│   ├─ Tools: curl, nc, nmap                                      │
│   └─ Privileged mode: YES                                       │
│                                                                   │
│  [NeuroSentry Protection]                                        │
│   ├─ LSM BPF hooks (file access) - ENFORCE MODE                 │
│   ├─ XDP/TC programs (network monitoring) - MONITOR ONLY        │
│   ├─ Uprobes (framework monitoring)                              │
│   └─ File Protection: .safetensors, .gguf, .pth, .onnx, .pt     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                       ACHIEVEMENTS                                │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ATTACKER   │ Successfully exfiltrated the model                  │
│  EXPLORER   │ 10+ creative attempts (participation)               │
│  RESEARCHER │ Found novel bypass technique                        │
│  AUDITOR    │ Found critical security bug (CVE)                   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                          HINTS                                    │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  💡 "What happens when you can't bypass the security?"           │
│                                                                   │
│  💡 "How does NeuroSentry know which files to protect?"          │
│                                                                   │
│  💡 "The kernel is the ultimate arbiter of system calls"         │
│                                                                   │
│  💡 "File extensions are just part of the filename..."           │
│                                                                   │
│  💡 "Network traffic is monitored but not blocked..."            │
│                                                                   │
│  💡 "Maybe the vulnerability is in the protection itself..."     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                        VERIFICATION                               │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  If you succeed, verify:                                         │
│                                                                   │
│  1. md5sum /tmp/stolen/model.safetensors                         │
│  2. Compare with original                                        │
│  3. Document your method                                         │
│  4. Report to: github.com/tonghuaroot/neurosentry/issues         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────┐
│                          RULES                                    │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ✓ Any technique is allowed                                      │
│  ✓ Documentation of attempts encouraged                          │
│  ✓ Collaboration is allowed (team prize if successful)           │
│                                                                   │
│  ✗ No Denial of Service on other challenges                     │
│  ✗ No physical access to the machine                             │
│  ✗ No attacking other participants                               │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘

                    GOOD LUCK, HAVE FUN!

                   github.com/tonghuaroot/neurosentry
```

---

## Quick Reference

### Available Commands
```bash
# Access attacker container
docker exec -it attacker sh

# Check NeuroSentry status
curl http://localhost:2112/health

# View metrics
curl http://localhost:2112/metrics

# View NeuroSentry logs
docker logs --tail 50 neurosentry
```

### Target File
- **Path**: `/target/model.safetensors`
- **Size**: 13,824 MB (13.5 GB)
- **Format**: safetensors (PyTorch compatible)
- **MD5**: See `model.md5` file

### Success Criteria
```bash
# Your attempt is successful if:
1. /tmp/stolen/model.safetensors exists
2. md5sum matches the original
3. File is readable and complete
```

---
*This is a security research challenge. All techniques will be analyzed*
*to improve NeuroSentry and AI security overall. Happy hacking!*
