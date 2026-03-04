#!/bin/bash
# Capture The Model Challenge Setup Script
# Black Hat Arsenal Demo

set -e

CHALLENGE_DIR="/opt/capture-the-model"
MODEL_PATH="${CHALLENGE_DIR}/model/llama-2-7b.safetensors"
MODEL_SIZE_GB=13

echo "=========================================="
echo "NeuroSentry: Capture The Model Challenge"
echo "Black Hat USA Arsenal 2026"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Create challenge directory
mkdir -p "$CHALLENGE_DIR"
cd "$CHALLENGE_DIR"

echo "[+] Setting up challenge environment..."

# Create a fake model file (for demo purposes)
echo "[+] Creating protected model file..."
mkdir -p model
dd if=/dev/urandom of="$MODEL_PATH" bs=1M count=$((MODEL_SIZE_GB * 1024)) 2>/dev/null
echo "Created ${MODEL_SIZE_GB}GB model file at $MODEL_PATH"

# Deploy NeuroSentry
echo "[+] Deploying NeuroSentry..."
docker run -d \
    --name neurosentry \
    --privileged \
    --pid=host \
    --network=host \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v "${CHALLENGE_DIR}/config.yaml:/etc/neurosentry/config.yaml" \
    -v "${MODEL_PATH}:${MODEL_PATH}" \
    neurosentry:latest

# Wait for NeuroSentry to start
echo "[+] Waiting for NeuroSentry to initialize..."
sleep 5

# Create attacker container
echo "[+] Creating attacker container..."
docker run -d \
    --name attacker \
    --network=host \
    --privileged \
    -v "${MODEL_PATH}:/target/model.safetensors:ro" \
    -v "${CHALLENGE_DIR}/attacker:/workspace" \
    alpine:3.19 \
    sleep infinity

# Install tools in attacker container
docker exec attacker sh -c "
    apk add --no-cache curl nmap nmap-scripts netcat-openbsd
"

# Copy challenge files
echo "[+] Copying challenge files..."
cat > "${CHALLENGE_DIR}/attacker/mission.txt" << 'EOF'
╔═══════════════════════════════════════════════════════════════════╗
║           NEUROSENTRY: CAPTURE THE MODEL CHALLENGE               ║
║                  Black Hat USA Arsenal 2026                       ║
╚═══════════════════════════════════════════════════════════════════╝

MISSION:
--------
You have gained access to an inference pod running a Llama-2-7B model.
The model file is located at: /target/model.safetensors

NeuroSentry is actively protecting this file. Your mission:

1. Copy /target/model.safetensors to /tmp/stolen/
2. Get the file to verify it's intact (md5sum)

CONSTRAINTS:
-----------
- Time limit: 15 minutes
- NeuroSentry is running in enforce mode
- Kernel LSM hooks are active
- Network containment is enabled

HINTS:
------
- The model is 13GB - plan your exfiltration carefully
- Consider: Can you kill the BPF programs? Unload them? Bypass them?
- What about container escape? Kernel exploits?
- Maybe there's a vulnerability in NeuroSentry itself?

GOOD LUCK!
----------

If you succeed: You get a BLACK HAT (and find a real bug!)
If you fail: You get a WHITE HAT (for trying!)
If you find a novel bypass: You get a GREY HAT (we'll buy you a drink!)

Report your findings: challenges@neurosentry.io
EOF

# Create solutions reference (for organizers only - hidden!)
mkdir -p "${CHALLENGE_DIR}/.organizers-only"
cat > "${CHALLENGE_DIR}/.organizers-only/solutions.txt" << 'EOF'
ORGANIZER REFERENCE - DO NOT SHOW PARTICIPANTS
===============================================

Expected Results:
-----------------
1. MOST ATTEMPTS WILL FAIL - NeuroSentry is designed to be robust
2. Common attempts:
   - cat/cp/dd -> EPERM (blocked by LSM)
   - Kill neurosentry container -> Auto-restart by systemd
   - rm /sys/fs/bpf/* -> Read-only maps
   - Kernel module unload -> BPF programs are JIT-compiled, not modules

Potential Bypasses (hypothetical - should be patched!):
-------------------------------------------------------
1. If attacker can modify vmlinux BTF -> Could confuse CO-RE relocations
2. If attacker can trigger a specific kernel panic -> BPF programs unload
3. If attacker finds a bug in NeuroSentry's CIDR parsing -> Network bypass
4. Race condition between map update and policy evaluation

If Someone Succeeds:
--------------------
1. Verify the exploit
2. Thank them enthusiastically!
3. Issue CVE if needed
4. Buy them a drink at the Arsenal party
5. Fix the bug before the conference ends

Prize Distribution:
------------------
- Black Hat: Successful exfiltration (unlimited)
- White Hat: 10+ creative attempts (participation trophy)
- Grey Hat: Found a real bug (consulting job offer?)

Safety Notes:
-------------
1. This is an ISOLATED environment - no production systems
2. The "model" is just random data - no real IP
3. Network containment should prevent accidental exfiltration
4. Have a rollback plan if someone DoS's the demo machine

Contact: @NeuroSentryTeam on Twitter
EOF

# Print completion message
echo ""
echo "=========================================="
echo "Challenge Setup Complete!"
echo "=========================================="
echo ""
echo "Attacker container: docker exec -it attacker sh"
echo "NeuroSentry logs:    docker logs -f neurosentry"
echo "NeuroSentry metrics: http://localhost:2112/metrics"
echo ""
echo "Mission file: ${CHALLENGE_DIR}/attacker/mission.txt"
echo ""
echo "Good luck!"
