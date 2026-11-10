#!/usr/bin/env bash
# Test suite for agent-sudo guardrails and flags

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCRIPT_DIR}/../bin/agent-sudo"

PASS=0
FAIL=0

assert_blocked() {
  local desc="$1"
  shift
  local output
  output=$("${BIN}" "$@" 2>&1)
  local status=$?

  if [ "${status}" -eq 126 ] && echo "${output}" | grep -q "BLOCKED"; then
    echo "[PASS] Blocked: ${desc}"
    PASS=$((PASS + 1))
  else
    echo "[FAIL] Expected blocked for: ${desc} (exit: ${status}, output: ${output})"
    FAIL=$((FAIL + 1))
  fi
}

assert_allowed() {
  local desc="$1"
  shift
  # We test guardrail check function by checking that it doesn't fail with 126
  # Because the backend might not be installed yet in /usr/local/libexec,
  # exit code 127 (backend missing) or 0/1 means it passed guardrails!
  local output
  output=$("${BIN}" "$@" 2>&1 || true)

  if echo "${output}" | grep -q "BLOCKED"; then
    echo "[FAIL] False positive blocked for: ${desc} (output: ${output})"
    FAIL=$((FAIL + 1))
  else
    echo "[PASS] Allowed: ${desc}"
    PASS=$((PASS + 1))
  fi
}

echo "=== Running agent-sudo Flag Tests ==="

# Test Help
HELP_OUT=$("${BIN}" --help)
if echo "${HELP_OUT}" | grep -q "USAGE:"; then
  echo "[PASS] --help displays usage"
  PASS=$((PASS + 1))
else
  echo "[FAIL] --help failed"
  FAIL=$((FAIL + 1))
fi

# Test Version
VER_OUT=$("${BIN}" --version)
if echo "${VER_OUT}" | grep -q "agent-sudo 0.1.0"; then
  echo "[PASS] --version displays 0.1.0"
  PASS=$((PASS + 1))
else
  echo "[FAIL] --version failed"
  FAIL=$((FAIL + 1))
fi

echo "=== Running Guardrail Blocking Tests ==="
assert_blocked "Recursive root wipe (rm -rf /)" rm -rf /
assert_blocked "Recursive root wipe (rm -rf /*)" rm -rf /*
assert_blocked "Recursive root wipe separated (rm -r -f /)" rm -r -f /
assert_blocked "Recursive root wipe reversed (rm -fr /)" rm -fr /
assert_blocked "Recursive /boot wipe" rm -rf /boot
assert_blocked "Recursive /etc wipe" rm -rf /etc
assert_blocked "Recursive /usr wipe" rm -rf /usr
assert_blocked "Recursive /bin wipe" rm -rf /bin
assert_blocked "Raw disk format with mkfs" mkfs.ext4 /dev/nvme0n1p1
assert_blocked "Disk wipe with wipefs" wipefs -a /dev/sda
assert_blocked "Raw disk overwrite with dd" dd if=/dev/zero of=/dev/sda bs=1M
assert_blocked "Raw disk overwrite with dd nvme" dd if=/dev/urandom of=/dev/nvme0n1
assert_blocked "Direct overwrite /etc/shadow" bash -c 'echo "hacked" > /etc/shadow'
assert_blocked "Direct remove /etc/shadow" rm /etc/shadow
assert_blocked "Fork bomb" ':(){ :|:& };:'

echo "=== Running Guardrail Allowed Tests ==="
assert_allowed "Package installation (pacman)" pacman -S --noconfirm ripgrep
assert_allowed "Service restart (systemctl)" systemctl restart NetworkManager
assert_allowed "Safe directory removal" rm -rf /tmp/my-temp-dir-12345
assert_allowed "Creating directory" mkdir -p /opt/custom-app
assert_allowed "Changing permissions" chmod 0755 /opt/custom-app
assert_allowed "Writing systemd service" tee /etc/systemd/system/myapp.service
assert_allowed "Updating pacman mirrors" reflector --latest 5 --save /etc/pacman.d/mirrorlist

echo ""
echo "=== Test Summary: ${PASS} Passed, ${FAIL} Failed ==="
if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi
exit 0
