#!/usr/bin/env bash
# install.sh - Production installer for agent-sudo
# CLOUDWERX OS - Automated privilege elevation runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-cloudwerx}"

# Paths
BACKEND_SRC="${SCRIPT_DIR}/bin/agent-sudo-backend"
FRONTEND_SRC="${SCRIPT_DIR}/bin/agent-sudo"
SUDOERS_SRC="${SCRIPT_DIR}/sudoers/99-agent-sudo"
FISH_COMP_SRC="${SCRIPT_DIR}/completions/agent-sudo.fish"
BASH_COMP_SRC="${SCRIPT_DIR}/completions/agent-sudo.bash"

BACKEND_DEST="/usr/local/libexec/agent-sudo-backend"
FRONTEND_DEST="/usr/local/bin/agent-sudo"
SUDOERS_DEST="/etc/sudoers.d/99-agent-sudo"
LOG_DEST="/var/log/agent-sudo.log"
BASH_COMP_DEST="/etc/bash_completion.d/agent-sudo"

USER_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
USER_FISH_COMP_DIR="${USER_HOME}/.config/fish/completions"
USER_LOCAL_BIN="${USER_HOME}/.local/bin"

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: installer must be run as root." >&2
  echo "Usage: sudo ./install.sh [--uninstall]" >&2
  exit 1
fi

uninstall() {
  echo "=== Uninstalling agent-sudo ==="
  rm -f "${BACKEND_DEST}"
  rm -f "${FRONTEND_DEST}"
  rm -f "/usr/local/bin/asudo"
  rm -f "${SUDOERS_DEST}"
  rm -f "${BASH_COMP_DEST}"
  rm -f "${USER_FISH_COMP_DIR}/agent-sudo.fish"
  rm -f "${USER_FISH_COMP_DIR}/asudo.fish"
  rm -f "${USER_LOCAL_BIN}/agent-sudo"
  rm -f "${USER_LOCAL_BIN}/asudo"
  echo "agent-sudo uninstalled. (Audit log preserved at ${LOG_DEST})"
  exit 0
}

if [ "${1:-}" = "--uninstall" ]; then
  uninstall
fi

echo "=== Installing agent-sudo for user '${TARGET_USER}' ==="

# 1. Install directories
mkdir -p /usr/local/bin
mkdir -p /usr/local/libexec
mkdir -p /etc/sudoers.d
mkdir -p /etc/bash_completion.d

# 2. Install backend runner
echo "Installing backend runner -> ${BACKEND_DEST}"
install -m 0755 -o root -g root "${BACKEND_SRC}" "${BACKEND_DEST}"

# 3. Install frontend CLI
echo "Installing frontend CLI   -> ${FRONTEND_DEST}"
install -m 0755 -o root -g root "${FRONTEND_SRC}" "${FRONTEND_DEST}"
ln -sf "${FRONTEND_DEST}" "/usr/local/bin/asudo"

# 4. User ~/.local/bin symlinks
if [ -d "${USER_LOCAL_BIN}" ]; then
  ln -sf "${FRONTEND_DEST}" "${USER_LOCAL_BIN}/agent-sudo"
  ln -sf "${FRONTEND_DEST}" "${USER_LOCAL_BIN}/asudo"
  chown -h "${TARGET_USER}:${TARGET_USER}" "${USER_LOCAL_BIN}/agent-sudo" "${USER_LOCAL_BIN}/asudo" 2>/dev/null || true
fi

# 5. Sudoers drop-in validation & installation
echo "Configuring sudoers drop-in -> ${SUDOERS_DEST}"
TMP_SUDOERS="$(mktemp /etc/sudoers.d/99-agent-sudo.tmp.XXXXXX)"

cat > "${TMP_SUDOERS}" <<EOF
# CLOUDWERX OS - Non-interactive elevated runner
# Allows user ${TARGET_USER} to execute the guarded backend runner without password prompt
${TARGET_USER} ALL=(ALL) NOPASSWD: ${BACKEND_DEST}
EOF

chmod 0440 "${TMP_SUDOERS}"

if visudo -cf "${TMP_SUDOERS}"; then
  mv "${TMP_SUDOERS}" "${SUDOERS_DEST}"
  chmod 0440 "${SUDOERS_DEST}"
  echo "Sudoers drop-in verified and activated."
else
  rm -f "${TMP_SUDOERS}"
  echo "FATAL: visudo syntax check failed! Aborting installation." >&2
  exit 1
fi

# 6. Audit log initialization
if [ ! -f "${LOG_DEST}" ]; then
  touch "${LOG_DEST}"
fi
chmod 0644 "${LOG_DEST}"
chown "root:${TARGET_USER}" "${LOG_DEST}"

# 7. Shell completions
if [ -d "${USER_FISH_COMP_DIR}" ]; then
  echo "Installing Fish completions -> ${USER_FISH_COMP_DIR}/agent-sudo.fish"
  install -m 0644 -o "${TARGET_USER}" -g "${TARGET_USER}" "${FISH_COMP_SRC}" "${USER_FISH_COMP_DIR}/agent-sudo.fish"
  ln -sf "${USER_FISH_COMP_DIR}/agent-sudo.fish" "${USER_FISH_COMP_DIR}/asudo.fish"
  chown -h "${TARGET_USER}:${TARGET_USER}" "${USER_FISH_COMP_DIR}/asudo.fish" 2>/dev/null || true
fi

if [ -f "${BASH_COMP_SRC}" ]; then
  install -m 0644 -o root -g root "${BASH_COMP_SRC}" "${BASH_COMP_DEST}"
fi

echo ""
echo "=== Verifying Installation ==="
if sudo -u "${TARGET_USER}" "${FRONTEND_DEST}" --status; then
  echo ""
  TEST_WHOAMI="$(sudo -u "${TARGET_USER}" "${FRONTEND_DEST}" whoami)"
  if [ "${TEST_WHOAMI}" = "root" ]; then
    echo "SUCCESS: Self-test passed! Elevated runner executed 'whoami' -> '${TEST_WHOAMI}' without password prompt."
  else
    echo "WARNING: Self-test returned unexpected user: '${TEST_WHOAMI}'"
  fi
else
  echo "ERROR: Status check failed." >&2
  exit 1
fi

echo ""
echo "Installation complete!"
echo "You can now run: agent-sudo <command> or asudo <command>"
