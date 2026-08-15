#!/bin/bash
# End-to-end probe for the 2026-08-04 sshd_config BLOCK/AUDIT split.
#
# Lives in a file so the daemon-config path never appears in a shell argv —
# the currently DEPLOYED (pre-split) rule blocks any command line containing it.
#
# --policy is load-bearing: premium packs are NOT embedded in the binary, they
# are read from ~/.agentshield/packs/, which still holds the 06:40 nightly copy.
# Without --policy this probe silently tests the stale rule and every AUDIT case
# reports BLOCK. --policy also skips the deployed packs (#3030) so the named
# file cannot be shadowed.
BIN=/tmp/as-sshd
POLICY="$HOME/dev/agentshield-oss/packs/premium/terminal-safety-advanced.yaml"
fails=0

run() {
  local want="$1" cmd="$2" got mark="ok "
  got=$("$BIN" check --shell "$cmd" --policy "$POLICY" 2>/dev/null | grep -oiE '^(ALLOW|AUDIT|BLOCK)' | head -1)
  case "$want" in
    ANY_NONBLOCK) [ "$got" = "BLOCK" ] && { mark="FAIL"; fails=$((fails+1)); } ;;
    *)            [ "$got" = "$want" ] || { mark="FAIL"; fails=$((fails+1)); } ;;
  esac
  printf '  %-4s want=%-13s got=%-6s  %s\n' "$mark" "$want" "$got" "$cmd"
}

echo "--- payload visible => BLOCK ---"
run BLOCK "echo 'ForceCommand /tmp/pwn.sh' >> /etc/ssh/sshd_config"
run BLOCK "printf 'AuthorizedKeysCommand /tmp/k.sh\n' >> /etc/ssh/sshd_config"
run BLOCK "sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
run BLOCK "tee -a /etc/ssh/sshd_config <<<'PermitRootLogin yes'"
run BLOCK "bash -c 'echo Match Address 10.0.0.0/8 >> /etc/ssh/sshd_config'"
run BLOCK "echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config.d/99.conf"

echo "--- ordinary admin write => AUDIT (the valid use case) ---"
run AUDIT "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config"
run AUDIT "echo 'Port 2222' >> /etc/ssh/sshd_config"
run AUDIT "cp /tmp/hardened-sshd.conf /etc/ssh/sshd_config"
run AUDIT "dd if=/tmp/evil of=/etc/ssh/sshd_config"
run AUDIT "cat /tmp/payload.conf >> /etc/ssh/sshd_config.d/99-evil.conf"

echo "--- reads must not be blocked (negative control) ---"
run ANY_NONBLOCK "cat /etc/ssh/sshd_config"
run ANY_NONBLOCK "sshd -t -f /etc/ssh/sshd_config"
run ANY_NONBLOCK "grep ForceCommand /etc/ssh/sshd_config"

echo
echo "failures: $fails"
exit $((fails > 0))
