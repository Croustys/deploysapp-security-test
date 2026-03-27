#!/bin/sh
# Returns 0 (vulnerable) if dangerous capabilities are present
cap_eff=$(grep CapEff /proc/self/status | awk '{print $2}')
cap_int=$(printf '%d' "0x$cap_eff" 2>/dev/null || echo 0)

# Check for specific dangerous capabilities by bit position
# CAP_SYS_ADMIN = bit 21, CAP_NET_ADMIN = bit 12, CAP_SYS_PTRACE = bit 19
# CAP_DAC_OVERRIDE = bit 1, CAP_SETUID = bit 7, CAP_SYS_MODULE = bit 16
DANGEROUS=0
FOUND=""

check_cap() {
  local name="$1" bit="$2"
  if [ $(( (cap_int >> bit) & 1 )) -eq 1 ]; then
    FOUND="$FOUND $name"
    DANGEROUS=1
  fi
}

check_cap "CAP_SYS_ADMIN"   21
check_cap "CAP_NET_ADMIN"   12
check_cap "CAP_SYS_PTRACE"  19
check_cap "CAP_SYS_MODULE"  16
check_cap "CAP_SETUID"       7
check_cap "CAP_DAC_OVERRIDE" 1
check_cap "CAP_CHOWN"        0

if [ "$DANGEROUS" -eq 1 ]; then
  echo "Dangerous capabilities found: $FOUND (CapEff: $cap_eff)"
  exit 0
fi
echo "No dangerous capabilities. CapEff: $cap_eff"
exit 1
