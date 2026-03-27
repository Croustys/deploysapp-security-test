#!/bin/sh
# Check for dangerous /proc paths that could allow host interaction
# Returns 0 (vulnerable) if dangerous paths are writable

DANGEROUS=0
echo "Checking dangerous /proc paths..."

check_path() {
  local path="$1" desc="$2"
  if [ -e "$path" ]; then
    echo "  EXISTS: $path ($desc)"
    if [ -w "$path" ]; then
      echo "  WRITABLE: $path — DANGEROUS"
      DANGEROUS=1
    fi
  fi
}

check_path "/proc/sysrq-trigger"    "can trigger kernel functions"
check_path "/proc/kcore"            "raw kernel memory"
check_path "/proc/kmem"             "kernel memory write"
check_path "/proc/mem"              "process memory"
check_path "/proc/sys/kernel/core_pattern" "can redirect core dumps"

if [ "$DANGEROUS" -eq 1 ]; then
  echo "Dangerous /proc paths are writable"
  exit 0
fi
echo "No writable dangerous /proc paths found"
exit 1
