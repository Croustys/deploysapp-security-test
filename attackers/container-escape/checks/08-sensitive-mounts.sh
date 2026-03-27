#!/bin/sh
# Check for sensitive host paths mounted into the container
# Returns 0 (vulnerable) if dangerous mounts found

DANGEROUS=0
echo "Checking for sensitive host mounts..."

check_mount() {
  local path="$1" desc="$2"
  if [ -e "$path" ]; then
    echo "  FOUND: $path ($desc)"
    DANGEROUS=1
  fi
}

# Check /proc/mounts for suspicious bind mounts
if [ -r /proc/mounts ]; then
  echo "Mount points:"
  cat /proc/mounts | grep -v "^overlay\|^proc\|^tmpfs\|^devpts\|^sysfs\|^cgroup\|^mqueue\|^shm" || true
fi

check_mount "/etc/crontab"         "host crontab"
check_mount "/etc/cron.d"          "host cron directory"
check_mount "/root/.ssh"           "host SSH keys"
check_mount "/home"                "host home directories"
check_mount "/etc/shadow"          "host password hashes"
check_mount "/boot"                "host bootloader"
check_mount "/lib/modules"         "kernel modules"

if [ "$DANGEROUS" -eq 1 ]; then
  echo "Sensitive host paths mounted in container"
  exit 0
fi
echo "No sensitive host paths found"
exit 1
