#!/usr/bin/env bash

set -u

interval="${INTERVAL:-10}"
process_pattern="${PROCESS_PATTERN:-pcscd|scdaemon|gpg-agent|opensc|p11-kit|chrome|chromium|firefox|thunderbird|claude|zed|code|electron}"

timestamp() {
  date '+%Y-%m-%d %H:%M:%S %z'
}

log() {
  printf '[%s] %s\n' "$(timestamp)" "$*"
}

run_probe() {
  local output rc
  output="$(gpg --card-status 2>&1)"
  rc=$?

  if (( rc == 0 )); then
    printf 'OK\n'
    printf '%s\n' "$output" | sed -n '/^Reader .*:/p;/^Application ID/p;/^Version/p;/^Manufacturer/p;/^Serial number/p'
  else
    printf 'FAIL rc=%s\n' "$rc"
    printf '%s\n' "$output"
  fi
}

snapshot_processes() {
  ps -ef | grep -E "$process_pattern" | grep -v grep || true
}

snapshot_usb() {
  if command -v lsusb >/dev/null 2>&1; then
    lsusb | grep -i 'nitrokey\|smart\|ccid\|20a0:' || true
  fi
}

snapshot_readers() {
  ls -l ~/.gnupg/reader_*.status 2>/dev/null || true
  for file in ~/.gnupg/reader_*.status; do
    [[ -e "$file" ]] || continue
    printf -- '--- %s ---\n' "$file"
    cat "$file" || true
  done
}

main() {
  local current_state previous_state first_loop details

  log "watcher starting interval=${interval}s pid=$$"
  first_loop=1
  previous_state=""

  while true; do
    details="$(run_probe)"
    current_state="$(printf '%s\n' "$details" | sed -n '1p')"

    if [[ "$first_loop" -eq 1 || "$current_state" != "$previous_state" ]]; then
      log "state=${current_state}"
      printf '%s\n' "$details"

      log "process snapshot:"
      snapshot_processes

      log "usb snapshot:"
      snapshot_usb

      log "reader snapshot:"
      snapshot_readers

      if [[ "$current_state" == FAIL* ]]; then
        log "scdaemon failure detected; try: gpgconf --kill scdaemon"
      fi
    fi

    previous_state="$current_state"
    first_loop=0
    sleep "$interval"
  done
}

main "$@"
