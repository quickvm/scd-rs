#!/usr/bin/env bash

set -euo pipefail

exec systemd-run \
  --user \
  --collect \
  --same-dir \
  --quiet \
  -E DISPLAY \
  -E WAYLAND_DISPLAY \
  -E XDG_RUNTIME_DIR \
  -E DBUS_SESSION_BUS_ADDRESS \
  -E XAUTHORITY \
  -p InaccessiblePaths=/run/pcscd \
  /usr/bin/claude-desktop "$@"
