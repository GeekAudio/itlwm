#!/bin/sh
# Reproduce BusyBox ash's asynchronous-stdin behavior used by the router.
set -eu
if command -v busybox >/dev/null 2>&1; then
  output="$(printf 'ABORT\n' | busybox ash -c 'exec 3<&0; cat <&3 & wait')"
elif command -v ash >/dev/null 2>&1; then
  output="$(printf 'ABORT\n' | ash -c 'exec 3<&0; cat <&3 & wait')"
else
  echo "SKIP_BUSYBOX_ASH_UNAVAILABLE"
  exit 77
fi
[ "$output" = "ABORT" ]
echo "ASH_ASYNC_STDIN_FD3_OK"
