#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/test105.XXXXXX")
trap 'python3 -c '\''import pathlib, shutil, sys; shutil.rmtree(pathlib.Path(sys.argv[1]), ignore_errors=True)'\'' "$BUILD_DIR"' EXIT HUP INT TERM

STRICT_FLAGS="-std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -Werror"
clang $STRICT_FLAGS -g -fsanitize=address,undefined \
  "$ROOT/awdl_directed_responder_test105_core.c" \
  "$ROOT/test_awdl_directed_responder_test105.c" \
  -o "$BUILD_DIR/offline-tests"
"$BUILD_DIR/offline-tests"

clang $STRICT_FLAGS -g \
  "$ROOT/awdl_directed_responder_test105.c" \
  "$ROOT/awdl_directed_responder_test105_core.c" \
  -o "$BUILD_DIR/responder"
PLAN=$("$BUILD_DIR/responder" --peer fe80::2 --local fe80::1 \
  --ifindex 17 --nonce 0102030405060708 --timeout-ms 5000)
printf '%s\n' "$PLAN" | python3 -c '
import json, sys
raw = sys.stdin.read()
obj = json.loads(raw)
assert obj["event"] == "T105_REPLY_READY"
assert obj["status"] == "planned"
assert obj["socket_opened"] is False
assert obj["nonce_serialized"] is False
assert obj["peer_receipt_proven"] is False
assert "fe80::1" not in raw and "fe80::2" not in raw
assert "0102030405060708" not in raw
'
printf '%s\n' 'PASS Test105 production build and dry-run JSON'
