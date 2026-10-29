#!/usr/bin/env python3
"""Bounded, privacy-preserving OpenWrt monitor capture coordinator.

Default mode is read-only preflight. Capture is opt-in, bounded by both a
sleep/SIGINT timer and tcpdump's packet count, and never starts the Intel-side
collector. The READY event is the handoff point for an external coordinator.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Sequence, Tuple


REMOTE_TCPDUMP = "/tmp/iw-awdl-tools/bin/tcpdump"
REMOTE_LIBDIR = "/tmp/iw-awdl-tools/lib"
REMOTE_TMP_PREFIX = "/tmp/iw-awdl-capture-"
MIN_DURATION_SECONDS = 12
MAX_DURATION_SECONDS = 20
DEFAULT_DURATION_SECONDS = 16
DEFAULT_PACKET_LIMIT = 2048
MAX_PACKET_LIMIT = 4096
SNAPLEN_BYTES = 2048
MAX_PCAP_BYTES = 24 + MAX_PACKET_LIMIT * (16 + SNAPLEN_BYTES)
MAX_PROTOCOL_LINE_BYTES = 4096
MAX_BOOTSTRAP_COMMAND_BYTES = 512
LOCAL_SETUP_MARGIN_SECONDS = 16
LOCAL_CLEANUP_MARGIN_SECONDS = 6

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,255}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
               b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
REMOTE_BOOTSTRAP = (
    "IFS= read -r encoded || exit 1; "
    "script=$(printf '%s' \"$encoded\" | base64 -d 2>/dev/null) || exit 1; "
    "eval \"$script\""
)


class CaptureError(RuntimeError):
    """A sanitized, user-facing operation failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ExpectedAP:
    interface: str
    phy: int
    channel: int
    frequency_mhz: int
    width_mhz: int


@dataclass
class ProtocolState:
    preflight: Optional[Dict[str, object]] = None
    ap: Dict[str, Dict[str, Dict[str, int]]] = field(
        default_factory=lambda: {"before": {}, "after": {}}
    )
    uci_sha256: Dict[str, str] = field(default_factory=dict)
    ready_token: Optional[str] = None
    ready_window_seconds: Optional[int] = None
    ready_link_type: Optional[int] = None
    window_remaining_seconds: Optional[int] = None
    result: Optional[Dict[str, object]] = None
    error: Optional[str] = None
    pcap_started: bool = False
    pcap_finished: bool = False
    copy_acknowledged: bool = False
    pcap_bytes_written: int = 0
    pcap_header: bytearray = field(default_factory=bytearray)
    pcap_link_type: Optional[int] = None
    pcap_hash: object = field(default_factory=hashlib.sha256)
    cleanup_report: Optional[Dict[str, object]] = None


def validate_interface(value: str) -> str:
    if not IFACE_RE.fullmatch(value) or value.startswith("-"):
        raise CaptureError("INVALID_INTERFACE")
    return value


def validate_host(value: str) -> str:
    if not HOST_RE.fullmatch(value) or value.startswith("-"):
        raise CaptureError("INVALID_HOST")
    return value


def parse_expected_ap(value: str) -> ExpectedAP:
    pieces = value.split(":")
    if len(pieces) != 5:
        raise CaptureError("INVALID_EXPECTED_AP")
    name = validate_interface(pieces[0])
    try:
        phy, channel, frequency, width = (int(v, 10) for v in pieces[1:])
    except ValueError as exc:
        raise CaptureError("INVALID_EXPECTED_AP") from exc
    if not (0 <= phy <= 31 and 1 <= channel <= 233
            and 2000 <= frequency <= 7125 and 1 <= width <= 320):
        raise CaptureError("INVALID_EXPECTED_AP")
    return ExpectedAP(name, phy, channel, frequency, width)


def validate_capture_limits(duration: int, packets: int) -> None:
    if not MIN_DURATION_SECONDS <= duration <= MAX_DURATION_SECONDS:
        raise CaptureError("DURATION_OUT_OF_RANGE")
    if not 1 <= packets <= MAX_PACKET_LIMIT:
        raise CaptureError("PACKET_LIMIT_OUT_OF_RANGE")
    if 24 + packets * (16 + SNAPLEN_BYTES) > MAX_PCAP_BYTES:
        raise CaptureError("PCAP_BOUND_INVALID")


def shell_quote(value: str) -> str:
    """POSIX single-quote a value for the remote command string."""
    return "'" + value.replace("'", "'\\''") + "'"


def _expected_case(expected: Sequence[ExpectedAP]) -> str:
    if not expected:
        return "EXPECT_REQUIRED=0"
    lines = ["EXPECT_REQUIRED=1", "expected_for() {", "  case \"$1\" in"]
    for item in expected:
        lines.append(
            "    {name}) EXPECT_PHY={phy}; EXPECT_CHANNEL={channel}; "
            "EXPECT_FREQ={freq}; EXPECT_WIDTH={width} ;;".format(
                name=item.interface, phy=item.phy, channel=item.channel,
                freq=item.frequency_mhz, width=item.width_mhz
            )
        )
    lines.extend(("    *) return 1 ;;", "  esac", "}"))
    return "\n".join(lines)


def build_remote_script(
    *,
    ap_interfaces: Sequence[str],
    selected_interface: str,
    monitor_interface: str,
    expected: Sequence[ExpectedAP],
    run_id: str,
    capture: bool,
    duration: int = DEFAULT_DURATION_SECONDS,
    packet_limit: int = DEFAULT_PACKET_LIMIT,
) -> str:
    """Build the remote POSIX-shell body. Inputs are validated before use."""
    if not ap_interfaces or len(set(ap_interfaces)) != len(ap_interfaces):
        raise CaptureError("INVALID_AP_SET")
    aps = [validate_interface(name) for name in ap_interfaces]
    selected_interface = validate_interface(selected_interface)
    monitor_interface = validate_interface(monitor_interface)
    if selected_interface not in aps:
        raise CaptureError("SELECTED_INTERFACE_NOT_IN_AP_SET")
    if not RUN_ID_RE.fullmatch(run_id):
        raise CaptureError("INVALID_RUN_ID")
    if capture:
        validate_capture_limits(duration, packet_limit)
        if {item.interface for item in expected} != set(aps):
            raise CaptureError("CAPTURE_REQUIRES_EXPECTATIONS_FOR_ALL_APS")
    if len({item.interface for item in expected}) != len(expected):
        raise CaptureError("DUPLICATE_EXPECTED_AP")

    ap_list = " ".join(aps)
    expected_case = _expected_case(expected)
    capture_value = "1" if capture else "0"
    shell = r'''#!/bin/sh
LC_ALL=C
export LC_ALL
umask 077
CAPTURE=__CAPTURE__
AP_LIST="__AP_LIST__"
SELECTED="__SELECTED__"
MON="__MONITOR__"
RUN_ID="__RUN_ID__"
DURATION=__DURATION__
PACKET_LIMIT=__PACKETS__
SNAPLEN=2048
SYS_CLASS_NET="/sys/class/net"
TCPDUMP="/tmp/iw-awdl-tools/bin/tcpdump"
LIBDIR="/tmp/iw-awdl-tools/lib"
TMP="/tmp/iw-awdl-capture-$RUN_ID"
TMP_CREATED=0
WATCHDOG_PID=""
WATCHDOG_FLAG=""
MAIN_PID=$$
MON_CREATED=0
MON_IFINDEX=""
MON_REMOVED=0
MON_CLEANUP_UNKNOWN=0
CAP_PID=""
CAP_START=""
TIMER_PID=""
TIMER_START=""
CONTROL_PID=""
CONTROL_START=""
RUN_FLAG=""
EXIT_CODE=0

fail() {
  printf 'ERROR\t%s\n' "$1"
  exit 2
}

ifindex_for() {
  if [ -r "$SYS_CLASS_NET/$1/ifindex" ]; then
    cat "$SYS_CLASS_NET/$1/ifindex" 2>/dev/null
  else
    iw dev "$1" info 2>/dev/null | awk '$1 == "ifindex" { print $2; exit }'
  fi
}

proc_start_time() {
  statline=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  rest=${statline##*) }
  set -- $rest
  [ "$#" -ge 20 ] || return 1
  printf '%s' "${20}"
}

signal_owned_pid() {
  pid="$1"
  expected_start="$2"
  sig="$3"
  case "$pid:$expected_start" in *[!0-9:]*) return 1 ;; esac
  [ -n "$pid" ] && [ -n "$expected_start" ] || return 1
  current_start=$(proc_start_time "$pid" 2>/dev/null || true)
  [ -n "$current_start" ] && [ "$current_start" = "$expected_start" ] || return 1
  kill -"$sig" "$pid" 2>/dev/null
}

write_pid_ticket() {
  pid="$1"
  path="$2"
  start=$(proc_start_time "$pid" 2>/dev/null || true)
  case "$pid:$start" in *[!0-9:]*) return 1 ;; esac
  [ -n "$pid" ] && [ -n "$start" ] || return 1
  printf '%s %s\n' "$pid" "$start" > "$path"
}

signal_pid_ticket() {
  path="$1"
  sig="$2"
  [ -r "$path" ] || return 1
  IFS=' ' read ticket_pid ticket_start < "$path" || return 1
  case "$ticket_pid:$ticket_start" in *[!0-9:]*) return 1 ;; esac
  signal_owned_pid "$ticket_pid" "$ticket_start" "$sig"
}

snapshot_ap() {
  ap="$1"
  info=$(iw dev "$ap" info 2>/dev/null) || return 1
  row=$(printf '%s\n' "$info" | awk '
    $1 == "ifindex" { idx=$2 }
    $1 == "wiphy" { phy=$2 }
    $1 == "type" {
      if ($2 == "AP") mode=1
      else if ($2 == "monitor") mode=2
      else if ($2 == "managed") mode=3
      else if ($2 == "adhoc") mode=4
      else if ($2 == "mesh" || $2 == "mesh-point") mode=5
      else mode=0
    }
    $1 == "channel" {
      channel=$2
      freq=$3
      gsub(/[^0-9]/, "", freq)
      for (i=1; i<NF; i++) {
        if ($i == "width:") {
          width=$(i+1)
          gsub(/[^0-9]/, "", width)
        }
      }
    }
    END {
      if (idx ~ /^[0-9]+$/ && phy ~ /^[0-9]+$/ && mode == 1 &&
          channel ~ /^[0-9]+$/ && freq ~ /^[0-9]+$/ && width ~ /^[0-9]+$/)
        printf "%s\t%s\t%s\t%s\t%s\t%s", idx, phy, mode,
          channel, freq, width
      else exit 1
    }') || return 1
  oldifs=$IFS
  IFS=$(printf '\t')
  set -- $row
  IFS=$oldifs
  [ "$#" -eq 6 ] || return 1
  printf 'AP\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$PHASE" "$ap" "$1" "$2" "$3" "$4" "$5" "$6"
  if [ "$EXPECT_REQUIRED" -eq 1 ]; then
    expected_for "$ap" || return 1
    [ "$2" = "$EXPECT_PHY" ] && [ "$4" = "$EXPECT_CHANNEL" ] &&
      [ "$5" = "$EXPECT_FREQ" ] && [ "$6" = "$EXPECT_WIDTH" ] || return 2
  fi
}

uci_hash() {
  uci_dump=$(uci export wireless 2>/dev/null) || return 1
  [ -n "$uci_dump" ] || return 1
  hash=$(printf '%s' "$uci_dump" | sha256sum 2>/dev/null | awk '{print $1}')
  case "$hash" in
    [0-9a-f][0-9a-f]*) [ "${#hash}" -eq 64 ] || return 1 ;;
    *) return 1 ;;
  esac
  printf 'UCI\t%s\t%s\n' "$PHASE" "$hash"
}

emit_snapshot() {
  PHASE="$1"
  for ap in $AP_LIST; do
    snapshot_ap "$ap"
    rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
  done
  uci_hash || return 3
}

monitor_supported() {
  phy="$1"
  iw phy "phy$phy" info 2>/dev/null | awk '
    /Supported interface modes:/ { in_modes=1; next }
    in_modes && $1 == "*" && $2 == "monitor" { found=1 }
    in_modes && NF > 0 && $1 != "*" && $1 !~ /^Supported/ { in_modes=0 }
    END { print found ? 1 : 0 }'
}

monitor_available() {
  [ -r "$SYS_CLASS_NET" ] || return 2
  [ ! -d "$SYS_CLASS_NET/$MON" ]
}

write_cleanup_report() {
  saved="$1"
  observed="$2"
  removed="$3"
  announce="$4"
  case "$saved" in ''|*[!0-9]*) saved=0 ;; esac
  case "$observed" in ''|*[!0-9]*) observed=0 ;; esac
  case "$removed" in 0|1) ;; *) removed=0 ;; esac
  report="/tmp/iw-awdl-cleanup-$RUN_ID.status"
  if [ ! -e "$report" ]; then
    (umask 077; set -C; printf 'run_id=%s\nmonitor_ifindex_expected=%s\nmonitor_ifindex_observed=%s\nmonitor_removed=%s\n' \
      "$RUN_ID" "$saved" "$observed" "$removed" > "$report") 2>/dev/null || true
  fi
  if [ "$announce" = 1 ]; then
    printf 'CLEANUP_REPORT\t%s\t%s\t%s\t%s\n' \
      "$RUN_ID" "$saved" "$observed" "$removed" 2>/dev/null || true
  fi
}

stop_capture() {
  if [ -n "$CAP_PID" ]; then
    if [ "$TMP_CREATED" -eq 1 ]; then : > "$TMP/capture-live"; fi
    if [ -n "$CAP_START" ]; then
      signal_owned_pid "$CAP_PID" "$CAP_START" INT || true
    else
      # The unreaped direct child remains ours even if /proc is unavailable.
      kill -INT "$CAP_PID" 2>/dev/null || true
    fi
    FORCE_PID=""
    if [ "$TMP_CREATED" -eq 1 ]; then
      (
        left=4
        while [ "$left" -gt 0 ] && [ -f "$TMP/capture-live" ]; do
          sleep 1
          left=$((left - 1))
        done
        if [ -f "$TMP/capture-live" ]; then
          if [ -n "$CAP_START" ]; then signal_owned_pid "$CAP_PID" "$CAP_START" TERM || true
          else kill -TERM "$CAP_PID" 2>/dev/null || true; fi
        fi
        sleep 1
        if [ -f "$TMP/capture-live" ]; then
          if [ -n "$CAP_START" ]; then signal_owned_pid "$CAP_PID" "$CAP_START" KILL || true
          else kill -KILL "$CAP_PID" 2>/dev/null || true; fi
        fi
      ) &
      FORCE_PID=$!
    fi
    wait "$CAP_PID" 2>/dev/null || true
    [ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/capture.pid" 2>/dev/null || true
    CAP_PID=""
    CAP_START=""
    [ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/capture-live" 2>/dev/null || true
    if [ -n "$FORCE_PID" ]; then wait "$FORCE_PID" 2>/dev/null || true; fi
  fi
}

remove_monitor() {
  [ "$MON_CREATED" -eq 1 ] || return 0
  current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
  case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
  case "$MON_IFINDEX" in *[!0-9]*) MON_IFINDEX="" ;; esac
  if [ -n "$MON_IFINDEX" ] && [ "$current_ifindex" = "$MON_IFINDEX" ]; then
    ip link set dev "$MON" down >/dev/null 2>&1 || true
    current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
    case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
    if [ "$current_ifindex" = "$MON_IFINDEX" ]; then
      iw dev "$MON" del >/dev/null 2>&1 || true
    else
      MON_CLEANUP_UNKNOWN=1
      MON_REMOVED=0
      return 1
    fi
    current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
    case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
    if [ -z "$current_ifindex" ] && monitor_available; then
      MON_CREATED=0
      MON_REMOVED=1
      MON_CLEANUP_UNKNOWN=0
      return 0
    fi
    MON_CLEANUP_UNKNOWN=1
    MON_REMOVED=0
    return 1
  elif [ -z "$current_ifindex" ] && monitor_available; then
    MON_CREATED=0
    MON_REMOVED=1
    MON_CLEANUP_UNKNOWN=0
    return 0
  fi
  MON_CLEANUP_UNKNOWN=1
  MON_REMOVED=0
  return 1
}

cleanup() {
  trap - EXIT INT TERM HUP
  [ -n "$RUN_FLAG" ] && rm -f "$RUN_FLAG" 2>/dev/null || true
  stop_capture
  if [ -n "$CONTROL_PID" ]; then
    signal_owned_pid "$CONTROL_PID" "$CONTROL_START" TERM || true
    wait "$CONTROL_PID" 2>/dev/null || true
    CONTROL_PID=""
    CONTROL_START=""
    exec 3<&- 2>/dev/null || true
  fi
  if [ -n "$TIMER_PID" ]; then
    signal_owned_pid "$TIMER_PID" "$TIMER_START" TERM || true
    wait "$TIMER_PID" 2>/dev/null || true
    TIMER_PID=""
    TIMER_START=""
    [ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/timer.pid" 2>/dev/null || true
  fi
  remove_monitor || true
  if [ "$MON_CLEANUP_UNKNOWN" -eq 1 ]; then
    observed=$(ifindex_for "$MON" 2>/dev/null || true)
    write_cleanup_report "$MON_IFINDEX" "$observed" 0 1
  fi
  if [ "$TMP_CREATED" -eq 1 ]; then
    rm -rf "$TMP"
    TMP_CREATED=0
  fi
  if [ -n "$WATCHDOG_PID" ]; then
    wait "$WATCHDOG_PID" 2>/dev/null || true
    WATCHDOG_PID=""
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [ ! -x "$TCPDUMP" ]; then fail TOOL_UNAVAILABLE; fi
export LD_LIBRARY_PATH="$LIBDIR"
TCPDUMP_VERSION=$("$TCPDUMP" --version 2>/dev/null | awk '/^tcpdump version / {print $3; exit}')
LIBPCAP_VERSION=$("$TCPDUMP" --version 2>/dev/null | awk '/^libpcap version / {print $3; exit}')
case "$TCPDUMP_VERSION" in [0-9]*.[0-9]*.[0-9]*|[0-9]*.[0-9]*) ;; *) fail TOOL_UNAVAILABLE ;; esac
case "$LIBPCAP_VERSION" in [0-9]*.[0-9]*.[0-9]*|[0-9]*.[0-9]*) ;; *) fail TOOL_UNAVAILABLE ;; esac

__EXPECTED_CASE__
PHASE=before
emit_snapshot before
snapshot_rc=$?
[ "$snapshot_rc" -eq 0 ] || {
  [ "$snapshot_rc" -eq 2 ] && fail STATE_MISMATCH
  [ "$snapshot_rc" -eq 3 ] && fail UCI_EXPORT_UNAVAILABLE
  fail AP_STATE_UNAVAILABLE
}

SELECTED_INFO=$(iw dev "$SELECTED" info 2>/dev/null) || fail SELECTED_INTERFACE_UNAVAILABLE
SELECTED_PHY=$(printf '%s\n' "$SELECTED_INFO" | awk '$1 == "wiphy" {print $2; exit}')
case "$SELECTED_PHY" in ''|*[!0-9]*) fail SELECTED_PHY_UNAVAILABLE ;; esac
MONITOR_SUPPORTED=$(monitor_supported "$SELECTED_PHY")
case "$MONITOR_SUPPORTED" in 0|1) ;; *) fail MONITOR_CAPABILITY_UNKNOWN ;; esac
monitor_available
monitor_state=$?
case "$monitor_state" in
  0) MONITOR_AVAILABLE=1 ;;
  1) MONITOR_AVAILABLE=0 ;;
  *) fail MONITOR_STATE_UNKNOWN ;;
esac
printf 'PREFLIGHT\t%s\t%s\t%s\t%s\n' \
  "$TCPDUMP_VERSION" "$LIBPCAP_VERSION" \
  "$MONITOR_SUPPORTED" "$MONITOR_AVAILABLE"

if [ "$CAPTURE" -eq 0 ]; then exit 0; fi
if [ "$MONITOR_SUPPORTED" -ne 1 ]; then fail MONITOR_UNSUPPORTED; fi
if [ "$MONITOR_AVAILABLE" -ne 1 ]; then fail MONITOR_EXISTS; fi
if [ -e "$TMP" ]; then fail TEMP_PATH_EXISTS; fi
mkdir -m 700 "$TMP" 2>/dev/null || fail TEMP_CREATE_FAILED
TMP_CREATED=1
WATCHDOG_FLAG="$TMP/session-live"
: > "$WATCHDOG_FLAG"
MAIN_START=$(proc_start_time "$MAIN_PID" 2>/dev/null || true)
(
  left=40
  while [ "$left" -gt 0 ] && [ -f "$WATCHDOG_FLAG" ]; do
    sleep 1
    left=$((left - 1))
  done
  if [ ! -f "$WATCHDOG_FLAG" ]; then exit 0; fi
  current_start=$(proc_start_time "$MAIN_PID" 2>/dev/null || true)
  if [ -n "$MAIN_START" ] && [ "$current_start" = "$MAIN_START" ]; then
    kill -TERM "$MAIN_PID" 2>/dev/null || true
  fi
  left=5
  while [ "$left" -gt 0 ] && [ -f "$WATCHDOG_FLAG" ]; do
    sleep 1
    left=$((left - 1))
  done
  if [ ! -f "$WATCHDOG_FLAG" ]; then exit 0; fi
  if signal_pid_ticket "$TMP/capture.pid" INT; then
    sleep 2
    signal_pid_ticket "$TMP/capture.pid" TERM || true
    sleep 1
    signal_pid_ticket "$TMP/capture.pid" KILL || true
  fi
  for pidfile in "$TMP/control.pid" "$TMP/timer.pid"; do
    signal_pid_ticket "$pidfile" TERM || true
  done
  saved_ifindex=$(cat "$TMP/monitor.ifindex" 2>/dev/null || true)
  current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
  case "$saved_ifindex" in ''|*[!0-9]*) saved_ifindex="" ;; esac
  case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
  removed=0
  add_started=0
  [ -f "$TMP/monitor-add-started" ] && add_started=1
  if [ "$add_started" -eq 1 ] && [ -n "$saved_ifindex" ] &&
      [ "$current_ifindex" = "$saved_ifindex" ]; then
    ip link set dev "$MON" down >/dev/null 2>&1 || true
    current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
    case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
    if [ "$current_ifindex" = "$saved_ifindex" ]; then
      iw dev "$MON" del >/dev/null 2>&1 || true
      current_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
      case "$current_ifindex" in *[!0-9]*) current_ifindex="" ;; esac
      if [ -z "$current_ifindex" ] && monitor_available; then removed=1; fi
    fi
  elif [ "$add_started" -eq 1 ] && [ -z "$current_ifindex" ] && monitor_available; then
    removed=1
  fi
  if [ "$add_started" -eq 1 ]; then
    write_cleanup_report "$saved_ifindex" "$current_ifindex" "$removed" 0
  fi
  current_start=$(proc_start_time "$MAIN_PID" 2>/dev/null || true)
  if [ -n "$MAIN_START" ] && [ "$current_start" = "$MAIN_START" ]; then
    kill -KILL "$MAIN_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
) &
WATCHDOG_PID=$!
PCAP="$TMP/capture.pcap"
ERR="$TMP/tcpdump.stderr"
RUN_FLAG="$TMP/capture-running"

# Record that this run entered the add operation. The watchdog still requires
# a matching ifindex ticket before it may delete anything.
: > "$TMP/monitor-add-started"
if ! iw phy "phy$SELECTED_PHY" interface add "$MON" type monitor flags otherbss \
    >/dev/null 2>&1; then
  possible_ifindex=$(ifindex_for "$MON" 2>/dev/null || true)
  case "$possible_ifindex" in ''|*[!0-9]*) fail MONITOR_CREATE_FAILED ;; esac
  MON_CREATED=1
  MON_IFINDEX=""
  fail MONITOR_CREATE_UNCONFIRMED
fi
MON_CREATED=1
MON_IFINDEX=$(ifindex_for "$MON" 2>/dev/null || true)
case "$MON_IFINDEX" in ''|*[!0-9]*) fail MONITOR_ID_UNAVAILABLE ;; esac
printf '%s\n' "$MON_IFINDEX" > "$TMP/monitor.ifindex"
ip link set dev "$MON" up >/dev/null 2>&1 || fail MONITOR_UP_FAILED

"$TCPDUMP" -nn -p -i "$MON" -s "$SNAPLEN" -c "$PACKET_LIMIT" -U \
  -w "$PCAP" 2>"$ERR" &
CAP_PID=$!
CAP_START=$(proc_start_time "$CAP_PID" 2>/dev/null || true)
write_pid_ticket "$CAP_PID" "$TMP/capture.pid" || fail CAPTURE_PID_UNVERIFIED
ready=0
attempt=0
while [ "$attempt" -lt 5 ]; do
  linktype_name=$(awk 'index($0, "listening on ") && index($0, "link-type ") {
    for (i=1; i<NF; i++) if ($i == "link-type") {
      value=$(i+1); gsub(/[^A-Za-z0-9_]/, "", value); print value; exit
    }
  }' "$ERR" 2>/dev/null)
  case "$linktype_name" in
    IEEE802_11_RADIO) LINKTYPE_NUM=127 ;;
    IEEE802_11) LINKTYPE_NUM=105 ;;
    *) LINKTYPE_NUM=0 ;;
  esac
  if [ -f "$PCAP" ]; then
    pcap_size=$(wc -c < "$PCAP" 2>/dev/null | tr -d ' ')
    case "$pcap_size" in ''|*[!0-9]*) pcap_size=0 ;; esac
    if [ "$pcap_size" -ge 24 ] && [ "$LINKTYPE_NUM" -ne 0 ] && kill -0 "$CAP_PID" 2>/dev/null; then
      ready=1
      break
    fi
  fi
  if ! kill -0 "$CAP_PID" 2>/dev/null; then break; fi
  sleep 1
  attempt=$((attempt + 1))
done
[ "$ready" -eq 1 ] || fail TCPDUMP_START_FAILED

: > "$RUN_FLAG"
exec 3<&0
(
  while IFS= read -r control <&3; do
    if [ "$control" = "CANCEL" ]; then
      : > "$TMP/cancelled"
      signal_pid_ticket "$TMP/capture.pid" INT || true
      exit 0
    fi
  done
  if kill -0 "$CAP_PID" 2>/dev/null; then
    : > "$TMP/cancelled"
    signal_pid_ticket "$TMP/capture.pid" INT || true
  fi
) &
CONTROL_PID=$!
CONTROL_START=$(proc_start_time "$CONTROL_PID" 2>/dev/null || true)
write_pid_ticket "$CONTROL_PID" "$TMP/control.pid" || fail CONTROL_PID_UNVERIFIED
printf 'READY\t%s\t%s\t%s\n' "$RUN_ID" "$DURATION" "$LINKTYPE_NUM"
(
  left="$DURATION"
  while [ "$left" -gt 0 ]; do
    [ -f "$RUN_FLAG" ] || exit 0
    kill -0 "$CAP_PID" 2>/dev/null || exit 0
    printf 'WINDOW\t%s\t%s\n' "$RUN_ID" "$left"
    sleep 1
    left=$((left - 1))
  done
  if [ -f "$RUN_FLAG" ] && kill -0 "$CAP_PID" 2>/dev/null; then
    signal_pid_ticket "$TMP/capture.pid" INT || true
  fi
) &
TIMER_PID=$!
TIMER_START=$(proc_start_time "$TIMER_PID" 2>/dev/null || true)
write_pid_ticket "$TIMER_PID" "$TMP/timer.pid" || fail TIMER_PID_UNVERIFIED

wait "$CAP_PID"
CAPTURE_EXIT=$?
[ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/capture.pid" 2>/dev/null || true
CAP_PID=""
CAP_START=""
rm -f "$RUN_FLAG"
if [ -n "$CONTROL_PID" ]; then
  signal_owned_pid "$CONTROL_PID" "$CONTROL_START" TERM || true
  wait "$CONTROL_PID" 2>/dev/null || true
  CONTROL_PID=""
  CONTROL_START=""
  [ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/control.pid" 2>/dev/null || true
  exec 3<&- 2>/dev/null || true
fi
if [ -n "$TIMER_PID" ]; then
  signal_owned_pid "$TIMER_PID" "$TIMER_START" TERM || true
  wait "$TIMER_PID" 2>/dev/null || true
  TIMER_PID=""
  TIMER_START=""
  [ "$TMP_CREATED" -eq 1 ] && rm -f "$TMP/timer.pid" 2>/dev/null || true
fi

captured=$(awk '$2 == "packets" && $3 == "captured" && $1 ~ /^[0-9]+$/ {v=$1} END {if(v=="") print -1; else print v}' "$ERR")
received=$(awk '$2 == "packets" && $3 == "received" && $4 == "by" && $5 == "filter" && $1 ~ /^[0-9]+$/ {v=$1} END {if(v=="") print -1; else print v}' "$ERR")
dropped=$(awk '$2 == "packets" && $3 == "dropped" && $4 == "by" && $5 == "kernel" && $1 ~ /^[0-9]+$/ {v=$1} END {if(v=="") print -1; else print v}' "$ERR")
pcap_bytes=$(wc -c < "$PCAP" 2>/dev/null | tr -d ' ')
case "$pcap_bytes" in ''|*[!0-9]*) fail PCAP_READ_FAILED ;; esac
[ "$pcap_bytes" -ge 24 ] && [ "$pcap_bytes" -le __MAX_PCAP_BYTES__ ] || fail PCAP_SIZE_INVALID
pcap_sha=$(sha256sum "$PCAP" 2>/dev/null | awk '{print $1}')
case "$pcap_sha" in
  [0-9a-f][0-9a-f]*) [ "${#pcap_sha}" -eq 64 ] || fail PCAP_HASH_FAILED ;;
  *) fail PCAP_HASH_FAILED ;;
esac

remove_monitor || fail MONITOR_CLEANUP_UNCONFIRMED
PHASE=after
emit_snapshot after
snapshot_rc=$?
[ "$snapshot_rc" -eq 0 ] || {
  [ "$snapshot_rc" -eq 3 ] && fail POST_CAPTURE_UCI_EXPORT_UNAVAILABLE
  fail POST_CAPTURE_STATE_UNAVAILABLE
}

cancelled=0
[ -f "$TMP/cancelled" ] && cancelled=1
printf 'RESULT\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$CAPTURE_EXIT" "$captured" "$received" "$dropped" \
  "$pcap_bytes" "$pcap_sha" "$cancelled" "$MON_REMOVED"
printf 'PCAP-BEGIN\n'
cat "$PCAP"
if ! IFS= read -r copy_ack; then fail COPY_UNVERIFIED; fi
case "$copy_ack" in
  "VERIFY $pcap_sha") printf 'ACK\tOK\n' ;;
  *) fail COPY_HASH_MISMATCH ;;
esac
exit 0
'''
    replacements = {
        "__CAPTURE__": capture_value,
        "__AP_LIST__": ap_list,
        "__SELECTED__": selected_interface,
        "__MONITOR__": monitor_interface,
        "__RUN_ID__": run_id,
        "__DURATION__": str(duration),
        "__PACKETS__": str(packet_limit),
        "__MAX_PCAP_BYTES__": str(MAX_PCAP_BYTES),
        "__EXPECTED_CASE__": expected_case,
    }
    for marker, value in replacements.items():
        shell = shell.replace(marker, value)
    return shell


def build_ssh_argv(host: str, control_path: str) -> List[str]:
    validate_host(host)
    if not os.path.isabs(control_path) or "\n" in control_path:
        raise CaptureError("INVALID_CONTROL_PATH")
    # Send source on SSH stdin after the short exec request has started. Long
    # scripts exceed Dropbear/OpenSSH exec-command limits when shell-quoted.
    remote_command = "sh -c " + shell_quote(REMOTE_BOOTSTRAP)
    if len(remote_command.encode("utf-8")) > MAX_BOOTSTRAP_COMMAND_BYTES:
        raise CaptureError("BOOTSTRAP_COMMAND_TOO_LONG")
    return [
        "ssh", "-T", "-S", control_path,
        "-o", "ControlMaster=no",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ProxyCommand=/usr/bin/false",
        "-o", "ConnectTimeout=5",
        host, remote_command,
    ]


def validate_control_socket(path: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise CaptureError("CONTROL_SOCKET_UNAVAILABLE") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise CaptureError("CONTROL_SOCKET_UNAVAILABLE")


def parse_numeric_fields(fields: Sequence[str], count: int) -> List[int]:
    if len(fields) != count:
        raise CaptureError("PROTOCOL_ERROR")
    try:
        return [int(value, 10) for value in fields]
    except ValueError as exc:
        raise CaptureError("PROTOCOL_ERROR") from exc


def handle_protocol_line(state: ProtocolState, raw_line: bytes,
                         capture: bool,
                         on_ready: Optional[Callable[[str, int, int], None]] = None) -> None:
    try:
        line = raw_line.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CaptureError("PROTOCOL_ERROR") from exc
    parts = line.split("\t")
    kind = parts[0]
    if kind == "ERROR" and len(parts) == 2 and re.fullmatch(r"[A-Z_]{1,48}", parts[1]):
        state.error = parts[1]
        return
    if kind == "CLEANUP_REPORT" and len(parts) == 5 and RUN_ID_RE.fullmatch(parts[1]):
        numbers = parse_numeric_fields(parts[2:], 3)
        expected_ifindex, observed_ifindex, removed = numbers
        if min(expected_ifindex, observed_ifindex, removed) < 0 or removed not in (0, 1):
            raise CaptureError("PROTOCOL_ERROR")
        state.cleanup_report = {
            "expected_ifindex": expected_ifindex,
            "observed_ifindex": observed_ifindex,
            "monitor_removed": bool(removed),
        }
        print("CLEANUP_REPORT run_id=" + parts[1] +
              " expected_ifindex=" + str(expected_ifindex) +
              " observed_ifindex=" + str(observed_ifindex) +
              " monitor_removed=" + str(removed), flush=True)
        return
    if kind == "PREFLIGHT" and len(parts) == 5:
        if not VERSION_RE.fullmatch(parts[1]) or not VERSION_RE.fullmatch(parts[2]):
            raise CaptureError("PROTOCOL_ERROR")
        if parts[3] not in ("0", "1") or parts[4] not in ("0", "1"):
            raise CaptureError("PROTOCOL_ERROR")
        state.preflight = {
            "tcpdump_version": parts[1],
            "libpcap_version": parts[2],
            "monitor_supported": parts[3] == "1",
            "monitor_name_available": parts[4] == "1",
        }
        return
    if kind == "AP" and len(parts) == 9 and parts[1] in ("before", "after"):
        name = validate_interface(parts[2])
        if name in state.ap[parts[1]]:
            raise CaptureError("PROTOCOL_ERROR")
        numbers = parse_numeric_fields(parts[3:], 6)
        idx, phy, mode, channel, frequency, width = numbers
        if idx <= 0 or phy < 0 or mode != 1 or min(channel, frequency, width) <= 0:
            raise CaptureError("PROTOCOL_ERROR")
        state.ap[parts[1]][name] = {
            "ifindex": idx,
            "phy": phy,
            "type_code": mode,
            "channel": channel,
            "frequency_mhz": frequency,
            "width_mhz": width,
        }
        return
    if kind == "UCI" and len(parts) == 3 and parts[1] in ("before", "after"):
        if not SHA_RE.fullmatch(parts[2]) or parts[1] in state.uci_sha256:
            raise CaptureError("PROTOCOL_ERROR")
        state.uci_sha256[parts[1]] = parts[2]
        return
    if kind == "READY" and len(parts) == 4 and RUN_ID_RE.fullmatch(parts[1]):
        if not capture or state.ready_token is not None:
            raise CaptureError("PROTOCOL_ERROR")
        try:
            window = int(parts[2], 10)
            link_type = int(parts[3], 10)
        except ValueError as exc:
            raise CaptureError("PROTOCOL_ERROR") from exc
        if (not MIN_DURATION_SECONDS <= window <= MAX_DURATION_SECONDS
                or link_type not in (105, 127)):
            raise CaptureError("PROTOCOL_ERROR")
        state.ready_token = parts[1]
        state.ready_window_seconds = window
        state.ready_link_type = link_type
        if on_ready:
            on_ready(parts[1], window, link_type)
        return
    if kind == "WINDOW" and len(parts) == 3 and RUN_ID_RE.fullmatch(parts[1]):
        if not capture or state.ready_token != parts[1]:
            raise CaptureError("PROTOCOL_ERROR")
        try:
            remaining = int(parts[2], 10)
        except ValueError as exc:
            raise CaptureError("PROTOCOL_ERROR") from exc
        if not 0 <= remaining <= (state.ready_window_seconds or 0):
            raise CaptureError("PROTOCOL_ERROR")
        previous = state.window_remaining_seconds
        if previous is not None and remaining > previous:
            raise CaptureError("PROTOCOL_ERROR")
        state.window_remaining_seconds = remaining
        print("WINDOW " + parts[1] + " remaining_seconds=" + str(remaining),
              flush=True)
        return
    if kind == "RESULT" and len(parts) == 9:
        if not capture or state.result is not None:
            raise CaptureError("PROTOCOL_ERROR")
        exit_code, captured, received, dropped, byte_count = parse_numeric_fields(parts[1:6], 5)
        if parts[7] not in ("0", "1") or parts[8] not in ("0", "1") \
                or not SHA_RE.fullmatch(parts[6]):
            raise CaptureError("PROTOCOL_ERROR")
        if not (0 <= exit_code <= 255 and 24 <= byte_count <= MAX_PCAP_BYTES):
            raise CaptureError("PROTOCOL_ERROR")
        def optional_count(value: int) -> Optional[int]:
            if value == -1:
                return None
            if value < 0:
                raise CaptureError("PROTOCOL_ERROR")
            return value
        state.result = {
            "tcpdump_exit_code": exit_code,
            "packets_captured": optional_count(captured),
            "packets_received_by_filter": optional_count(received),
            "packets_dropped_by_kernel": optional_count(dropped),
            "pcap_bytes_remote": byte_count,
            "pcap_sha256_remote": parts[6],
            "cancelled": parts[7] == "1",
            "monitor_removed": parts[8] == "1",
        }
        return
    if kind == "PCAP-BEGIN" and len(parts) == 1:
        if not capture or state.result is None or state.pcap_started:
            raise CaptureError("PROTOCOL_ERROR")
        state.pcap_started = True
        return
    if kind == "ACK" and parts == ["ACK", "OK"]:
        if not capture or not state.pcap_finished or state.copy_acknowledged:
            raise CaptureError("PROTOCOL_ERROR")
        state.copy_acknowledged = True
        return
    raise CaptureError("PROTOCOL_ERROR")


class ProtocolConsumer:
    """Parse text events, then stream opaque PCAP bytes directly to disk."""

    def __init__(self, capture: bool, output_file: Optional[BinaryIO],
                 on_ready: Optional[Callable[[str, int, int], None]] = None,
                 on_pcap_complete: Optional[Callable[[str], None]] = None):
        self.capture = capture
        self.output_file = output_file
        self.on_ready = on_ready
        self.on_pcap_complete = on_pcap_complete
        self.state = ProtocolState()
        self.buffer = bytearray()
        self.finished = False

    def _write_pcap(self, data: bytes) -> None:
        if not data:
            return
        if self.output_file is None or not self.state.pcap_started:
            raise CaptureError("PROTOCOL_ERROR")
        new_total = self.state.pcap_bytes_written + len(data)
        if new_total > MAX_PCAP_BYTES:
            raise CaptureError("PCAP_SIZE_LIMIT_EXCEEDED")
        if len(self.state.pcap_header) < 24:
            needed = 24 - len(self.state.pcap_header)
            self.state.pcap_header.extend(data[:needed])
        view = memoryview(data)
        while view:
            written = self.output_file.write(view)
            if written is None or written <= 0:
                raise CaptureError("PCAP_WRITE_FAILED")
            view = view[written:]
        self.state.pcap_hash.update(data)
        self.state.pcap_bytes_written = new_total

    def feed(self, data: bytes) -> None:
        if self.finished:
            raise CaptureError("PROTOCOL_ERROR")
        pending = data
        while pending:
            if self.state.pcap_started and not self.state.pcap_finished:
                assert self.state.result is not None
                target = int(self.state.result["pcap_bytes_remote"])
                remaining = target - self.state.pcap_bytes_written
                if remaining <= 0:
                    raise CaptureError("PROTOCOL_ERROR")
                take = min(remaining, len(pending))
                self._write_pcap(pending[:take])
                pending = pending[take:]
                if self.state.pcap_bytes_written == target:
                    header = bytes(self.state.pcap_header)
                    if len(header) != 24 or header[:4] not in PCAP_MAGICS:
                        raise CaptureError("PCAP_HEADER_INVALID")
                    little = header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
                    link_type = int.from_bytes(header[20:24], "little" if little else "big")
                    if link_type not in (105, 127) or link_type != self.state.ready_link_type:
                        raise CaptureError("PCAP_LINK_TYPE_MISMATCH")
                    self.state.pcap_link_type = link_type
                    actual_sha = self.state.pcap_hash.hexdigest()
                    if actual_sha != self.state.result["pcap_sha256_remote"]:
                        raise CaptureError("PCAP_HASH_MISMATCH")
                    self.state.pcap_finished = True
                    if self.on_pcap_complete:
                        self.on_pcap_complete(actual_sha)
                continue

            self.buffer.extend(pending)
            pending = b""
            while b"\n" in self.buffer:
                line, _, rest = self.buffer.partition(b"\n")
                self.buffer = bytearray(rest)
                if len(line) > MAX_PROTOCOL_LINE_BYTES:
                    raise CaptureError("PROTOCOL_ERROR")
                if line == b"PCAP-BEGIN":
                    handle_protocol_line(self.state, line, self.capture,
                                         self.on_ready)
                    break
                handle_protocol_line(self.state, line, self.capture,
                                     self.on_ready)
            else:
                if len(self.buffer) > MAX_PROTOCOL_LINE_BYTES:
                    raise CaptureError("PROTOCOL_ERROR")
                continue
            # PCAP-BEGIN may share a read with the first raw packet bytes.
            pending = bytes(self.buffer)
            self.buffer.clear()

    def finish(self) -> ProtocolState:
        if self.buffer:
            raise CaptureError("PROTOCOL_ERROR")
        self.finished = True
        if self.state.error:
            raise CaptureError(self.state.error)
        if self.capture and not (self.state.pcap_started
                                 and self.state.pcap_finished
                                 and self.state.copy_acknowledged):
            raise CaptureError("CAPTURE_STREAM_INCOMPLETE")
        if not self.capture and self.state.pcap_started:
            raise CaptureError("PROTOCOL_ERROR")
        return self.state


def expected_matches(state: ProtocolState, expected: Sequence[ExpectedAP]) -> bool:
    if not expected:
        return True
    before = state.ap["before"]
    if {item.interface for item in expected} != set(before):
        return False
    for item in expected:
        observed = before.get(item.interface)
        if not observed:
            return False
        if (observed["phy"], observed["channel"], observed["frequency_mhz"],
                observed["width_mhz"]) != (
                item.phy, item.channel, item.frequency_mhz, item.width_mhz):
            return False
    return True


def state_unchanged(state: ProtocolState, ap_interfaces: Sequence[str]) -> bool:
    if set(state.ap["before"]) != set(ap_interfaces):
        return False
    if set(state.ap["after"]) != set(ap_interfaces):
        return False
    if state.uci_sha256.get("before") is None or state.uci_sha256.get("after") is None:
        return False
    return (state.ap["before"] == state.ap["after"]
            and state.uci_sha256["before"] == state.uci_sha256["after"])


def open_private_output(path: str) -> Tuple[int, Path]:
    target = Path(path).expanduser()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(target), flags, 0o600)
    except OSError as exc:
        raise CaptureError("OUTPUT_CREATE_FAILED") from exc
    os.fchmod(fd, 0o600)
    return fd, target


def write_private_failure_marker(path: Path, error: str,
                                 pcap_sha256: Optional[str]) -> None:
    """Mark a complete, SHA-verified capture that failed a later step."""
    marker = Path(str(path) + ".capture-failed.json")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(marker), flags, 0o600)
    except OSError:
        return
    payload = {
        "schema_version": 1,
        "status": "failed_after_local_pcap_verification",
        "error": error,
        "pcap_sha256": pcap_sha256,
    }
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                # The status marker still identifies that the verified PCAP
                # could not be durably committed.
                pass
    except OSError:
        pass


def _ready_printer(token: str, window_seconds: int, link_type: int) -> None:
    print("READY " + token + " window_seconds=" + str(window_seconds)
          + " link_type=" + str(link_type),
          flush=True)


def run_session(args: argparse.Namespace) -> Dict[str, object]:
    host = validate_host(args.host)
    validate_control_socket(args.control_path)
    ap_interfaces = [validate_interface(item) for item in args.ap]
    if not ap_interfaces or len(ap_interfaces) > 4 or len(set(ap_interfaces)) != len(ap_interfaces):
        raise CaptureError("INVALID_AP_SET")
    selected = validate_interface(args.interface or ap_interfaces[0])
    monitor = validate_interface(args.monitor)
    expected = [parse_expected_ap(item) for item in args.expect_ap]
    if args.capture:
        validate_capture_limits(args.duration, args.max_packets)
        if selected not in ap_interfaces:
            raise CaptureError("SELECTED_INTERFACE_NOT_IN_AP_SET")
        if {item.interface for item in expected} != set(ap_interfaces):
            raise CaptureError("CAPTURE_REQUIRES_EXPECTATIONS_FOR_ALL_APS")
        if not args.output:
            raise CaptureError("OUTPUT_REQUIRED")
    elif args.output:
        raise CaptureError("OUTPUT_REQUIRES_CAPTURE")

    run_id = uuid.uuid4().hex
    remote_script = build_remote_script(
        ap_interfaces=ap_interfaces,
        selected_interface=selected,
        monitor_interface=monitor,
        expected=expected,
        run_id=run_id,
        capture=args.capture,
        duration=args.duration,
        packet_limit=args.max_packets,
    )
    argv = build_ssh_argv(host, args.control_path)

    out_fd: Optional[int] = None
    out_path: Optional[Path] = None
    out_file: Optional[BinaryIO] = None
    verified_pcap_sha256: Optional[str] = None
    if args.capture:
        out_fd, out_path = open_private_output(args.output)
        out_file = os.fdopen(out_fd, "wb", buffering=0)

    proc: Optional[subprocess.Popen] = None
    interrupted = False
    cancel_sent = False
    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def on_signal(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    deadline_seconds = (args.duration + LOCAL_SETUP_MARGIN_SECONDS
                        + LOCAL_CLEANUP_MARGIN_SECONDS if args.capture else 15)
    deadline = time.monotonic() + deadline_seconds
    try:
        if interrupted:
            raise CaptureError("INTERRUPTED")
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
        script_line = base64.b64encode(remote_script.encode("utf-8")) + b"\n"
        proc.stdin.write(script_line)
        proc.stdin.flush()
        def acknowledge_copy(local_sha256: str) -> None:
            nonlocal verified_pcap_sha256
            if proc is None or proc.stdin is None:
                raise CaptureError("COPY_UNVERIFIED")
            if out_file is None:
                raise CaptureError("COPY_UNVERIFIED")
            # Keep a complete SHA-matched local artifact if ACK or a later
            # fsync/ACK/post-capture validation fails.
            verified_pcap_sha256 = local_sha256
            out_file.flush()
            try:
                os.fsync(out_file.fileno())
            except OSError as exc:
                raise CaptureError("PCAP_SYNC_FAILED") from exc
            proc.stdin.write(("VERIFY " + local_sha256 + "\n").encode("ascii"))
            proc.stdin.flush()

        consumer = ProtocolConsumer(
            args.capture, out_file,
            _ready_printer if args.capture else None,
            acknowledge_copy if args.capture else None,
        )
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)

        try:
            eof = False
            while not eof:
                if interrupted and not cancel_sent and not consumer.state.copy_acknowledged:
                    try:
                        proc.stdin.write(b"CANCEL\n")
                        proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass
                    cancel_sent = True
                if time.monotonic() >= deadline:
                    if not cancel_sent:
                        try:
                            if consumer.state.result is None:
                                proc.stdin.write(b"CANCEL\n")
                            else:
                                proc.stdin.write(b"CANCEL\n")
                            proc.stdin.flush()
                        except (BrokenPipeError, OSError):
                            pass
                        cancel_sent = True
                    raise CaptureError("LOCAL_HARD_TIMEOUT")
                events = selector.select(timeout=0.2)
                if not events:
                    if proc.poll() is not None:
                        # Drain once more; EOF is delivered as a readable event.
                        continue
                    continue
                for key, _mask in events:
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        eof = True
                        break
                    consumer.feed(chunk)
            state = consumer.finish()
        finally:
            selector.close()
        return_code = proc.wait(timeout=2)
        if return_code != 0:
            raise CaptureError("SSH_OR_REMOTE_FAILED")
        if state.preflight is None:
            raise CaptureError("PREFLIGHT_MISSING")
        if set(state.ap["before"]) != set(ap_interfaces) or "before" not in state.uci_sha256:
            raise CaptureError("PREFLIGHT_INCOMPLETE")
        if not expected_matches(state, expected):
            raise CaptureError("STATE_MISMATCH")

        if not args.capture:
            ready = bool(state.preflight["monitor_supported"]
                         and state.preflight["monitor_name_available"])
            return {
                "schema_version": 1,
                "mode": "preflight",
                "ready_for_capture": ready,
                "tcpdump_version": state.preflight["tcpdump_version"],
                "libpcap_version": state.preflight["libpcap_version"],
                "monitor_supported": state.preflight["monitor_supported"],
                "monitor_name_available": state.preflight["monitor_name_available"],
                "ap_before": state.ap["before"],
                "uci_sha256_before": state.uci_sha256["before"],
            }

        if state.ready_token is None or state.result is None:
            raise CaptureError("CAPTURE_RESULT_MISSING")
        if not state.copy_acknowledged:
            raise CaptureError("COPY_UNVERIFIED")
        if not state.result["monitor_removed"]:
            raise CaptureError("MONITOR_CLEANUP_UNCONFIRMED")
        if set(state.ap["after"]) != set(ap_interfaces) or "after" not in state.uci_sha256:
            raise CaptureError("POST_CAPTURE_STATE_MISSING")
        if out_file is None or out_path is None:
            raise CaptureError("OUTPUT_CREATE_FAILED")
        out_file.flush()
        os.fsync(out_file.fileno())
        out_file.close()
        out_file = None
        local_bytes = out_path.stat().st_size
        if local_bytes != state.pcap_bytes_written:
            raise CaptureError("PCAP_READ_FAILED")
        if local_bytes != state.result["pcap_bytes_remote"]:
            raise CaptureError("PCAP_LENGTH_MISMATCH")
        if not (24 <= local_bytes <= MAX_PCAP_BYTES):
            raise CaptureError("PCAP_SIZE_INVALID")
        with out_path.open("rb") as capture_file:
            if capture_file.read(4) not in PCAP_MAGICS:
                raise CaptureError("PCAP_HEADER_INVALID")
        local_sha = state.pcap_hash.hexdigest()
        if local_sha != state.result["pcap_sha256_remote"]:
            raise CaptureError("PCAP_HASH_MISMATCH")
        same = state_unchanged(state, ap_interfaces)
        summary: Dict[str, object] = {
            "schema_version": 1,
            "mode": "capture",
            "ready_token": state.ready_token,
            "ready_window_seconds": state.ready_window_seconds,
            "pcap_link_type": state.pcap_link_type,
            "last_observed_window_remaining_seconds": state.window_remaining_seconds,
            "duration_limit_seconds": args.duration,
            "packet_limit": args.max_packets,
            "snaplen_bytes": SNAPLEN_BYTES,
            "ap_before": state.ap["before"],
            "ap_after": state.ap["after"],
            "uci_sha256_before": state.uci_sha256["before"],
            "uci_sha256_after": state.uci_sha256["after"],
            "state_unchanged": same,
            "tcpdump_version": state.preflight["tcpdump_version"],
            "libpcap_version": state.preflight["libpcap_version"],
            "tcpdump_exit_code": state.result["tcpdump_exit_code"],
            "packets_captured": state.result["packets_captured"],
            "packets_received_by_filter": state.result["packets_received_by_filter"],
            "packets_dropped_by_kernel": state.result["packets_dropped_by_kernel"],
            "pcap_bytes": local_bytes,
            "pcap_sha256": local_sha,
            "local_pcap_mode": "0600",
            "cancelled": bool(interrupted or state.result["cancelled"]),
            "monitor_removed": state.result["monitor_removed"],
            "zero_kernel_drops_do_not_prove_no_loss": True,
            "raw_packets_or_addresses_in_summary": False,
        }
        return summary
    except CaptureError as exc:
        if out_file is not None:
            out_file.close()
            out_file = None
        if out_path is not None:
            if verified_pcap_sha256:
                write_private_failure_marker(out_path, exc.code,
                                             verified_pcap_sha256)
            else:
                try:
                    out_path.unlink()
                except FileNotFoundError:
                    pass
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin is not None:
                    proc.stdin.write(b"CANCEL\n")
                    proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        if out_file is not None:
            out_file.close()
            out_file = None
        if out_path is not None:
            if verified_pcap_sha256:
                write_private_failure_marker(out_path, "LOCAL_IO_FAILED",
                                             verified_pcap_sha256)
            else:
                try:
                    out_path.unlink()
                except FileNotFoundError:
                    pass
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin is not None:
                    proc.stdin.write(b"CANCEL\n")
                    proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        raise CaptureError("LOCAL_IO_FAILED") from exc
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
        if proc is not None and proc.poll() is None:
            try:
                if proc.stdin is not None:
                    proc.stdin.write(b"CANCEL\n")
                    proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        if out_file is not None:
            out_file.close()
        if proc is not None:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded OpenWrt AWDL monitor capture coordinator")
    parser.add_argument("--host", required=True, help="SSH target already owned by the supplied ControlMaster")
    parser.add_argument("--control-path", required=True, help="Existing authenticated OpenSSH ControlMaster socket")
    parser.add_argument("--ap", action="append", required=True, help="AP interface to snapshot; repeat for every AP")
    parser.add_argument("--expect-ap", action="append", default=[], metavar="IFACE:PHY:CHANNEL:FREQ:WIDTH",
                        help="Expected AP tuple; capture requires one matching tuple per --ap")
    parser.add_argument("--interface", help="AP interface whose current channel the monitor will inherit")
    parser.add_argument("--monitor", default="awdlmon0", help="Monitor interface name; existing names are refused")
    parser.add_argument("--capture", action="store_true", help="Explicitly enable one bounded passive capture")
    parser.add_argument("--output", help="New local PCAP path; created mode 0600 and never overwritten")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION_SECONDS,
                        help="Capture timer in seconds (12 through 20; default 16)")
    parser.add_argument("--max-packets", type=int, default=DEFAULT_PACKET_LIMIT,
                        help="Hard tcpdump packet cap (maximum 4096)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_session(args)
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        if args.capture and not summary["state_unchanged"]:
            return 3
        if args.capture and summary["tcpdump_exit_code"] != 0:
            return 4
        return 0
    except CaptureError as exc:
        print(json.dumps({"schema_version": 1, "error": exc.code}, sort_keys=True))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"schema_version": 1, "error": "INTERRUPTED"}, sort_keys=True))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
