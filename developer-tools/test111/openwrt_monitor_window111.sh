#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Test111 remote, bounded radio0 monitor window. No arguments means read-only plan.
set -u
umask 077
PATH="${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL

SCHEMA='test111-openwrt-monitor-window/v1'
RADIO0='radio0'
RADIO1='radio1'
PHY0='6'
PHY1='7'
MON='iw111mon'
ECHO_NAME='openwrt_echo110'
ECHO_SHA256='ed7d33fb127d95b9593102cb3c80109021b302726d203cca01ff8cb1419415be'
ACTIVE='/tmp/iw111echo.active'
LOCK='/tmp/iw111echo.lock'
PROC_ROOT='/proc'
ACTION='plan'
STATE_DIR=''
RUN_TOKEN=''
LEASE_SECONDS='60'
ECHO_BIN=''
LOCAL_MAC=''
PEER_MAC=''
LOCAL_IPV6=''
PEER_IPV6=''
NONCE=''
LOCK_HELD=0
PREPARE_IN_PROGRESS=0

say() { printf '%s\n' "$*" >&2; }
die() { say "ERROR: $*"; exit 1; }

plan() {
    printf '{"schema":"%s","mode":"plan","echo_rf_action":false,"runtime_wifi_change":true,"persistent_config_write":false,"wan_lan_change":false,"steps":["verify radio0 maps only to phy6 and radio1 maps only to phy7","snapshot four config SHA256 values and radio1 interface signature","start and confirm a per-run 60-second nohup watchdog","stop only radio0 through ubus","remove only reserved iw111mon if it is a phy6 monitor","create iw111mon on phy6, tune channel 6, record fresh ifindex/wdev","require iwinfo channel 6 at 2437 MHz; unchanged echo110 then enforces direct GET_INTERFACE 2437 MHz offset 0 before READY","stream the original echo110 stdout unchanged","on every exit terminate this run echo, confirm exit, remove owned monitor, ubus-up radio0, verify AP channel 6/20 MHz, radio1 and four config hashes","cancel watchdog only after successful restoration"]}\n' "$SCHEMA"
}

usage() {
    cat >&2 <<'EOF'
No arguments (or --plan): print a read-only plan.
--prepare --state-dir /tmp/iw111echo-<32-hex-token> --run-token <token> [--lease-seconds 60]
--run --state-dir /tmp/iw111echo-<32-hex-token> --run-token <token> --echo-binary <same-dir>/openwrt_echo110 --local-mac <mac> --peer-mac <mac> --local-ipv6 <ll-ipv6> --peer-ipv6 <ll-ipv6> --nonce <16-hex>
--restore --state-dir /tmp/iw111echo-<32-hex-token> --run-token <token>
Internal watchdog mode is private to this script.
EOF
}

parse() {
    [ "$#" -gt 0 ] || return 0
    case "$1" in
        --plan|plan) ACTION=plan ;;
        --prepare|prepare) ACTION=prepare ;;
        --run|run) ACTION=run ;;
        --restore|restore) ACTION=restore ;;
        --watchdog|watchdog) ACTION=watchdog ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown mode: $1" ;;
    esac
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --state-dir) [ "$#" -ge 2 ] || die '--state-dir needs a value'; STATE_DIR=$2; shift 2 ;;
            --run-token) [ "$#" -ge 2 ] || die '--run-token needs a value'; RUN_TOKEN=$2; shift 2 ;;
            --lease-seconds) [ "$#" -ge 2 ] || die '--lease-seconds needs a value'; LEASE_SECONDS=$2; shift 2 ;;
            --echo-binary) [ "$#" -ge 2 ] || die '--echo-binary needs a value'; ECHO_BIN=$2; shift 2 ;;
            --local-mac) [ "$#" -ge 2 ] || die '--local-mac needs a value'; LOCAL_MAC=$2; shift 2 ;;
            --peer-mac) [ "$#" -ge 2 ] || die '--peer-mac needs a value'; PEER_MAC=$2; shift 2 ;;
            --local-ipv6) [ "$#" -ge 2 ] || die '--local-ipv6 needs a value'; LOCAL_IPV6=$2; shift 2 ;;
            --peer-ipv6) [ "$#" -ge 2 ] || die '--peer-ipv6 needs a value'; PEER_IPV6=$2; shift 2 ;;
            --nonce) [ "$#" -ge 2 ] || die '--nonce needs a value'; NONCE=$2; shift 2 ;;
            --plan) ACTION='plan'; shift ;;
            --help|-h) usage; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
}

valid_token() {
    case "$1" in *[!0-9a-f]*|'') return 1 ;; esac
    [ "${#1}" -eq 32 ] || return 1
    [ "$1" != '00000000000000000000000000000000' ]
}

uptime_cs() {
    awk '{printf "%.0f\n", $1 * 100}' /proc/uptime 2>/dev/null
}

validate_state_path() {
    valid_token "$RUN_TOKEN" || die 'run token must be 32 lowercase hex characters and nonzero'
    [ "$STATE_DIR" = "/tmp/iw111echo-$RUN_TOKEN" ] || die 'state directory must be the token-scoped /tmp path'
    [ ! -L "$STATE_DIR" ] || die 'state directory may not be a symlink'
    [ -d "$STATE_DIR" ] || die 'state directory must already exist (mode 0700)'
    listing=$(ls -ldn "$STATE_DIR" 2>/dev/null) || die 'cannot inspect state directory ownership and mode'
    printf '%s\n' "$listing" | awk -v path="$STATE_DIR" \
        'NR == 1 && NF >= 9 && $1 == "drwx------" && $3 == "0" && $NF == path { ok=1 }
         END { exit !(NR == 1 && ok) }' || die 'state directory must be root-owned mode 0700'
    SCRIPT_PATH=$0
    case "$SCRIPT_PATH" in "$STATE_DIR/monitor_window111.sh") ;; *) die 'script must run from its token-scoped state directory' ;; esac
    [ ! -L "$SCRIPT_PATH" ] || die 'script may not be a symlink'
}

validate_owner() {
    [ "$(cat "$STATE_DIR/owner" 2>/dev/null || true)" = "$RUN_TOKEN" ] || die 'state owner token mismatch'
}

read_status() {
    ubus call network.wireless status
}

radio_field() {
    radio=$1
    field=$2
    status=$(read_status) || return 1
    printf '%s\n' "$status" | jsonfilter -e "@.$radio.$field" 2>/dev/null
}

radio_ifnames() {
    radio=$1
    status=$(read_status) || return 1
    printf '%s\n' "$status" | jsonfilter -e "@.$radio.interfaces.*.ifname" 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u
}

phy_for_if() {
    wanted=$1
    iw dev | awk -v wanted="$wanted" '
        /^phy#[0-9]+/ { phy=$1; sub(/^phy#/, "", phy) }
        /^[[:space:]]*Interface[[:space:]]/ && $2 == wanted { print phy; found++ }
        END { if (found != 1) exit 1 }
    '
}

phy_ifnames() {
    wanted_phy=$1
    iw dev | awk -v wanted="$wanted_phy" '
        /^phy#[0-9]+/ { phy=$1; sub(/^phy#/, "", phy) }
        /^[[:space:]]*Interface[[:space:]]/ && phy == wanted { print $2 }
    '
}

info_fields() {
    iw dev "$1" info 2>/dev/null | awk '
        /^[[:space:]]*ifindex[[:space:]]/ { idx=$2 }
        /^[[:space:]]*wdev[[:space:]]/ { wdev=$2 }
        /^[[:space:]]*type[[:space:]]/ { type=$2 }
        /^[[:space:]]*channel[[:space:]]/ { channel=$0; sub(/^[[:space:]]*/, "", channel) }
        END { if (idx != "" && wdev != "" && type != "") printf "%s\t%s\t%s\t%s\n", idx, wdev, type, channel; else exit 1 }
    '
}

iface_is_up() {
    ip link show dev "$1" 2>/dev/null | awk '
        NR == 1 && match($0, /<[^>]+>/) {
            flags=substr($0, RSTART+1, RLENGTH-2)
            count=split(flags, parts, ",")
            for (i=1; i<=count; i++) if (parts[i] == "UP") up=1
        }
        END { exit !up }
    '
}

assert_radio_map() {
    radio=$1
    expected=$2
    names=$(radio_ifnames "$radio") || return 1
    [ -n "$names" ] || { say "$radio has no interfaces to map"; return 1; }
    for name in $names; do
        mapped=$(phy_for_if "$name") || { say "cannot map $radio interface $name"; return 1; }
        [ "$mapped" = "$expected" ] || { say "$radio interface $name maps to phy$mapped, expected phy$expected"; return 1; }
    done
}

radio_signature() {
    radio=$1
    up=$(radio_field "$radio" up) || return 1
    disabled=$(radio_field "$radio" disabled) || return 1
    autostart=$(radio_field "$radio" autostart) || return 1
    names=$(radio_ifnames "$radio") || return 1
    [ -n "$names" ] || return 1
    printf 'radio=%s up=%s disabled=%s autostart=%s\n' "$radio" "$up" "$disabled" "$autostart"
    for name in $names; do
        phy=$(phy_for_if "$name") || return 1
        fields=$(info_fields "$name") || return 1
        if iface_is_up "$name"; then state=UP; else state=DOWN; fi
        printf 'if=%s phy=%s state=%s fields=%s\n' "$name" "$phy" "$state" "$fields"
    done
}

config_hashes() {
    for file in /etc/config/network /etc/config/wireless /etc/config/firewall /etc/config/dhcp; do
        [ -r "$file" ] || { say "missing protected config $file"; return 1; }
        digest=$(sha256sum "$file" | awk '{print $1}') || return 1
        [ "${#digest}" -eq 64 ] || return 1
        printf '%s  %s\n' "$digest" "$file"
    done
}

assert_config_unchanged() {
    now=$(config_hashes) || return 1
    before=$(cat "$STATE_DIR/config.sha256" 2>/dev/null) || return 1
    [ "$now" = "$before" ] || { say 'one or more protected OpenWrt config hashes changed'; return 1; }
}

assert_radio1_unchanged() {
    now=$(radio_signature "$RADIO1") || return 1
    before=$(cat "$STATE_DIR/radio1.signature" 2>/dev/null) || return 1
    [ "$now" = "$before" ] || { say 'radio1/phy7 signature changed'; return 1; }
}

active_token() { cat "$ACTIVE" 2>/dev/null || true; }

acquire_lock() {
    tries=${1:-5}
    while [ "$tries" -gt 0 ]; do
        if mkdir "$LOCK" 2>/dev/null; then
            printf '%s %s\n' "$RUN_TOKEN" "$$" > "$LOCK/owner"
            LOCK_HELD=1
            return 0
        fi
        if [ -r "$LOCK/owner" ]; then
            read -r lock_token lock_pid < "$LOCK/owner" || true
            if [ "$lock_token" = "$RUN_TOKEN" ] && [ -n "${lock_pid:-}" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
                rm -f "$LOCK/owner"
                rmdir "$LOCK" 2>/dev/null || true
                continue
            fi
        fi
        sleep 1
        tries=$((tries - 1))
    done
    return 1
}

release_lock() {
    [ "$LOCK_HELD" -eq 1 ] || return 0
    if [ "$(cat "$LOCK/owner" 2>/dev/null || true)" = "$RUN_TOKEN $$" ]; then
        rm -f "$LOCK/owner"
        rmdir "$LOCK" 2>/dev/null || true
    fi
    LOCK_HELD=0
}

clear_active_after_success() {
    [ "$(active_token)" = "$RUN_TOKEN" ] || { say 'active token changed; leaving guard state intact'; return 1; }
    rm -f "$ACTIVE"
    printf '%s\n' restored > "$STATE_DIR/state"
}

pid_is_echo() {
    pid=$1
    [ -r "$PROC_ROOT/$pid/cmdline" ] || return 1
    exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null || true)
    [ "$exe" = "$STATE_DIR/$ECHO_NAME" ] || return 1
    cmd=$(tr '\000' ' ' < "$PROC_ROOT/$pid/cmdline" 2>/dev/null || true)
    case "$cmd" in *"$STATE_DIR/$ECHO_NAME"*"--run-token $RUN_TOKEN"*) return 0 ;; esac
    return 1
}

watchdog_process_matches() {
    pid=$1
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "$PROC_ROOT/$pid/cmdline" ] && [ -e "$PROC_ROOT/$pid/exe" ] || return 1
    exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null || true)
    case "$exe" in */busybox|*/ash|*/sh|*/dash) : ;; *) return 1 ;; esac
    cmd=$(tr '\000' ' ' < "$PROC_ROOT/$pid/cmdline" 2>/dev/null || true)
    case "$cmd" in
        *"$SCRIPT_PATH"*' --watchdog --state-dir '"$STATE_DIR"' --run-token '"$RUN_TOKEN"*) return 0 ;;
    esac
    return 1
}

terminate_echo() {
    [ -r "$STATE_DIR/echo.pid" ] || return 0
    pid=$(cat "$STATE_DIR/echo.pid") || return 1
    case "$pid" in ''|*[!0-9]*) say 'invalid echo pid'; return 1 ;; esac
    if ! kill -0 "$pid" 2>/dev/null; then
        printf '%s\n' confirmed > "$STATE_DIR/echo.exit-confirmed"
        return 0
    fi
    pid_is_echo "$pid" || { say 'refusing to signal a PID that is not this run echo110'; return 1; }
    kill -TERM "$pid" 2>/dev/null || true
    count=0
    while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 5 ]; do sleep 1; count=$((count + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
        pid_is_echo "$pid" || { say 'echo PID identity changed before force stop'; return 1; }
        kill -KILL "$pid" 2>/dev/null || true
    fi
    count=0
    while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 5 ]; do sleep 1; count=$((count + 1)); done
    if kill -0 "$pid" 2>/dev/null; then say 'echo110 exit not confirmed'; return 1; fi
    printf '%s\n' confirmed > "$STATE_DIR/echo.exit-confirmed"
}

remove_owned_monitor() {
    pending=$(cat "$STATE_DIR/monitor-create-pending" 2>/dev/null || true)
    [ "$pending" = 1 ] || return 0
    fields=$(info_fields "$MON" 2>/dev/null || true)
    [ -n "$fields" ] || { rm -f "$STATE_DIR/monitor.identity"; return 0; }
    phy=$(phy_for_if "$MON") || { say 'refusing to remove iw111mon with unknown phy'; return 1; }
    type=$(printf '%s\n' "$fields" | awk -F '\t' '{print $3}')
    [ "$phy" = "$PHY0" ] && [ "$type" = monitor ] || { say 'refusing to remove unowned/non-phy6 iw111mon'; return 1; }
    if [ -r "$STATE_DIR/monitor.identity" ]; then
        [ "$fields" = "$(cat "$STATE_DIR/monitor.identity")" ] || { say 'iw111mon ifindex/wdev changed; refusing deletion'; return 1; }
    fi
    iw dev "$MON" del || return 1
    if iw dev "$MON" info >/dev/null 2>&1; then say 'iw111mon still exists after deletion'; return 1; fi
    rm -f "$STATE_DIR/monitor.identity" "$STATE_DIR/monitor-create-pending"
}

verify_radio0_restored() {
    up=$(radio_field "$RADIO0" up) || return 1
    disabled=$(radio_field "$RADIO0" disabled) || return 1
    [ "$up" = true ] && [ "$disabled" = false ] || { say 'radio0 did not return UP/enabled'; return 1; }
    assert_radio_map "$RADIO0" "$PHY0" || return 1
    names=$(radio_ifnames "$RADIO0") || return 1
    found=0
    for name in $names; do
        fields=$(info_fields "$name") || return 1
        type=$(printf '%s\n' "$fields" | awk -F '\t' '{print $3}')
        [ "$type" = AP ] || continue
        if ! iface_is_up "$name"; then continue; fi
        details=$(iwinfo "$name" info 2>/dev/null) || return 1
        printf '%s\n' "$details" | grep -Eq 'Channel:[[:space:]]*6[[:space:]]*\(2\.437[[:space:]]+GHz\)' || continue
        printf '%s\n' "$details" | grep -Eq 'HT Mode:[[:space:]]*[A-Z0-9]*20([[:space:]]|$)' || continue
        found=1
    done
    [ "$found" -eq 1 ] || { say 'radio0 AP channel 6 / 20 MHz not verified'; return 1; }
}

restore_runtime() {
    [ "$(active_token)" = "$RUN_TOKEN" ] || { say 'this run no longer owns the active guard'; return 1; }
    terminate_echo || return 1
    remove_owned_monitor || return 1
    ubus call network.wireless up '{"device":"radio0"}' >/dev/null || { say 'ubus failed to bring radio0 up'; return 1; }
    count=0
    while [ "$count" -lt 12 ]; do
        if verify_radio0_restored && assert_radio1_unchanged && assert_config_unchanged; then
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    say 'radio/config restoration verification did not pass'
    return 1
}

cancel_guard_after_verified_restore() {
    read -r ready_token ready_pid ready_uptime < "$STATE_DIR/guard.ready" || { say 'guard readiness receipt missing'; return 1; }
    [ "$ready_token" = "$RUN_TOKEN" ] || { say 'guard readiness token mismatch'; return 1; }
    guard_pid=$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)
    case "$guard_pid" in ''|*[!0-9]*) say 'invalid guard pid'; return 1 ;; esac
    [ "$ready_pid" = "$guard_pid" ] || { say 'guard readiness pid mismatch'; return 1; }
    if kill -0 "$guard_pid" 2>/dev/null; then
        watchdog_process_matches "$guard_pid" || { say 'refusing to signal a PID that is not this run watchdog'; return 1; }
        printf '%s\n' "$RUN_TOKEN" > "$STATE_DIR/cancel"
        if kill -0 "$guard_pid" 2>/dev/null; then
            watchdog_process_matches "$guard_pid" || { say 'watchdog PID identity changed before TERM'; return 1; }
            kill -TERM "$guard_pid" 2>/dev/null || true
        fi
        count=0
        while kill -0 "$guard_pid" 2>/dev/null && [ "$count" -lt 5 ]; do
            watchdog_process_matches "$guard_pid" || { say 'watchdog PID identity changed while stopping'; return 1; }
            sleep 1
            count=$((count + 1))
        done
        kill -0 "$guard_pid" 2>/dev/null && { say 'watchdog exit not confirmed'; return 1; }
    fi
    clear_active_after_success
}

restore_action() {
    validate_state_path
    owner=$(cat "$STATE_DIR/owner" 2>/dev/null || true)
    active=$(active_token)
    if [ -z "$owner" ]; then
        [ -z "$active" ] || die 'another run owns the active guard; refusing restore'
        printf '{"schema":"%s","event":"RESTORED","idempotent":true,"router_change":"none; prepare never claimed this token"}\n' "$SCHEMA"
        return 0
    fi
    [ "$owner" = "$RUN_TOKEN" ] || die 'state owner token mismatch; refusing restore'
    state=$(cat "$STATE_DIR/state" 2>/dev/null || true)
    if [ "$state" = restored ] ||
       { [ -z "$active" ] && { [ "$state" = aborted-before-change ] ||
          { [ "$state" = preparing ] && [ "$(cat "$STATE_DIR/monitor-create-pending" 2>/dev/null || true)" != 1 ]; }; }; }; then
        [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || die 'another run owns the active guard; refusing idempotent restore'
        verify_radio0_restored || die 'recorded restore state no longer matches radio0 AP ch6/20MHz'
        assert_radio1_unchanged || die 'recorded restore state no longer matches radio1/phy7'
        assert_config_unchanged || die 'recorded restore state no longer matches protected config hashes'
        printf '{"schema":"%s","event":"RESTORED","idempotent":true,"radio0":"verified read-only","radio1":"unchanged","config_sha256":"unchanged","guard":"already stopped"}\n' "$SCHEMA"
        return 0
    fi
    [ "$state" = prepared ] || [ "$state" = preparing ] || die 'run is not in a restorable state'
    [ "$(active_token)" = "$RUN_TOKEN" ] || die 'this token does not own the active guard'
    acquire_lock 10 || die 'could not acquire run lock; watchdog remains armed'
    if ! restore_runtime; then release_lock; die 'restore failed; watchdog/state left armed for recovery'; fi
    if ! cancel_guard_after_verified_restore; then release_lock; die 'restore verified but watchdog cancellation unconfirmed; state left for recovery'; fi
    release_lock
    printf '{"schema":"%s","event":"RESTORED","radio0":"phy6 AP ch6/20MHz verified","radio1":"unchanged","config_sha256":"unchanged","guard":"cancelled after verification"}\n' "$SCHEMA"
}

write_config_baseline() {
    config_hashes > "$STATE_DIR/config.sha256" || return 1
    chmod 600 "$STATE_DIR/config.sha256"
}

write_radio1_baseline() {
    radio_signature "$RADIO1" > "$STATE_DIR/radio1.signature" || return 1
    chmod 600 "$STATE_DIR/radio1.signature"
}

wait_guard_ready() {
    count=0
    while [ "$count" -lt 6 ]; do
        if [ -r "$STATE_DIR/guard.ready" ] && [ "$(cat "$STATE_DIR/guard.ready" 2>/dev/null | awk '{print $1}')" = "$RUN_TOKEN" ]; then
            guard_pid=$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)
            case "$guard_pid" in ''|*[!0-9]*) return 1 ;; esac
            ready_pid=$(cat "$STATE_DIR/guard.ready" 2>/dev/null | awk '{print $2}')
            ready_uptime=$(cat "$STATE_DIR/guard.ready" 2>/dev/null | awk '{print $3}')
            [ "$ready_pid" = "$guard_pid" ] || return 1
            case "$ready_uptime" in ''|*[!0-9]*) return 1 ;; esac
            kill -0 "$guard_pid" 2>/dev/null || return 1
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    return 1
}

prepare_action() {
    validate_state_path
    owner=$(cat "$STATE_DIR/owner" 2>/dev/null || true)
    [ -z "$owner" ] && [ ! -L "$STATE_DIR/owner" ] || die 'state directory has already been used'
    [ ! -e "$STATE_DIR/state" ] && [ ! -L "$STATE_DIR/state" ] || die 'state directory has already been used'
    [ "${LEASE_SECONDS#0}" = "$LEASE_SECONDS" ] || die 'lease must be a decimal integer without a leading zero'
    case "$LEASE_SECONDS" in ''|*[!0-9]*) die 'invalid lease seconds' ;; esac
    [ "$LEASE_SECONDS" -ge 30 ] && [ "$LEASE_SECONDS" -le 120 ] || die 'lease must be 30..120 seconds'
    [ "$(id -u)" = 0 ] || die 'prepare requires root on OpenWrt'
    [ -x "$STATE_DIR/$ECHO_NAME" ] || die 'verified echo110 binary is missing from the run directory'
    echo_sha=$(sha256sum "$STATE_DIR/$ECHO_NAME" | awk '{print $1}')
    [ "$echo_sha" = "$ECHO_SHA256" ] || die 'echo110 SHA256 mismatch'
    assert_radio_map "$RADIO0" "$PHY0" || die 'radio0 is not exclusively mapped to phy6'
    assert_radio_map "$RADIO1" "$PHY1" || die 'radio1 is not exclusively mapped to phy7'
    [ "$(radio_field "$RADIO0" up)" = true ] || die 'radio0 is not currently up'
    [ "$(radio_field "$RADIO0" disabled)" = false ] || die 'radio0 is disabled'
    [ "$(radio_field "$RADIO1" up)" = true ] || die 'radio1 is not currently up'
    verify_radio0_restored || die 'radio0 is not currently AP ch6/20MHz; refusing a non-baseline switch'

    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || die 'another Test111 run/guard is still active; do not replace its token'
    acquire_lock 1 || die 'another Test111 run holds the remote lock'
    [ ! -e "$ACTIVE" ] && [ ! -L "$ACTIVE" ] || die 'another Test111 run/guard became active'
    assert_radio_map "$RADIO0" "$PHY0" || die 'radio0 mapping changed during preflight'
    assert_radio_map "$RADIO1" "$PHY1" || die 'radio1 mapping changed during preflight'
    [ "$(radio_field "$RADIO0" up)" = true ] || die 'radio0 stopped during preflight'
    [ "$(radio_field "$RADIO1" up)" = true ] || die 'radio1 stopped during preflight'
    write_config_baseline || die 'could not snapshot protected config hashes'
    write_radio1_baseline || die 'could not snapshot radio1/phy7 state'
    (set -C; printf '%s\n' "$RUN_TOKEN" > "$ACTIVE") 2>/dev/null || die 'could not claim active run token'
    printf '%s\n' "$RUN_TOKEN" > "$STATE_DIR/owner"
    printf '%s\n' preparing > "$STATE_DIR/state"
    printf '%s\n' "$ECHO_SHA256" > "$STATE_DIR/echo.sha256"
    printf '%s\n' "$LEASE_SECONDS" > "$STATE_DIR/lease.seconds"
    printf '%s\n' "$$" > "$STATE_DIR/prepare.pid"

    command -v nohup >/dev/null 2>&1 || die 'nohup is required for an independent watchdog'
    : > "$STATE_DIR/guard.launching"
    nohup /bin/sh "$SCRIPT_PATH" --watchdog --state-dir "$STATE_DIR" --run-token "$RUN_TOKEN" --lease-seconds "$LEASE_SECONDS" </dev/null >/dev/null 2>"$STATE_DIR/watchdog.log" &
    guard_pid=$!
    printf '%s\n' "$guard_pid" > "$STATE_DIR/guard.pid"
    chmod 600 "$STATE_DIR/guard.pid"
    rm -f "$STATE_DIR/guard.launching"
    wait_guard_ready || die 'independent watchdog did not start and confirm before radio0 down'
    PREPARE_IN_PROGRESS=1

    # iw111mon is the reserved Test111 interface. Existing instances are replaced
    # only when they are actually monitor-type interfaces on the verified phy6.
    old_fields=$(info_fields "$MON" 2>/dev/null || true)
    if [ -n "$old_fields" ]; then
        old_phy=$(phy_for_if "$MON") || die 'existing iw111mon has unknown phy'
        old_type=$(printf '%s\n' "$old_fields" | awk -F '\t' '{print $3}')
        [ "$old_phy" = "$PHY0" ] && [ "$old_type" = monitor ] || die 'existing iw111mon is not an owned phy6 monitor'
        iw dev "$MON" del || die 'could not remove existing owned iw111mon'
        iw dev "$MON" info >/dev/null 2>&1 && die 'existing iw111mon remained after delete'
    fi

    ubus call network.wireless down '{"device":"radio0"}' >/dev/null || die 'ubus radio0 down failed'
    count=0
    while [ "$(radio_field "$RADIO0" up 2>/dev/null || true)" != false ] && [ "$count" -lt 10 ]; do sleep 1; count=$((count + 1)); done
    [ "$(radio_field "$RADIO0" up 2>/dev/null || true)" = false ] || die 'radio0 down not confirmed'
    assert_radio1_unchanged || die 'radio1 changed during radio0 stop'

    # Re-read all phy6 interfaces after AP stop; any UP non-monitor is a hard stop.
    for name in $(phy_ifnames "$PHY0"); do
        fields=$(info_fields "$name") || die "cannot read phy6 interface $name after radio0 down"
        type=$(printf '%s\n' "$fields" | awk -F '\t' '{print $3}')
        if [ "$type" != monitor ] && iface_is_up "$name"; then die "phy6 still has UP non-monitor interface $name"; fi
    done

    printf '%s\n' 1 > "$STATE_DIR/monitor-create-pending"
    iw phy "phy$PHY0" interface add "$MON" type monitor >/dev/null || die 'could not create phy6 monitor'
    ip link set dev "$MON" up >/dev/null || die 'could not set monitor UP'
    iw dev "$MON" set channel 6 >/dev/null || die 'could not tune monitor to channel 6'
    fields=$(info_fields "$MON") || die 'could not re-read monitor ifindex/wdev'
    phy=$(phy_for_if "$MON") || die 'new monitor has no phy mapping'
    type=$(printf '%s\n' "$fields" | awk -F '\t' '{print $3}')
    [ "$phy" = "$PHY0" ] && [ "$type" = monitor ] || die 'new monitor identity is not phy6 monitor'
    printf '%s\n' "$fields" > "$STATE_DIR/monitor.identity"
    chmod 600 "$STATE_DIR/monitor.identity"
    for name in $(phy_ifnames "$PHY0"); do
        fields_check=$(info_fields "$name") || die "cannot inspect phy6 interface $name"
        type_check=$(printf '%s\n' "$fields_check" | awk -F '\t' '{print $3}')
        if [ "$name" != "$MON" ] && [ "$type_check" != monitor ] && iface_is_up "$name"; then die "phy6 has UP non-monitor interface $name"; fi
    done
    details=$(iwinfo "$MON" info 2>/dev/null) || die 'iwinfo cannot read new monitor frequency'
    printf '%s\n' "$details" | grep -Eq 'Channel:[[:space:]]*6[[:space:]]*\(2\.437[[:space:]]+GHz\)' || die 'monitor is not on 2437 MHz'
    [ "$(cat "$STATE_DIR/echo.sha256")" = "$ECHO_SHA256" ] || die 'stored echo hash changed'
    printf '%s\n' prepared > "$STATE_DIR/state"
    rm -f "$STATE_DIR/prepare.pid"
    release_lock
    PREPARE_IN_PROGRESS=0
    PREPARE_SUCCEEDED=1
    printf '{"schema":"%s","event":"PREPARED","run_token":"%s","radio0":"down","monitor":"phy6 iw111mon","ifindex":%s,"wdev":"%s","frequency_mhz":2437,"echo_sha256":"%s","watchdog":"ready before radio0 down","rf_action":false}\n' \
        "$SCHEMA" "$RUN_TOKEN" "$(printf '%s\n' "$fields" | awk -F '\t' '{print $1}')" "$(printf '%s\n' "$fields" | awk -F '\t' '{print $2}')" "$ECHO_SHA256"
}

run_action() {
    validate_state_path
    validate_owner
    [ "$(cat "$STATE_DIR/state" 2>/dev/null || true)" = prepared ] || die 'run requires completed prepare'
    [ "$(active_token)" = "$RUN_TOKEN" ] || die 'run token no longer owns active guard'
    read -r ready_token ready_pid ready_uptime < "$STATE_DIR/guard.ready" || die 'watchdog uptime receipt missing'
    [ "$ready_token" = "$RUN_TOKEN" ] || die 'watchdog uptime receipt token mismatch'
    case "$ready_uptime" in ''|*[!0-9]*) die 'watchdog uptime receipt invalid' ;; esac
    guard_pid=$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)
    [ "$ready_pid" = "$guard_pid" ] && kill -0 "$guard_pid" 2>/dev/null || die 'independent watchdog is not alive for this run'
    lease=$(cat "$STATE_DIR/lease.seconds" 2>/dev/null || true)
    case "$lease" in ''|*[!0-9]*) die 'watchdog lease receipt invalid' ;; esac
    now_uptime=$(uptime_cs)
    case "$now_uptime" in ''|*[!0-9]*) die 'cannot read monotonic uptime for watchdog lease' ;; esac
    remaining_cs=$((lease * 100 - now_uptime + ready_uptime))
    [ "$remaining_cs" -ge 2000 ] || die 'watchdog has less than 20 seconds remaining; refusing echo launch'
    [ "$ECHO_BIN" = "$STATE_DIR/$ECHO_NAME" ] || die 'echo binary path must be the staged run-scoped binary'
    [ -x "$ECHO_BIN" ] || die 'echo binary is not executable'
    [ "$(sha256sum "$ECHO_BIN" | awk '{print $1}')" = "$ECHO_SHA256" ] || die 'echo110 SHA256 mismatch'
    [ ! -e "$STATE_DIR/echo.pid" ] || die 'echo already launched for this run token'
    fields=$(info_fields "$MON") || die 'monitor disappeared before echo launch'
    [ "$fields" = "$(cat "$STATE_DIR/monitor.identity" 2>/dev/null || true)" ] || die 'monitor ifindex/wdev changed before echo launch'
    [ "$(phy_for_if "$MON")" = "$PHY0" ] || die 'monitor no longer maps to phy6'
    type=$(printf '%s\n' "$fields" | awk -F '\t' '{print $3}')
    [ "$type" = monitor ] && iface_is_up "$MON" || die 'monitor is not UP/type monitor on phy6'
    # iwinfo issues a live interface query and is a cheap frequency preflight.
    details=$(iwinfo "$MON" info 2>/dev/null) || die 'iwinfo frequency preflight failed'
    printf '%s\n' "$details" | grep -Eq 'Channel:[[:space:]]*6[[:space:]]*\(2\.437[[:space:]]+GHz\)' || die 'monitor frequency is not 2437 MHz'
    fields=$(info_fields "$MON") || die 'monitor disappeared during frequency preflight'
    [ "$fields" = "$(cat "$STATE_DIR/monitor.identity" 2>/dev/null || true)" ] &&
        [ "$(phy_for_if "$MON")" = "$PHY0" ] && iface_is_up "$MON" || die 'monitor identity changed during preflight'
    for value in "$LOCAL_MAC" "$PEER_MAC"; do
        case "$value" in *[!0-9a-fA-F:]*|'') die 'invalid MAC argument syntax' ;; esac
    done
    for value in "$LOCAL_IPV6" "$PEER_IPV6"; do
        case "$value" in *[!0-9a-fA-F:]*|'') die 'invalid IPv6 argument syntax' ;; esac
    done
    case "$NONCE" in *[!0-9a-f]*|'') die 'nonce must be lowercase hex' ;; esac
    [ "${#NONCE}" -eq 16 ] || die 'nonce must be 16 hex characters'
    [ "$RUN_TOKEN" = "$(cat "$STATE_DIR/owner")" ] || die 'echo token differs from state owner'
    printf '%s\n' "$$" > "$STATE_DIR/echo.pid"
    chmod 600 "$STATE_DIR/echo.pid"
    # stdout is the real echo process stdout, beginning with its original READY.
    exec "$ECHO_BIN" --run --interface "$MON" --local-mac "$LOCAL_MAC" --peer-mac "$PEER_MAC" \
        --local-ipv6 "$LOCAL_IPV6" --peer-ipv6 "$PEER_IPV6" --nonce "$NONCE" --run-token "$RUN_TOKEN" --window-ms 16000
}

watchdog_action() {
    validate_state_path
    validate_owner
    trap '' HUP INT
    trap '[ -e "$STATE_DIR/cancel" ] && exit 0' TERM
    [ "$(active_token)" = "$RUN_TOKEN" ] || exit 2
    count=0
    while [ "$count" -lt 6 ]; do
        [ "$(active_token)" = "$RUN_TOKEN" ] || exit 2
        guard_pid=$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)
        if [ "$guard_pid" = "$$" ]; then break; fi
        [ -z "$guard_pid" ] || exit 4
        sleep 1
        count=$((count + 1))
    done
    [ "$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)" = "$$" ] || exit 4
    started_uptime=$(uptime_cs)
    case "$started_uptime" in ''|*[!0-9]*) exit 3 ;; esac
    printf '%s %s %s\n' "$RUN_TOKEN" "$$" "$started_uptime" > "$STATE_DIR/guard.ready"
    chmod 600 "$STATE_DIR/guard.ready"
    deadline_cs=$((started_uptime + LEASE_SECONDS * 100))
    while :; do
        [ -e "$STATE_DIR/cancel" ] && exit 0
        [ "$(active_token)" = "$RUN_TOKEN" ] || exit 0
        now_cs=$(uptime_cs)
        case "$now_cs" in ''|*[!0-9]*) exit 3 ;; esac
        [ "$now_cs" -lt "$deadline_cs" ] || break
        sleep 1
    done
    [ -e "$STATE_DIR/cancel" ] && exit 0
    [ "$(active_token)" = "$RUN_TOKEN" ] || exit 0
    # If a prepare session was abandoned while holding the lock, terminate only
    # that token-scoped script process so this guard can take over restoration.
    if [ "$(cat "$STATE_DIR/state" 2>/dev/null || true)" = preparing ]; then
        prepare_pid=$(cat "$STATE_DIR/prepare.pid" 2>/dev/null || true)
        case "$prepare_pid" in ''|*[!0-9]*) prepare_pid='' ;; esac
        if [ -n "$prepare_pid" ] && [ -r "$PROC_ROOT/$prepare_pid/cmdline" ]; then
            prepare_cmd=$(tr '\000' ' ' < "$PROC_ROOT/$prepare_pid/cmdline" 2>/dev/null || true)
            case "$prepare_cmd" in
                *"$SCRIPT_PATH"*'--prepare'*"$STATE_DIR"*"$RUN_TOKEN"*)
                    kill -TERM "$prepare_pid" 2>/dev/null || true
                    count=0
                    while kill -0 "$prepare_pid" 2>/dev/null && [ "$count" -lt 5 ]; do sleep 1; count=$((count + 1)); done
                    if kill -0 "$prepare_pid" 2>/dev/null; then
                        prepare_cmd=$(tr '\000' ' ' < "$PROC_ROOT/$prepare_pid/cmdline" 2>/dev/null || true)
                        case "$prepare_cmd" in *"$SCRIPT_PATH"*'--prepare'*"$RUN_TOKEN"*) kill -KILL "$prepare_pid" 2>/dev/null || true ;; esac
                    fi
                    ;;
            esac
        fi
    fi
    if ! acquire_lock 20; then
        say 'watchdog could not acquire restore lock; leaving active guard marker for manual recovery'
        exit 1
    fi
    [ "$(active_token)" = "$RUN_TOKEN" ] || { release_lock; exit 0; }
    if restore_runtime; then
        printf '%s\n' watchdog-restored > "$STATE_DIR/state"
        clear_active_after_success || { release_lock; exit 1; }
        printf '%s\n' restored > "$STATE_DIR/watchdog.result"
    else
        printf '%s\n' restore-failed > "$STATE_DIR/watchdog.result"
        say 'watchdog restore failed; active marker remains to block another run'
        release_lock
        exit 1
    fi
    release_lock
}

on_exit() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$ACTION" = prepare ] && [ "$PREPARE_SUCCEEDED" -eq 0 ] && [ "$(active_token)" = "$RUN_TOKEN" ]; then
        if [ "$PREPARE_IN_PROGRESS" -eq 1 ]; then
            say 'prepare exited after guard confirmation; attempting the ordered restore path'
            if restore_runtime; then
                cancel_guard_after_verified_restore || say 'prepare cleanup verified but watchdog cancellation remains unconfirmed'
            else
                say 'prepare cleanup failed; independent watchdog remains armed'
            fi
        else
            say 'prepare exited before radio changes; stopping any partial watchdog and verifying the untouched state'
            guard_pid=$(cat "$STATE_DIR/guard.pid" 2>/dev/null || true)
            case "$guard_pid" in ''|*[!0-9]*) guard_pid='' ;; esac
            guard_exit_confirmed=0
            if [ -n "$guard_pid" ]; then
                if ! kill -0 "$guard_pid" 2>/dev/null; then
                    guard_exit_confirmed=1
                elif watchdog_process_matches "$guard_pid"; then
                    printf '%s\n' "$RUN_TOKEN" > "$STATE_DIR/cancel"
                    if watchdog_process_matches "$guard_pid"; then
                        kill -TERM "$guard_pid" 2>/dev/null || true
                        count=0
                        while kill -0 "$guard_pid" 2>/dev/null && [ "$count" -lt 5 ]; do
                            watchdog_process_matches "$guard_pid" || break
                            sleep 1
                            count=$((count + 1))
                        done
                        if ! kill -0 "$guard_pid" 2>/dev/null; then guard_exit_confirmed=1; fi
                    fi
                else
                    say 'refusing to signal a PID that is not this run watchdog'
                fi
            elif [ ! -e "$STATE_DIR/guard.launching" ]; then
                guard_exit_confirmed=1
            fi
            if [ "$guard_exit_confirmed" -eq 1 ] &&
               [ "$(radio_field "$RADIO0" up 2>/dev/null || true)" = true ] &&
               assert_radio1_unchanged && assert_config_unchanged; then
                rm -f "$ACTIVE"
                printf '%s\n' aborted-before-change > "$STATE_DIR/state"
            else
                say 'untouched-state proof or guard exit failed; active marker remains for recovery'
            fi
        fi
    fi
    release_lock
    exit "$status"
}

main() {
    PREPARE_SUCCEEDED=0
    parse "$@"
    case "$ACTION" in
        plan) plan; exit 0 ;;
        prepare|run|restore|watchdog) : ;;
        *) usage; exit 2 ;;
    esac
    validate_state_path
    SCRIPT_PATH=$0
    case "$SCRIPT_PATH" in /*) : ;; *) die 'script path must be absolute' ;; esac
    case "$ACTION" in
        prepare)
            trap on_exit EXIT HUP INT TERM
            prepare_action
            ;;
        run) run_action ;;
        restore) restore_action ;;
        watchdog) watchdog_action ;;
    esac
}

main "$@"
