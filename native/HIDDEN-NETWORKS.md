# AX201 hidden-network offline candidate

Dev04 is based on Test120 (`dd5913819449b6a9d4d8701531f093d88e9260c8`).
It has not been deployed, loaded, or tested with a hidden AP.

## Request and firmware path

The existing native setWCL_SCAN_REQ path decodes scan441 (0x1550 bytes). Its
SSID-list count at +0x1318 is bounded to ten; +0x131c carries 56-byte records
(version DWORD, byte length DWORD, 32 SSID bytes, 16 reserved bytes). The saved
25G332 producer supports up to nine caller strings and appends one zero-filled
record. Version 1 entries (including explicit empty SSIDs) and a canonical
all-zero version0 record only in the final slot are accepted. A version0
sentinel before the final slot is rejected. Unknown versions/metadata, length
>32, count >10 and ambiguous list plus single-SSID requests fail closed. Target bytes and duplicates retain order.

A captured, fixed-capacity target set passes through the native owned gate into
net80211 and the HAL main-gate scan-policy snapshot. All three UMAC builders
pack it into real firmware SSID records and channel bitmaps. Passive requests
do not enable probes. Existing channel/MCC restrictions remain in force.
The native multiple-SSID capability bit 73 is conditional on the existing native
scan callback; no unproved legacy setSCAN_REQ virtual slot is introduced.

Zero-length records are not list terminators in the saved native consumer.
The direct consumer evidence for their broadcast meaning is from 25G241
Broadcom; the producer and transport layouts are pinned in 25G332. This is an
explicit cross-version inference, not proof of the AX201 radio behavior.
The private evidence package includes the image hashes, raw instruction pins
and a read-only verifier. No hotspot error is attributed to this path.

## Join and reconnect

A native scan must discover an actual candidate before Join. Join retains the
selected nonempty SSID, unicast BSSID and explicitly selected security/AKM.
Its own directed scan uses that SSID and ignores an old WCL scan-list snapshot.
The existing net80211 probe-response learning path supplies hidden BSS identity;
this change does not synthesize a BSS or authenticate a zero-candidate target.

Scan admission protects an RSN association whose controlled port is not yet
valid or whose PMF key batch is pending, including actual HAL background-scan
admission. OS-driven saved-network retries use current bounded deferred-Join
admission, a fresh epoch and current BSS/port authorization. Leave/failure/stop
clear temporary credentials. Immediate radio-admission failure also clears the
same attempt's desired SSID/BSSID/DESBSSID and authentication metadata, guarded
by the captured Join epoch and controller identity so it cannot erase a
replacement request. Deferred failure still has its separate backend callback.
This is not a new persistent credential store or
a driver-initiated automatic reconnect loop.

## Offline checks and limits

`sh native/tests/run_personal_security.sh` includes parser/backend hidden-network
cases and extracted production policy, SSID serializer, channel selection and
key-window gate tests under ASan/UBSan. Cases include ten slots, the empty slot,
ordered duplicates, 32-byte/binary inputs, invalid lengths/counts/metadata,
immutable snapshots, delayed scan events, Join, Leave and saved-network retry,
invalid-port admission and stop. The production builders are source-bound to
the tested packer and compiled with the real SDK; the host harness does not
execute a complete firmware scan.

AP acceptance remains open: hidden open/WPA2/WPA3 APs, PMF required/optional,
2.4/5 GHz legal channels, cache hit/miss, wrong password, lost replies,
sleep/wake, radio Off/On and repeated rekey/reconnect. Parser preservation of
binary names does not establish every unusual SSID encoding is supported by
the pre-existing discovery/UI layers. Enterprise, OWE, WEP/WPA/TKIP, FT and
192-bit security require separate implementations and tests.
