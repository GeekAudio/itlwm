# AX201 WPA3 / PMF development candidate

`25G332-WPA3PMF-Dev04` is an isolated x86_64 Tahoe/AX201 development candidate.
It has not been deployed or tested against an access point. A successful build,
portable handshake, or firmware command-table match does not establish a working
encrypted Wi-Fi connection or AirDrop interoperability.

## Implemented scope

| Native request | Implementation | Runtime acceptance |
| --- | --- | --- |
| WPA2-Personal / CCMP, AKM 2 | Existing passphrase, 64hex or PMK path | Re-test required for this candidate |
| WPA2-Personal-SHA256 / CCMP, AKM 6 | SHA-256 PTK derivation and descriptor version 3 | Not tested on hardware |
| WPA3-Personal / CCMP, ordinary SAE AKM 8 | P-256 group 19; H&P and H2E; commit/confirm; anti-clogging token; PMF required | Not tested on hardware |
| Optional or required PMF | Pairwise firmware CCMP MFP; IGTK command and software BIP-CMAC-128; replay checks; SA Query | Not tested on hardware |
| Enterprise / 802.1X, Suite-B / 192-bit, OWE, WPA/TKIP, SAE-EXT-KEY, FT-SAE, other SAE groups, password identifiers | Unsupported | Rejected or not advertised |

The parser requires an explicit selected AKM offered by the AP. SAE requires
MFPC and makes the local association require PMF, including transition-mode APs.
RSN group/data cipher support remains CCMP and the management cipher remains
BIP-CMAC-128. MFPR without MFPC and unsupported management ciphers are rejected.
An SAE password is 1–64 bytes; embedded NUL is rejected. Native auxiliary PMK
storage is bounded and ignored for SAE. Only a verified peer Confirm supplies
the node PMK/PMKID, and the controlled port remains closed for the 4-way handshake.

Ordinary SAE uses the SHA-256 PTK KDF, EAPOL descriptor version 0, AES-CMAC MIC,
and AES Key Wrap. It does not use the SAE-EXT-KEY HMAC-SHA-256 MIC rule. The
vendored crypto revisions, licenses, platform glue, and bounded Confirm retry
behavior are documented in [third_party/sae](../third_party/sae/README.md).

PMF key submission is asynchronous. A queued command is pending, not installed;
the port waits for all required PTK/GTK/IGTK acknowledgements. Command identity,
firmware generation, node epoch, and key incarnation reject stale completions.
Failure or missing acknowledgement closes the port and triggers cleanup/reset.
Software BIP checks the actual MIC and strictly increasing 48-bit IPN. Duplicate
key delivery does not reset replay state. Explicit leave, failure, address change,
and successful gated stop clear credentials and temporary SAE state.

The STA-only build now initiates SA Query for an unprotected reason-6/7
disconnect addressed to the current authorized PMF association. It discards the
unprotected disconnect, sends at most five protected queries, and accepts any
matching outstanding transaction ID from that BSS. Its local policy retries at
204 ms with an approximately 1020 ms bound. Timeout or timer failure closes the
port before attempting asynchronous reauthentication. The AP-only code path is
kept separate. Native association, authorization, and deauthentication snapshots
carry a join epoch; delayed events cannot authorize or tear down a replacement
join, and link-up also requires the current node's live port authorization.

The native card capability enables SAE only when the AX201 firmware/configuration
supports MFP. Native capability bit 75 has been located in both saved Tahoe builds
25G241 and 25G332. An independent native meaning for the old bit-48 PMF comment
has not been proved, so this change does not invent a new bit-48 contract.

## Dev03 review corrections

Dev04 supersedes the independent `88c80fe` Dev03 snapshot. Immediate failed
Join now retires desired SSID/BSSID/DESBSSID and authentication metadata only
for the captured epoch/controller; a replacement request is preserved. Native
version0 scan-list sentinels are accepted only in the final slot. These
corrections have production-body and parser/backend regressions.

## Test120 integration

Dev04 ports the complete Dev02 series onto `dd5913819449b6a9d4d8701531f093d88e9260c8`.
The observed-key wrapper goes through the real PMF main gate and forwards the
same receipt pointer to the installer. Gate rejection returns EAGAIN rather than
the submitted-asynchronous EBUSY result. The installer samples TX PN once for
both command and receipt, retains the Test110 API-3 RX replay-floor encoding,
and keeps the current HCMD submission/response provenance.

The SO-a0-HR-b0-68 command table reports ADD_STA_KEY API 3 (command 0x0117).
The pinned SO68 reverse evidence for MGMT_MCAST_KEY 0x011f uses exactly four
payload bytes containing LE32 status 1; unknown firmware ABI, failed/short/long
responses, timeout and stale command/node/key identities cannot activate IGTK.
These checks validate parsing and host policy offline; no live firmware reply
or protected AP exchange has been observed for Dev04.

The current lifecycle fence, tagged init-task dispatch, MCC and directed-DMA
ownership guards are retained. Shared RX decryption/dispatch, HCMD completion,
common CCMP key install/delete, stop/detach and DMA-owner retention are affected
by the port; ordinary WPA2 and GTK rekey need runtime regression too. Stop/detach still require actual ownership and
quiescence checks; the host tests do not establish unload safety on hardware.
Hidden-network behavior and scan priority are described separately in
[HIDDEN-NETWORKS.md](HIDDEN-NETWORKS.md).

## Offline checks

From the repository root, the portable parser/backend and PMF policy checks are:

```sh
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/wcl_backend.cpp \
  native/tests/wcl_test.cpp -o /tmp/ax201-wcl-test
/tmp/ax201-wcl-test
clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer native/wcl_wire.cpp native/tests/wcl_security_test.cpp \
  -o /tmp/ax201-wcl-security-test
/tmp/ax201-wcl-security-test
clang++ -std=c++14 -Wall -Wextra -Werror \
  native/tests/pmf_crypto_policy_test.cpp -o /tmp/ax201-pmf-policy-test
/tmp/ax201-pmf-policy-test
python3 native/tests/test_native_personal_join.py
python3 native/tests/test_native_security_stop.py
python3 native/tests/test_native_security_events.py
python3 native/tests/test_airport_stop_busy_retains.py
python3 native/tests/test_pmf_production_crypto.py
python3 native/tests/test_pmf_gate_lifecycle.py
python3 native/tests/test_pmf_ack_completion.py
python3 native/tests/test_pmf_reset_retry_body.py
python3 native/tests/test_iwx_transition_gate.py
python3 native/tests/test_sta_sa_query.py
sh third_party/sae/tests/run_host_tests.sh
```

These exercise production function bodies where stated, including SAE state,
credential cleanup, BIP crypto and SA Query. The Hostap Annex J.10 known-answer
vectors independently check H&P and H2E. The EAPOL reference test additionally
requires the hash-pinned Python crypto oracle described in
`native/tests/test_sae_eapol_reference.py`; its primitive adapters and key-wrap
dispatch spies are not the kernel/firmware execution path.

`sh native/tests/run_personal_security.sh` runs these checks together, including
the existing PSK key-material regression. Set `SAE_ORACLE_PYTHON` to the isolated
oracle environment's Python executable. A missing oracle is a failure.

The Tahoe Xcode target builds the pinned SAE C subset into a dedicated archive
to avoid the driver's C++ prefix header. The net80211 wrapper and SHA-2 bridge
use the existing C++ driver ABI. Other targets use fail-closed SAE stubs and do
not link the Tahoe crypto archive. A local MacKernelSDK is required for the
kernel build and is not distributed here.

Hardware acceptance still requires WPA2 regression, WPA3 H&P and H2E APs,
transition mode, required-PMF refusal and acceptance, protected management
frames, rekey/replay/SA Query, reconnect, sleep/wake, and a stable IP/data path.
AirDrop requires its own peer discovery and bidirectional transfer evidence.
