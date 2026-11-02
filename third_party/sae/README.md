# AX201 Native SAE crypto

This directory vendors only the code needed for SAE finite cyclic group 19
(P-256), H&P/H2E password-element derivation, commit/confirm, and PMK output.

## Pinned sources

- Mbed TLS `v3.6.7`, peeled commit `068ff080b369adfac81509f9b57b2afabaf82dc5`
  (2026-07-01). The upstream `LICENSE` provides Apache-2.0 OR
  GPL-2.0-or-later; this repository selects GPL-2.0-or-later. The vendored
  subset is MPI, P-256 ECP, constant-time helpers, and platform utilities.
- Hostap `648d1d225977822ed821d86b7cfd468e74daf752` (BSD license). The SAE and
  Dragonfly state/derivation code is adapted behind a small port layer.

`mbedtls/include/mbedtls/mbedtls_config.h` is a project-specific minimal
configuration. `mbedtls/library/sae_mbedtls_port.c` routes kernel allocations
through `IOMalloc`/`IOFree` and zeroes freed buffers. Kernel entropy is supplied
through the existing `arc4random_buf` adapter in the SAE crypto glue.

The vendored `.c` files are compiled as kernel C by the Tahoe target's
`scripts/build_sae_crypto.sh` phase into `libAX201SAE.a`. This avoids the main
target's C++ prefix header. The net80211 wrapper and SHA-2 bridge retain the
existing driver's C++ ABI. Other targets do not link this archive.

## Ordinary SAE EAPOL contract

This implementation advertises the ordinary SAE AKM selector `00:0f:ac:8`.
Its PTK uses the SHA-256 KDF, while its EAPOL-Key descriptor uses AKM-defined
version 0, AES-CMAC for the MIC, and AES Key Wrap for encrypted key data. This
follows the pinned Hostap `wpa_eapol_key_mic()`, `wpa_use_cmac()`, and
`wpa_use_aes_key_wrap()` behavior. The HMAC-SHA-256 MIC branch belongs to the
separate SAE-EXT-KEY selector and is not part of this group-19 implementation.

## Confirm loss recovery

After validating the AP Confirm, the station moves into `S_ASSOC`. An AP
configured for immediate Confirm can send its Confirm before it has received
the station's Confirm. If an exact duplicate AP Confirm reaches the station
while association is pending, the Tahoe wrapper retransmits its cached local
Confirm, up to three times. It clears the SAE exchange keys before caching,
binds both bodies to the BSSID/local MAC/SSID, and never repeats PMK import or
opens the controlled port. This does not make AP retransmission universal:
Hostapd's infrastructure retransmit timer is disabled, so recovery depends on
the peer actually sending a duplicate Confirm. `S_RUN` drops the retry cache;
timeout/reset/detach and credential replacement clear it and the corresponding
session secrets.

`tests/sae_hostap_kat.c` carries the pinned Hostap IEEE 802.11-2020 Annex J.10
H&P and H2E vectors. `tests/ieee80211_sae_wrapper_test.cpp` compiles and tests
the production net80211 authentication-body wrapper offline.
