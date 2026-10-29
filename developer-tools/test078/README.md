# Test078 host diagnostics source snapshot

This folder preserves the Test078 host-side collector, bounded OpenWrt capture tools, address-free decoders, their Python helpers, and focused host tests. `SOURCE-MANIFEST.json` records original and snapshot hashes; any portability change is stated explicitly.

The native RF collector needs a private runtime workspace with Test078 build/freeze/boot metadata, a loaded Test078 kext, private deployment helpers, macOS IORegistry/network tools, and an authenticated OpenWrt SSH control socket. Those runtime files, logs, captures, credentials, Apple binaries, and build products are excluded. Missing collector prerequisites remain a hard failure.

The [passive OpenWrt batch tool](tools/openwrt_capture_batch.md) uses the included single-window helper and an authenticated SSH control socket. It supports 1–8 independent capture windows, defaults to a dry run, and stops at the first failed window. It does not require a Mac RF claim or start the native collector.

The capture path defaults to disarmed. The collector requires explicit `--arm`, the receiver-gated coordinator, a fresh boot and matching loaded build identity. The coordinator defaults to a dry description and only enters its capture path with explicit `--run`. Keep those gates intact when adapting the tools.

The focused host tests are included as source. The Test078 collector suite has three passing safety checks and one explicit skip when its excluded private template is absent; present but malformed metadata still fails. The pure decoder and OpenWrt coordinator tests have no private-metadata requirement. The passive batch wrapper has 12 mocked tests and was verified against the router on 2026-10-29 with two 12-second windows: each PCAP and cleanup/AP/UCI receipt passed. This verifies repeated passive capture, not native RF, AWDL reception, or AirDrop.

The files retain the source repository's GPL-2.0 licensing. See the repository `LICENSE` for the license text.
