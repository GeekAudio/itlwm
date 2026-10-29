# Test078 host diagnostics source snapshot

This folder preserves the Test078 host-side collector, bounded OpenWrt capture coordinator, address-free decoders, their Python helpers, and focused host tests. `SOURCE-MANIFEST.json` maps every copied source file to its original relative path and SHA-256. The copied files are byte-identical to those sources.

This is a source snapshot for review and evidence preservation. It is **not a directly runnable clone**. The original tools expect a private runtime workspace with Test078 build/freeze/boot metadata, a loaded Test078 kext, the private helper executables installed by the deployment workflow, macOS IORegistry and network tools, and an authenticated OpenWrt SSH control socket. None of those runtime files, logs, captures, credentials, Apple binaries, or build products are included here. Restore those inputs only through the authorized private runtime workflow; missing inputs must remain a hard failure.

The capture path defaults to disarmed. The collector requires explicit `--arm`, the receiver-gated coordinator, a fresh boot and matching loaded build identity. The coordinator defaults to a dry description and only enters its capture path with explicit `--run`. Keep those gates intact when adapting the tools.

The focused host tests are included as source. In this public snapshot, the Test078 collector suite has three passing safety checks and one explicit skip: its template-specific test skips only when the excluded `research/test078-next-boot-private.json` file is absent. If that file is present, the same test continues to validate its disarmed state and build/source manifest; malformed or incomplete metadata still fails. The other three collector safety checks remain active. The pure decoder and OpenWrt coordinator tests have no private-metadata requirement. This snapshot has not been built as a product, run against a machine, or used for an RF observation.

The files retain the source repository's GPL-2.0 licensing. See the repository `LICENSE` for the license text.
