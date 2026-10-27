# Test053 packet-header correction

Test052 verified automatic resident `awdl0` UP/RUNNING and link-local IPv6
configuration with no manual interface setup. Its single armed RF observation
was interrupted by a DLIL input `M_PKTHDR` assertion. Final data completion/RX
counters and cleanup were not saved, so neither delivery nor cleanup passed.

The adapter had used mbuf_getcluster with a null mbuf. Apple's implementation
allocates that through m_get without a packet header. Test053 instead uses
mbuf_getpacket for both native RX input and raw TX, and verifies MBUF_PKTHDR
before writing packet metadata. Malformed outbound mbufs are also rejected.
The corrected host shim preserves the API distinction: original Test052 code
reaches a controlled missing-header invariant in RX; corrected code passes
ownership/failure cases. This is a host regression, not a kernel panic retest.

Test051 booted with a resident native interface and accepted real IPv6 output
after manual link-local setup. Its single RF session completed PSF/MIF and
received eight PSFs plus one MIF, but submitted no data packets. Inspection
found that the data path reused a pre-binding guard requiring binding ABSENT
while the current ROC binding was ACTIVE. This was a host-side gate failure,
not a firmware rejection or evidence of data interoperability.

Test052 uses an active-ROC guard with matching owner, epochs, healthy station,
idle command/state queues, active MAC and binding, leased PHY, matching live
START and idle completed P2P ring. Numeric gate counters distinguish these
blockers from peer/channel freshness and an empty BSD data queue.

The resident worker sets UP/RUNNING via the public interface KPI, clears raw
transport-incompatible offload capabilities, and configures a link-local IPv6
address derived from the owned AWDL MAC through the standard kernel IPv6
socket ioctl. It verifies address presence and records errors. Outbound framed
IPv6 packets are validated before mbuf_outbound_finalize computes pending
checksum work outside the queue spin lock. Test052 verified automatic interface
configuration; Test053 packet-header correction still needs runtime validation.

The exact 25G332 native lifecycle that passed in Test050 now keeps its object,
framework pools/queues, controller alias and genuine BSD `awdl0` registered.
Creation runs on the existing worker outside the radio gate after STA is ready.
Controller stop fences creation, closes the data adapter, then uses the native
terminate/stop/detach/deregister/free sequence. Ambiguous cleanup retains its owner.

The data adapter attaches an Apple interface filter to this native `awdl0`.
It consumes fully framed outbound IPv6 Ethernet mbufs with `EJUSTRETURN` only
after transferring them into its 32-entry queue. It never forwards them to STA.
The original mbuf is freed exactly once when encoded, expired, or canceled.
IPv6 length, source MAC, destination and MTU are checked; checksum/segmentation
offloads are disabled because the raw Intel path cannot service those requests.
Packets expire after two seconds; a radio-off or generation change cancels them.

Only one manually armed 900 ms firmware session is supported in this candidate.
After successful PSF/MIF completion, a fresh channel-6 peer, a matching START
without END, healthy STA epochs and an idle dedicated P2P ring are required for
at most four real queued data attempts. Encoded ordinary no-DS Data MPDUs use
the AWDL BSSID, Apple LLC/SNAP, AWDL data header and IPv6 payload. Queue TID 15
is retained for the dedicated non-QoS transport; actual firmware acceptance is
still an experiment. TX_CMD v9 FLAGS v3 must not receive the old ACK flag bit.
The normal ring/ticket validator checks the actual frame type, length, queue,
generation and completion SSN before freeing DMA ownership. Firmware response
success is counted separately from kernel acceptance and remote receipt.

Real RX MPDUs with the AWDL BSSID are copied only from a current, successful
channel-6 lease. Protected or stale data is rejected. The existing gate tick
decodes ordinary/QoS/A-MSDU IPv6 data, validates local/group destination, restores
an Ethernet header and passes an owned mbuf to the native interface's `ifnet_input`.
There is no loopback path or synthetic RX packet in the driver. Unknown RX MAC
affinity remains unknown; BSSID plus owned lease/address checks narrow this pilot.

Filter detach is asynchronous: the adapter waits for its final detached callback
and active input calls, and cannot release the interface while a DMA token is
outstanding. Failed completion cannot be retired by a timeout; only a validated
response or a positively established firmware/RX/TX/DMA drain clears that token.

## Proof boundary

Host KPI/DMA shims check production ownership and failure handling, not macOS
dispatch or radio behavior. Kernel SDK compilation and native symbol checks do
not prove framework compatibility. Test053 needs reboot-time resident-interface,
Wi-Fi, real kernel-output, firmware completion and genuine peer-RX verification.
Continuous peer timing/channel scheduling, sustained data transport, IPv6/mDNS
interoperability and bidirectional AirDrop remain unproven. A persistent interface
or a successful local TX command is never sufficient evidence for those features.

## Primary API and wire references

- Apple XNU `bsd/net/kpi_interfacefilter.h`: framed outbound filters, ownership
  on `EJUSTRETURN`, and asynchronous final-detach notification.
  <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/kpi_interfacefilter.h>
- Apple XNU `bsd/net/kpi_interface.h`: `ifnet_input`, interface references,
  offload configuration and native AWDL interface flags.
  <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/kpi_interface.h>
- Apple XNU `bsd/kern/kpi_mbuf.c` and SDK `sys/kpi_mbuf.h`: getcluster with a
  null mbuf does not create a packet header; getpacket explicitly does.
  <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kpi_mbuf.c>
- Intel firmware TX API: `iwl_tx_cmd_flags` v3 differs from the older ACK flags.
  <https://github.com/torvalds/linux/blob/master/drivers/net/wireless/intel/iwlwifi/fw/api/tx.h>
- AWDL wire subset and pinned protocol references: `awdl_data_frame_contract.md`.

No source from the excluded third-party port was copied into this adapter.
