# Read only GP2 register sampler

`IntelGp2Clock::readBracketedGp2` is a small adapter for collecting one raw
GP2 sample with host monotonic timestamps immediately before and after the
PRPH read. The hardware interface is injected by the caller, so the helper
does not touch PCI or make a firmware request itself.

For the local Intel family table, family 22000 uses PRPH `0x00a02c68` and
AX210 uses `0x00d02c68`. The active machine reports family AX210. The local
`iwx_prph_msk` preserves 24 PRPH address bits for AX210, while
`iwx_read_prph` requires the NIC lock and uses the indirect HBUS address,
barrier, and data-read sequence. The mailbox register `IWX_CSR_UCODE_DRV_GP2`
at CSR offset `0x60` is a different register and is not used here.

The Test044 integration uses a dedicated optional acquisition wrapper on the
main command gate. It preserves nested-lock accounting and requests MAC access
with a nominal 2 ms polling budget. A failed request clears MAC_ACCESS_REQ;
scheduler preemption is not bounded by this polling budget. Register reads
occur only after successful acquisition, and release uses iwx_nic_unlock.
The short TX-state spinlock is released before any NIC access or property
publication. An unused ticket and a completed historical ticket are both
compatible with absent queue resources; an incomplete ticket is rejected.

The signed seven-flag manual profile, worker ownership, paused state queue,
healthy associated radio, matching context/power/station generations and
absent resources are required. Samples occur before and after executeOnce,
with a second generation check after sampling. Normal startup does not arm the
probe, and neither RX nor the timing-sensitive PSF/MIF submit callback samples
the register. Sampling failure does not grant clock or scheduling permission.

This helper deliberately does not set clock mapper limits, infer frequency
drift, convert GP2 into host/TSF/AWDL time, or authorize a transmit. A useful
map still needs same-generation samples, measured bracket widths, and a
provenance-backed drift and uncertainty limit. The bracket also does not prove
that GP2 shares an epoch with the peer's AWDL clock.

The sampler and gated adapter are in the Test044 target, enabled only in the
explicit manually armed artifact. Host-only callback tests have passed; the
Test044 register read and radio behavior remain untested until the next boot.
