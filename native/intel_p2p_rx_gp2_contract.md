# RX descriptor GP2 preservation

The existing RX descriptor supplies `gp2_on_air_rise`: v1 has a 32-bit
little-endian value and v3 declares `__le32`. `iwx_rx_mpdu_mq` decodes either
with `le32toh` into the existing `device_timestamp`. That value already
travels with reordered MPDUs through `iwx_rx_reorder` and
`iwx_reorder_buf_entry::device_timestamp`; the Tahoe side tap now carries it
to `ActionFrameRecord` with an explicit present bit.

The router exposes only numeric count/last-value diagnostics through
IORegistry. It does not export source addresses or frame payload, read any
hardware register, or pass this descriptor timestamp into the AWDL host-clock
mapper or a TX gate. GP2 and the later host RX monotonic timestamp remain
separate fields. RX descriptor GP2 is an on-air timestamp, while the host
monotonic sample is taken after RX processing; pairing them is not a clock
calibration.

Local evidence:

- `itlwm/hal_iwx/if_iwxreg.h:3650` declares the v1 GP2 field; lines 3728-3730
  identify the v3 field as the GP2 timer at on-air rise.
- `itlwm/hal_iwx/ItlIwx.cpp:6389-6408` selects v3 or v1, decodes the GP2 value,
  carries it through reorder, and calls the ordinary RX input path.
- `itlwm/hal_iwx/ItlIwx.cpp:6214` stores the value in a reorder entry and
  lines 5959-5977 restore it before delivering buffered frames.
- `itlwm/hal_iwx/ItlIwx.cpp:5852-5858` forwards it to the observation-only tap
  while the normal `ieee80211_inputm` path retains packet ownership.

`native/tests/intel_p2p_rx_router_test.cpp` checks raw value and present-bit
preservation plus absence clearing. `native/tests/test_iwx_p2p_rx_tap.py`
checks both little-endian descriptor reads, reorder storage/restore, and the
real RX method's pass-through while retaining its STA input behavior.
