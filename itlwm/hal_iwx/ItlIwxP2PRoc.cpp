/*
 * Tahoe Intel P2P ROC firmware resource adapter.
 *
 * Sessions default to 100 ms / 20 MHz. A single 900 ms management-TX window
 * is allowed only on a legally bound social channel 6 P2P PHY. The opt-in
 * 149 observation session is 100 ms, Device Discovery only, and TX guarded.
 * Same-channel sessions remain supported; other off-channel targets fail closed.
 */
#include "ItlIwx.hpp"
#include "tahoe_p2p_roc_observation_policy.hpp"
#include <stddef.h>

#ifdef AIRPORT_TAHOE

namespace {

static const uint32_t kTahoeRocDurationMs = 100;
static const uint32_t kTahoeSocialTxRocDurationMs = 900;

static bool
tahoeP2pRocIsReceiveObservationOnly(const struct iwx_p2p_roc_state &roc)
{
    return __atomic_load_n(&roc.receive_observation_only, __ATOMIC_ACQUIRE) != 0;
}

static void
tahoeP2pRocResetState(struct iwx_p2p_roc_state &roc)
{
    memset(&roc, 0, offsetof(struct iwx_p2p_roc_state,
                             receive_observation_only));
    __atomic_store_n(&roc.receive_observation_only, 0, __ATOMIC_RELEASE);
}

static uint8_t
tahoeP2pRocAntennaCount(uint8_t mask)
{
    uint8_t count = 0;
    for (uint8_t bit = 1; bit != 0; bit <<= 1)
        count += (mask & bit) != 0;
    return count;
}

static int
tahoeP2pRocPhyCommand(ItlIwx *owner, struct iwx_softc *sc,
                      struct iwx_phy_ctxt *phy,
                      struct ieee80211_channel *channel,
                      uint32_t action)
{
    if (owner == NULL || sc == NULL || phy == NULL || channel == NULL)
        return EINVAL;
    if (owner->iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP,
                                  IWX_PHY_CONTEXT_CMD) != 3)
        return EOPNOTSUPP;

    struct iwx_phy_context_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(phy->id,
                                                       phy->color));
    cmd.action = htole32(action);
    cmd.lmac_id = htole32(owner->iwx_lmac_id(sc, channel));
    cmd.ci.band = IEEE80211_IS_CHAN_2GHZ(channel) ?
        IWX_PHY_BAND_24 : IWX_PHY_BAND_5;
    cmd.ci.channel = htole32(ieee80211_chan2ieee(&sc->sc_ic, channel));
    cmd.ci.width = IWX_PHY_VHT_CHANNEL_MODE20;
    cmd.ci.ctrl_pos = IWX_PHY_VHT_CTRL_POS_1_BELOW;

    /* Match the existing PHY context chain policy without reading STA width. */
    const uint8_t rxAnt = owner->iwx_fw_valid_rx_ant(sc);
    uint8_t idleCount = 1;
    uint8_t activeCount = 1;
    if (tahoeP2pRocAntennaCount(rxAnt) != 1) {
        idleCount = 2;
        activeCount = 2;
    }
    cmd.rxchain_info = htole32(rxAnt << IWX_PHY_RX_CHAIN_VALID_POS);
    cmd.rxchain_info |= htole32(idleCount << IWX_PHY_RX_CHAIN_CNT_POS);
    cmd.rxchain_info |= htole32(activeCount <<
                                IWX_PHY_RX_CHAIN_MIMO_CNT_POS);

    return owner->iwx_send_cmd_pdu(sc, IWX_PHY_CONTEXT_CMD, 0,
                                   sizeof(cmd), &cmd);
}

static int
tahoeP2pRocRestorePhy(
    ItlIwx *owner, struct iwx_softc *sc,
    struct iwx_p2p_roc_prepare_trace *prepareTrace = NULL)
{
    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    if (roc.phy_id >= IWX_NUM_PHY_CTX ||
        roc.original_phy_channel == NULL || roc.roc_channel == NULL)
        return EINVAL;

    struct iwx_phy_ctxt *phy = &sc->sc_phyctxt[roc.phy_id];
    roc.phase = IWX_P2P_ROC_PHY_RESTORE_REMOVE_UNKNOWN;
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace, IWX_P2P_TRACE_step,
            IWX_P2P_PREPARE_STEP_RESTORE_PHY_REMOVE);
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreRemoveAttempted, 1U);
    }
    int error = tahoeP2pRocPhyCommand(owner, sc, phy, roc.roc_channel,
                                      IWX_FW_CTXT_ACTION_REMOVE);
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreRemoveReturned, 1U);
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreRemoveResult, static_cast<uint32_t>(error));
    }
    if (error)
        return error;

    roc.phase = IWX_P2P_ROC_PHY_RESTORE_ADD_UNKNOWN;
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace, IWX_P2P_TRACE_step,
            IWX_P2P_PREPARE_STEP_RESTORE_PHY_ADD);
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreAddAttempted, 1U);
    }
    error = tahoeP2pRocPhyCommand(owner, sc, phy,
                                  roc.original_phy_channel,
                                  IWX_FW_CTXT_ACTION_ADD);
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreAddReturned, 1U);
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_restoreAddResult, static_cast<uint32_t>(error));
    }
    if (error)
        return error;

    phy->channel = roc.original_phy_channel;
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_phyReleaseAttempted, 1U);
    }
    error = owner->iwx_p2p_phy_release(sc);
    if (prepareTrace != NULL) {
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_phyReleaseReturned, 1U);
        iwx_p2p_roc_prepare_trace_store(prepareTrace,
            IWX_P2P_TRACE_phyReleaseResult, static_cast<uint32_t>(error));
    }
    if (error)
        return error;
    roc.phase = IWX_P2P_ROC_COMPLETE;
    return 0;
}

static uint32_t
tahoeP2pMsecToTu(uint32_t milliseconds)
{
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(milliseconds) * 1000u) / 1024u);
}

static bool
tahoeP2pRocConfigurationSupported(uint32_t configuration)
{
    return configuration == IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV ||
           configuration == IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION;
}

static bool
tahoeP2pRocChannelPointerInTable(struct ieee80211com *ic,
                                struct ieee80211_channel *channel)
{
    if (ic == NULL || channel == NULL)
        return false;
    for (u_int index = 1; index <= IEEE80211_CHAN_MAX; ++index) {
        if (&ic->ic_channels[index] == channel)
            return true;
    }
    return false;
}

static bool
tahoeP2pRocCurrentChannelIndex(struct ieee80211com *ic,
                               struct ieee80211_channel *channel,
                               u_int *channelIndex)
{
    if (ic == NULL || channel == NULL || channelIndex == NULL)
        return false;

    /* Avoid ieee80211_chan2ieee() on a foreign pointer: that routine logs a
     * bogus pointer and returns channel 1. Pointer equality is safe here. */
    for (u_int index = 1; index <= IEEE80211_CHAN_MAX; ++index) {
        if (&ic->ic_channels[index] != channel)
            continue;
        if (ieee80211_chan2ieee(ic, channel) != index)
            return false;
        *channelIndex = index;
        return true;
    }
    return false;
}

static bool
tahoeP2pRocSocialChannel6Allowed(struct ieee80211com *ic,
                                 struct ieee80211_channel *channel)
{
    if (ic == NULL || channel == NULL ||
        channel != &ic->ic_channels[6] ||
        !IEEE80211_IS_CHAN_2GHZ(channel) ||
        ieee80211_chan2ieee(ic, channel) != 6 ||
        channel->ic_freq != 2437 || channel->ic_flags == 0 ||
        (channel->ic_flags & (IEEE80211_CHAN_DFS |
                              IEEE80211_CHAN_PASSIVE)) != 0)
        return false;

    return true;
}

static bool
tahoeP2pRocOffChannelAllowed(struct ieee80211com *ic,
                            struct ieee80211_channel *channel,
                            uint32_t configuration)
{
    if (!tahoeP2pRocConfigurationSupported(configuration))
        return false;
    return tahoeP2pRocSocialChannel6Allowed(ic, channel);
}

static bool
tahoeP2pRocLongSocialTxAllowed(struct iwx_softc *sc,
                               const struct iwx_p2p_roc_state &roc,
                               uint32_t configuration)
{
    if (sc == NULL ||
        configuration != IWX_SESSION_PROTECT_CONF_P2P_GO_NEGOTIATION ||
        roc.phy_id != 1 || roc.roc_channel == NULL)
        return false;

    u_int channelIndex = 0;
    if (!tahoeP2pRocCurrentChannelIndex(&sc->sc_ic, roc.roc_channel,
                                        &channelIndex) ||
        channelIndex != 6 ||
        !tahoeP2pRocSocialChannel6Allowed(&sc->sc_ic, roc.roc_channel))
        return false;

    const struct iwx_phy_ctxt *phy = &sc->sc_phyctxt[1];
    return sc->sc_p2p.initialized &&
        sc->sc_p2p.fw_generation == roc.fw_generation &&
        sc->sc_p2p.phy_leased &&
        sc->sc_p2p.phy_id == 1 &&
        sc->sc_p2p.mac_id == 1 &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.binding_id == 1 &&
        sc->sc_p2p.phy_color == roc.phy_color &&
        sc->sc_p2p.binding_color == roc.phy_color &&
        phy->id == 1 && phy->color == roc.phy_color &&
        phy->channel == roc.roc_channel;
}

static TahoeP2PRocObservationPolicy::Channel
tahoeP2pRocObservationChannel(struct ieee80211_channel *channel,
                              u_int channelIndex)
{
    TahoeP2PRocObservationPolicy::Channel policyChannel = {};
    policyChannel.index = channelIndex;
    policyChannel.frequencyMHz = channel != NULL ? channel->ic_freq : 0;
    policyChannel.is5GHz = channel != NULL &&
        IEEE80211_IS_CHAN_5GHZ(channel);
    policyChannel.is2GHz = channel != NULL &&
        IEEE80211_IS_CHAN_2GHZ(channel);
    policyChannel.hasFlags = channel != NULL && channel->ic_flags != 0;
    policyChannel.isDfs = channel != NULL &&
        (channel->ic_flags & IEEE80211_CHAN_DFS) != 0;
    policyChannel.isPassive = channel != NULL &&
        (channel->ic_flags & IEEE80211_CHAN_PASSIVE) != 0;
    return policyChannel;
}

static bool
tahoeP2pRocObservation149PrepareAllowed(
    struct ieee80211_channel *channel, u_int channelIndex,
    uint32_t configuration, bool requested)
{
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    const bool featureCompiled = true;
#else
    const bool featureCompiled = false;
#endif
    return TahoeP2PRocObservationPolicy::prepareAllowed(
        featureCompiled, requested,
        configuration == IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV,
        tahoeP2pRocObservationChannel(channel, channelIndex));
}

static bool
tahoeP2pRocObservation149SubmitAllowed(
    const struct iwx_p2p_roc_state &roc, uint32_t configuration,
    uint32_t durationMs, u_int channelIndex)
{
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    const bool featureCompiled = true;
#else
    const bool featureCompiled = false;
#endif
    return TahoeP2PRocObservationPolicy::submitAllowed(
        featureCompiled, tahoeP2pRocIsReceiveObservationOnly(roc),
        configuration == IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV,
        durationMs,
        tahoeP2pRocObservationChannel(roc.roc_channel, channelIndex));
}

static bool
tahoeP2pRocObservationOwnerValid(struct iwx_softc *sc,
                                const struct iwx_p2p_roc_state &roc,
                                uint8_t expectedBindingState)
{
    if (sc == NULL || !tahoeP2pRocIsReceiveObservationOnly(roc))
        return false;
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    if (roc.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        roc.station_epoch != __atomic_load_n(&sc->sc_tx_rate_generation,
                                             __ATOMIC_ACQUIRE) ||
        sc->sc_ic.ic_state != IEEE80211_S_RUN || sc->sc_ic.ic_bss == NULL ||
        static_cast<void *>(sc->sc_ic.ic_bss) != roc.station_bss ||
        roc.station_phy_id != 0 || roc.station_phy_id >= IWX_NUM_PHY_CTX ||
        roc.station_phy_channel == NULL || roc.phy_id != 1 ||
        roc.phy_id >= IWX_NUM_PHY_CTX || roc.roc_channel == NULL)
        return false;

    const struct iwx_node *station =
        reinterpret_cast<const struct iwx_node *>(sc->sc_ic.ic_bss);
    const struct iwx_phy_ctxt *stationPhy = &sc->sc_phyctxt[0];
    const struct iwx_phy_ctxt *p2pPhy = &sc->sc_phyctxt[roc.phy_id];
    return station->in_phyctxt == stationPhy &&
        station->in_phyctxt->id == roc.station_phy_id &&
        station->in_phyctxt->color == roc.station_phy_color &&
        station->in_ni.ni_chan == roc.station_phy_channel &&
        stationPhy->id == roc.station_phy_id &&
        stationPhy->color == roc.station_phy_color &&
        stationPhy->channel == roc.station_phy_channel &&
        sc->sc_p2p.initialized &&
        sc->sc_p2p.fw_generation == roc.fw_generation &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.mac_id == 1 && sc->sc_p2p.phy_leased &&
        sc->sc_p2p.phy_id == roc.phy_id &&
        sc->sc_p2p.binding_id == roc.phy_id &&
        sc->sc_p2p.phy_color == roc.phy_color &&
        sc->sc_p2p.binding_color == roc.phy_color &&
        sc->sc_p2p.binding_state == expectedBindingState &&
        p2pPhy->id == roc.phy_id && p2pPhy->color == roc.phy_color &&
        p2pPhy->channel == roc.roc_channel;
#else
    (void)expectedBindingState;
    return false;
#endif
}

} // namespace

int ItlIwx::
tahoeP2pRocPrepare(struct iwx_softc *sc,
                    struct ieee80211_channel *channel,
                    uint32_t token, uint32_t configuration,
                    bool receiveObservation149)
{
    /* Attribute invalid callers to this driver's own softc; never deref the
     * foreign argument just to explain why it was rejected. */
    if (sc == NULL || sc != &com) {
        struct iwx_p2p_roc_prepare_trace &invalidTrace =
            com.sc_p2p_roc_prepare_trace;
        const uint32_t invalidSerial =
            iwx_p2p_roc_prepare_trace_begin(&invalidTrace);
        if (invalidSerial != 0) {
            const auto setInvalid = [&invalidTrace](
                enum iwx_p2p_roc_prepare_trace_field field, uint32_t value) {
                iwx_p2p_roc_prepare_trace_store(&invalidTrace, field, value);
            };
            setInvalid(IWX_P2P_TRACE_serial, invalidSerial);
            setInvalid(IWX_P2P_TRACE_token, token);
            setInvalid(IWX_P2P_TRACE_configuration, configuration);
            setInvalid(IWX_P2P_TRACE_receiveObservation149,
                       receiveObservation149 ? 1U : 0U);
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
            setInvalid(IWX_P2P_TRACE_featureCompiled, 1U);
#else
            setInvalid(IWX_P2P_TRACE_featureCompiled, 0U);
#endif
            setInvalid(IWX_P2P_TRACE_step, IWX_P2P_PREPARE_STEP_ARGUMENT);
            setInvalid(IWX_P2P_TRACE_reason, sc == NULL ?
                IWX_P2P_PREPARE_REASON_NULL_SOFTC :
                IWX_P2P_PREPARE_REASON_WRONG_SOFTC);
            setInvalid(IWX_P2P_TRACE_prepareErrno, EINVAL);
            setInvalid(IWX_P2P_TRACE_scGenerationEntry,
                       static_cast<uint32_t>(com.sc_generation));
            setInvalid(IWX_P2P_TRACE_scGenerationExit,
                       static_cast<uint32_t>(com.sc_generation));
            setInvalid(IWX_P2P_TRACE_p2pFirmwareGenerationEntry,
                       com.sc_p2p.fw_generation);
            setInvalid(IWX_P2P_TRACE_p2pFirmwareGenerationExit,
                       com.sc_p2p.fw_generation);
            setInvalid(IWX_P2P_TRACE_stationEpochEntry,
                       __atomic_load_n(&com.sc_tx_rate_generation,
                                       __ATOMIC_ACQUIRE));
            setInvalid(IWX_P2P_TRACE_stationEpochExit,
                       __atomic_load_n(&com.sc_tx_rate_generation,
                                       __ATOMIC_ACQUIRE));
            setInvalid(IWX_P2P_TRACE_prePhase, com.sc_p2p_roc.phase);
            setInvalid(IWX_P2P_TRACE_postPhase, com.sc_p2p_roc.phase);
            setInvalid(IWX_P2P_TRACE_preBindingState,
                       com.sc_p2p.binding_state);
            setInvalid(IWX_P2P_TRACE_postBindingState,
                       com.sc_p2p.binding_state);
            setInvalid(IWX_P2P_TRACE_prePhyLeased, com.sc_p2p.phy_leased);
            setInvalid(IWX_P2P_TRACE_postPhyLeased, com.sc_p2p.phy_leased);
            setInvalid(IWX_P2P_TRACE_sessionSubmitAttempted, 0U);
            setInvalid(IWX_P2P_TRACE_ownerEpochsUnchanged, 0U);
            setInvalid(IWX_P2P_TRACE_bindingKnownAbsent, 0U);
            setInvalid(IWX_P2P_TRACE_phyKnownUnleased, 0U);
            setInvalid(IWX_P2P_TRACE_phaseKnownIdle, 0U);
            setInvalid(IWX_P2P_TRACE_knownNotSubmittedSafeToAbort, 0U);
            setInvalid(IWX_P2P_TRACE_fullyRestored, 0U);
            iwx_p2p_roc_prepare_trace_finish(&invalidTrace);
        }
        return EINVAL;
    }

    struct iwx_p2p_roc_prepare_trace &trace =
        sc->sc_p2p_roc_prepare_trace;
    const uint32_t serial = iwx_p2p_roc_prepare_trace_begin(&trace);
    if (serial == 0)
        return EBUSY;
    const auto traceSet = [&trace](enum iwx_p2p_roc_prepare_trace_field field,
                                   uint32_t value) {
        iwx_p2p_roc_prepare_trace_store(&trace, field, value);
    };
    traceSet(IWX_P2P_TRACE_serial, serial);
    traceSet(IWX_P2P_TRACE_token, token);
    traceSet(IWX_P2P_TRACE_configuration, configuration);
    traceSet(IWX_P2P_TRACE_receiveObservation149,
             receiveObservation149 ? 1U : 0U);
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    traceSet(IWX_P2P_TRACE_featureCompiled, 1U);
#else
    traceSet(IWX_P2P_TRACE_featureCompiled, 0U);
#endif
    traceSet(IWX_P2P_TRACE_prepareErrno, EINPROGRESS);
    traceSet(IWX_P2P_TRACE_cleanupErrno, 0U);
    traceSet(IWX_P2P_TRACE_sessionSubmitAttempted, 0U);

    const uint32_t entryScGeneration = static_cast<uint32_t>(sc->sc_generation);
    const uint32_t entryP2pGeneration = sc->sc_p2p.fw_generation;
    const uint32_t entryP2pInitialized = sc->sc_p2p.initialized;
    const uint32_t entryP2pMacState = sc->sc_p2p.mac_state;
    const uint32_t entryP2pMacId = sc->sc_p2p.mac_id;
    const uint32_t entryP2pMacColor = sc->sc_p2p.mac_color;
    const uint32_t entryP2pBindingId = sc->sc_p2p.binding_id;
    const uint32_t entryP2pBindingColor = sc->sc_p2p.binding_color;
    const uint32_t entryStationEpoch = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    const void *const entryBssRaw = sc->sc_ic.ic_bss;
    const struct iwx_phy_ctxt *entryStationPhy = NULL;
    struct ieee80211_channel *entryStationChannel = NULL;
    struct ieee80211_channel *entryStationPhyChannel = NULL;
    uint32_t entryStationId = 0;
    uint32_t entryStationPhyId = 0xffU;
    uint32_t entryStationPhyColor = 0;
    uint32_t entryStationPhyChannelFrequency = 0;
    uint32_t entryStationChannelFrequency = 0;
    bool stationDetailsCaptured = false;
    bool stationChannelDetailsCaptured = false;
    struct ieee80211_channel *const entryP2pChannel =
        sc->sc_phyctxt[1].channel;
    const auto traceState = [sc]() {
        iwx_p2p_roc_prepare_trace_store(&sc->sc_p2p_roc_prepare_trace,
            IWX_P2P_TRACE_postPhase, sc->sc_p2p_roc.phase);
        iwx_p2p_roc_prepare_trace_store(&sc->sc_p2p_roc_prepare_trace,
            IWX_P2P_TRACE_postBindingState, sc->sc_p2p.binding_state);
        iwx_p2p_roc_prepare_trace_store(&sc->sc_p2p_roc_prepare_trace,
            IWX_P2P_TRACE_postPhyLeased, sc->sc_p2p.phy_leased);
        iwx_p2p_roc_prepare_trace_store(&sc->sc_p2p_roc_prepare_trace,
            IWX_P2P_TRACE_postPhyId, sc->sc_p2p.phy_id);
        iwx_p2p_roc_prepare_trace_store(&sc->sc_p2p_roc_prepare_trace,
            IWX_P2P_TRACE_postPhyColor, sc->sc_p2p.phy_color);
    };
    traceSet(IWX_P2P_TRACE_scGenerationEntry, entryScGeneration);
    traceSet(IWX_P2P_TRACE_scGenerationExit, entryScGeneration);
    traceSet(IWX_P2P_TRACE_p2pFirmwareGenerationEntry, entryP2pGeneration);
    traceSet(IWX_P2P_TRACE_p2pFirmwareGenerationExit, entryP2pGeneration);
    traceSet(IWX_P2P_TRACE_p2pInitializedEntry, entryP2pInitialized);
    traceSet(IWX_P2P_TRACE_p2pInitializedExit, entryP2pInitialized);
    traceSet(IWX_P2P_TRACE_p2pMacStateEntry, entryP2pMacState);
    traceSet(IWX_P2P_TRACE_p2pMacStateExit, entryP2pMacState);
    traceSet(IWX_P2P_TRACE_p2pMacIdEntry, entryP2pMacId);
    traceSet(IWX_P2P_TRACE_p2pMacIdExit, entryP2pMacId);
    traceSet(IWX_P2P_TRACE_p2pMacColorEntry, entryP2pMacColor);
    traceSet(IWX_P2P_TRACE_p2pMacColorExit, entryP2pMacColor);
    traceSet(IWX_P2P_TRACE_p2pBindingIdEntry, entryP2pBindingId);
    traceSet(IWX_P2P_TRACE_p2pBindingIdExit, entryP2pBindingId);
    traceSet(IWX_P2P_TRACE_p2pBindingColorEntry, entryP2pBindingColor);
    traceSet(IWX_P2P_TRACE_p2pBindingColorExit, entryP2pBindingColor);
    traceSet(IWX_P2P_TRACE_stationEpochEntry, entryStationEpoch);
    traceSet(IWX_P2P_TRACE_stationEpochExit, entryStationEpoch);
    traceSet(IWX_P2P_TRACE_stationPresentEntry, entryBssRaw != NULL);
    traceSet(IWX_P2P_TRACE_stationPresentExit, entryBssRaw != NULL);
    traceSet(IWX_P2P_TRACE_stationDetailsCapturedEntry, 0U);
    traceSet(IWX_P2P_TRACE_stationDetailsCapturedExit, 0U);
    traceSet(IWX_P2P_TRACE_stationChannelDetailsCapturedEntry, 0U);
    traceSet(IWX_P2P_TRACE_stationChannelDetailsCapturedExit, 0U);
    traceSet(IWX_P2P_TRACE_prePhase, sc->sc_p2p_roc.phase);
    traceSet(IWX_P2P_TRACE_postPhase, sc->sc_p2p_roc.phase);
    traceSet(IWX_P2P_TRACE_preBindingState, sc->sc_p2p.binding_state);
    traceSet(IWX_P2P_TRACE_postBindingState, sc->sc_p2p.binding_state);
    traceSet(IWX_P2P_TRACE_prePhyLeased, sc->sc_p2p.phy_leased);
    traceSet(IWX_P2P_TRACE_postPhyLeased, sc->sc_p2p.phy_leased);
    traceSet(IWX_P2P_TRACE_prePhyId, sc->sc_p2p.phy_id);
    traceSet(IWX_P2P_TRACE_postPhyId, sc->sc_p2p.phy_id);
    traceSet(IWX_P2P_TRACE_prePhyColor, sc->sc_p2p.phy_color);
    traceSet(IWX_P2P_TRACE_postPhyColor, sc->sc_p2p.phy_color);
    const auto finish = [&, entryP2pChannel, entryBssRaw,
                         entryScGeneration, entryP2pGeneration,
                         entryStationEpoch](uint32_t step, uint32_t reason,
                                            int prepareError,
                                            int cleanupError) {
        traceSet(IWX_P2P_TRACE_step, step);
        traceSet(IWX_P2P_TRACE_reason, reason);
        traceSet(IWX_P2P_TRACE_prepareErrno,
                 static_cast<uint32_t>(prepareError));
        traceSet(IWX_P2P_TRACE_cleanupErrno,
                 static_cast<uint32_t>(cleanupError));
        const void *const exitBssRaw = sc->sc_ic.ic_bss;
        const uint32_t exitStationEpoch = __atomic_load_n(
            &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
        const uint32_t exitP2pGeneration = sc->sc_p2p.fw_generation;
        const uint32_t exitP2pInitialized = sc->sc_p2p.initialized;
        const uint32_t exitP2pMacState = sc->sc_p2p.mac_state;
        const uint32_t exitP2pMacId = sc->sc_p2p.mac_id;
        const uint32_t exitP2pMacColor = sc->sc_p2p.mac_color;
        const uint32_t exitP2pBindingState = sc->sc_p2p.binding_state;
        const uint32_t exitP2pBindingId = sc->sc_p2p.binding_id;
        const uint32_t exitP2pBindingColor = sc->sc_p2p.binding_color;
        const uint32_t exitScGeneration =
            static_cast<uint32_t>(sc->sc_generation);
        const bool exitOwnerSnapshotValid = nativeP2pCommandAllowed() &&
            sc->sc_ic.ic_state == IEEE80211_S_RUN &&
            exitScGeneration == entryScGeneration &&
            exitP2pGeneration == entryP2pGeneration &&
            exitP2pGeneration == exitScGeneration &&
            exitStationEpoch == entryStationEpoch &&
            exitP2pInitialized == entryP2pInitialized &&
            exitP2pInitialized != 0 &&
            exitP2pMacState == entryP2pMacState &&
            exitP2pMacState == IWX_P2P_RESOURCE_ACTIVE &&
            exitP2pMacId == entryP2pMacId && exitP2pMacId == 1 &&
            exitP2pMacColor == entryP2pMacColor &&
            (sc->sc_flags & (IWX_FLAG_MAC_ACTIVE |
                             IWX_FLAG_BINDING_ACTIVE)) ==
                (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE) &&
            (exitP2pBindingState == IWX_P2P_RESOURCE_ABSENT ||
             exitP2pBindingState == IWX_P2P_RESOURCE_ACTIVE) &&
            exitBssRaw == entryBssRaw && stationDetailsCaptured;
        const struct iwx_node *exitStation = NULL;
        const struct iwx_phy_ctxt *exitStationPhy = NULL;
        struct ieee80211_channel *exitStationChannel = NULL;
        uint32_t exitStationId = 0;
        uint32_t exitStationPhyId = 0xffU;
        uint32_t exitStationPhyColor = 0;
        uint32_t exitStationPhyChannelFrequency = 0;
        uint32_t exitStationChannelFrequency = 0;
        struct ieee80211_channel *exitStationPhyChannel = NULL;
        bool exitStationDetailsCaptured = false;
        bool exitStationChannelDetailsCaptured = false;
        if (exitOwnerSnapshotValid) {
            /* Revalidate lifecycle and owner epochs before touching BSS. */
            exitStation = static_cast<const struct iwx_node *>(exitBssRaw);
            exitStationPhy = exitStation->in_phyctxt;
            exitStationChannel = exitStation->in_ni.ni_chan;
            exitStationId = exitStation->in_id;
            if (exitStationPhy == entryStationPhy &&
                entryStationPhy == &sc->sc_phyctxt[0]) {
                exitStationPhyId = exitStationPhy->id;
                exitStationPhyColor = exitStationPhy->color;
                exitStationPhyChannel = exitStationPhy->channel;
                exitStationDetailsCaptured = true;
            }
            if (exitStationPhy == entryStationPhy &&
                exitStationChannel == entryStationChannel &&
                stationChannelDetailsCaptured &&
                tahoeP2pRocChannelPointerInTable(
                    &sc->sc_ic, exitStationChannel) &&
                tahoeP2pRocChannelPointerInTable(
                    &sc->sc_ic, exitStationPhyChannel)) {
                exitStationChannelFrequency = exitStationChannel->ic_freq;
                exitStationPhyChannelFrequency =
                    exitStationPhyChannel->ic_freq;
                exitStationChannelDetailsCaptured =
                    exitStationChannelFrequency != 0 &&
                    exitStationPhyChannelFrequency != 0;
            }
        }
        traceSet(IWX_P2P_TRACE_scGenerationExit, exitScGeneration);
        traceSet(IWX_P2P_TRACE_p2pFirmwareGenerationExit, exitP2pGeneration);
        traceSet(IWX_P2P_TRACE_p2pInitializedExit, exitP2pInitialized);
        traceSet(IWX_P2P_TRACE_p2pMacStateExit, exitP2pMacState);
        traceSet(IWX_P2P_TRACE_p2pMacIdExit, exitP2pMacId);
        traceSet(IWX_P2P_TRACE_p2pMacColorExit, exitP2pMacColor);
        traceSet(IWX_P2P_TRACE_p2pBindingIdExit, exitP2pBindingId);
        traceSet(IWX_P2P_TRACE_p2pBindingColorExit, exitP2pBindingColor);
        traceSet(IWX_P2P_TRACE_stationEpochExit, exitStationEpoch);
        traceSet(IWX_P2P_TRACE_stationPresentExit, exitBssRaw != NULL);
        traceSet(IWX_P2P_TRACE_stationDetailsCapturedExit,
                 exitStationDetailsCaptured);
        traceSet(IWX_P2P_TRACE_stationChannelDetailsCapturedExit,
                 exitStationChannelDetailsCaptured);
        traceSet(IWX_P2P_TRACE_stationIdExit, exitStationId);
        traceSet(IWX_P2P_TRACE_stationColorExit, exitStationPhyColor);
        traceSet(IWX_P2P_TRACE_stationPhyIdExit, exitStationPhyId);
        traceSet(IWX_P2P_TRACE_stationPhyColorExit, exitStationPhyColor);
        traceSet(IWX_P2P_TRACE_stationChannelFrequencyExit,
                 exitStationChannelFrequency);
        traceSet(IWX_P2P_TRACE_restoredChannelDetailsCaptured, 0U);
        traceSet(IWX_P2P_TRACE_restoredChannelFrequency, 0U);
        struct ieee80211_channel *const restoredChannel =
            sc->sc_phyctxt[1].channel;
        if (tahoeP2pRocChannelPointerInTable(
                &sc->sc_ic, restoredChannel)) {
            const uint32_t restoredFrequency = restoredChannel->ic_freq;
            if (restoredFrequency != 0) {
                traceSet(IWX_P2P_TRACE_restoredChannelDetailsCaptured, 1U);
                traceSet(IWX_P2P_TRACE_restoredChannelFrequency,
                         restoredFrequency);
            }
        }
        traceState();

        const bool scGenerationUnchanged =
            entryScGeneration == exitScGeneration;
        const bool p2pGenerationUnchanged =
            entryP2pGeneration == exitP2pGeneration;
        const bool p2pContextUnchanged =
            entryP2pInitialized == exitP2pInitialized &&
            entryP2pMacState == exitP2pMacState &&
            entryP2pMacId == exitP2pMacId &&
            entryP2pMacColor == exitP2pMacColor;
        const bool stationEpochUnchanged =
            entryStationEpoch == exitStationEpoch;
        const bool bssIdentityUnchanged =
            entryBssRaw == exitBssRaw && stationDetailsCaptured &&
            exitStationDetailsCaptured;
        const bool stationIdUnchanged =
            entryStationId == exitStationId;
        const bool stationPhyIdUnchanged =
            entryStationPhyId == exitStationPhyId;
        const bool stationPhyColorUnchanged =
            entryStationPhyColor == exitStationPhyColor;
        const bool stationPhyChannelUnchanged =
            entryStationPhyChannel == exitStationPhyChannel &&
            stationChannelDetailsCaptured &&
            exitStationChannelDetailsCaptured &&
            entryStationPhyChannelFrequency ==
                exitStationPhyChannelFrequency;
        const bool stationPhyIdentityUnchanged =
            entryStationPhy == exitStationPhy &&
            stationPhyIdUnchanged && stationPhyColorUnchanged &&
            stationPhyChannelUnchanged;
        const bool stationChannelIdentityUnchanged =
            entryStationChannel == exitStationChannel &&
            stationChannelDetailsCaptured &&
            exitStationChannelDetailsCaptured &&
            entryStationChannelFrequency == exitStationChannelFrequency;
        const bool ownerUnchanged = scGenerationUnchanged &&
            p2pGenerationUnchanged && p2pContextUnchanged &&
            stationEpochUnchanged &&
            bssIdentityUnchanged && stationIdUnchanged &&
            stationPhyIdentityUnchanged && stationChannelIdentityUnchanged;
        traceSet(IWX_P2P_TRACE_ownerScGenerationUnchanged,
                 scGenerationUnchanged);
        traceSet(IWX_P2P_TRACE_ownerP2pFirmwareGenerationUnchanged,
                 p2pGenerationUnchanged);
        traceSet(IWX_P2P_TRACE_ownerP2pMacContextUnchanged,
                 p2pContextUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationEpochUnchanged,
                 stationEpochUnchanged);
        traceSet(IWX_P2P_TRACE_ownerBssIdentityUnchanged,
                 bssIdentityUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationIdUnchanged,
                 stationIdUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationPhyIdentityUnchanged,
                 stationPhyIdentityUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationPhyIdUnchanged,
                 stationPhyIdUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationPhyColorUnchanged,
                 stationPhyColorUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationPhyChannelUnchanged,
                 stationPhyChannelUnchanged);
        traceSet(IWX_P2P_TRACE_ownerStationChannelIdentityUnchanged,
                 stationChannelIdentityUnchanged);
        const bool bindingAbsent =
            sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT;
        const bool phyUnleased = sc->sc_p2p.phy_leased == 0;
        const bool phaseIdle = sc->sc_p2p_roc.phase == IWX_P2P_ROC_IDLE;
        const bool noSessionSubmit =
            iwx_p2p_roc_prepare_trace_load(
                &trace, IWX_P2P_TRACE_sessionSubmitAttempted) == 0;
        const bool knownSafe = ownerUnchanged && bindingAbsent &&
            phyUnleased && phaseIdle && noSessionSubmit;
        const bool originalChannelCaptured =
            iwx_p2p_roc_prepare_trace_load(
                &trace, IWX_P2P_TRACE_originalChannelDetailsCaptured) != 0;
        const bool restoredChannelCaptured =
            iwx_p2p_roc_prepare_trace_load(
                &trace, IWX_P2P_TRACE_restoredChannelDetailsCaptured) != 0;
        const bool sameP2pChannel =
            sc->sc_phyctxt[1].channel == entryP2pChannel &&
            originalChannelCaptured && restoredChannelCaptured &&
            iwx_p2p_roc_prepare_trace_load(
                &trace, IWX_P2P_TRACE_originalChannelFrequency) ==
                iwx_p2p_roc_prepare_trace_load(
                    &trace, IWX_P2P_TRACE_restoredChannelFrequency);
        traceSet(IWX_P2P_TRACE_ownerEpochsUnchanged, ownerUnchanged);
        traceSet(IWX_P2P_TRACE_bindingKnownAbsent, bindingAbsent);
        traceSet(IWX_P2P_TRACE_phyKnownUnleased, phyUnleased);
        traceSet(IWX_P2P_TRACE_phaseKnownIdle, phaseIdle);
        traceSet(IWX_P2P_TRACE_knownNotSubmittedSafeToAbort, knownSafe);
        traceSet(IWX_P2P_TRACE_fullyRestored,
                 knownSafe && sameP2pChannel && cleanupError == 0);
        iwx_p2p_roc_prepare_trace_finish(&trace);
        return prepareError;
    };

    /* Preserve the original gate order below. This is optional, read-only
     * owner evidence only, guarded by all owner and STA predicates needed
     * before reading a typed iwx_node or PHY context. */
    const bool preSampleOwnerValid = nativeP2pCommandAllowed() &&
        sc->sc_p2p_roc.phase == IWX_P2P_ROC_IDLE &&
        sc->sc_p2p.initialized &&
        sc->sc_p2p.fw_generation == entryScGeneration &&
        sc->sc_p2p.mac_state == IWX_P2P_RESOURCE_ACTIVE &&
        sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT &&
        sc->sc_p2p.mac_id == 1 &&
        (sc->sc_flags & (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE)) ==
            (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE) &&
        sc->sc_ic.ic_state == IEEE80211_S_RUN &&
        entryBssRaw != NULL && sc->sc_ic.ic_bss == entryBssRaw;
    if (preSampleOwnerValid) {
        const struct iwx_node *candidate =
            static_cast<const struct iwx_node *>(entryBssRaw);
        const struct iwx_phy_ctxt *candidatePhy = candidate->in_phyctxt;
        struct ieee80211_channel *const candidateChannel =
            candidate->in_ni.ni_chan;
        if (candidatePhy == &sc->sc_phyctxt[0] &&
            candidatePhy->id == 0 && candidate->in_id != sc->sc_p2p.mac_id &&
            candidateChannel != NULL &&
            sc->sc_phyctxt[0].channel == candidateChannel) {
            entryStationPhy = candidatePhy;
            entryStationChannel = candidateChannel;
            entryStationPhyChannel = candidatePhy->channel;
            entryStationId = candidate->in_id;
            entryStationPhyId = candidatePhy->id;
            entryStationPhyColor = candidatePhy->color;
            stationDetailsCaptured = true;
            traceSet(IWX_P2P_TRACE_stationDetailsCapturedEntry, 1U);
            traceSet(IWX_P2P_TRACE_stationIdEntry, entryStationId);
            traceSet(IWX_P2P_TRACE_stationColorEntry,
                     entryStationPhyColor);
            traceSet(IWX_P2P_TRACE_stationPhyIdEntry,
                     entryStationPhyId);
            traceSet(IWX_P2P_TRACE_stationPhyColorEntry,
                     entryStationPhyColor);
            const bool stationChannelValid =
                tahoeP2pRocChannelPointerInTable(
                    &sc->sc_ic, candidateChannel);
            const bool stationPhyChannelValid =
                tahoeP2pRocChannelPointerInTable(
                    &sc->sc_ic, entryStationPhyChannel);
            if (stationChannelValid && stationPhyChannelValid) {
                entryStationChannelFrequency = candidateChannel->ic_freq;
                entryStationPhyChannelFrequency =
                    entryStationPhyChannel->ic_freq;
                stationChannelDetailsCaptured =
                    entryStationChannelFrequency != 0 &&
                    entryStationPhyChannelFrequency != 0;
            }
            if (stationChannelDetailsCaptured) {
                traceSet(IWX_P2P_TRACE_stationChannelDetailsCapturedEntry,
                         1U);
                traceSet(IWX_P2P_TRACE_stationChannelFrequencyEntry,
                         entryStationChannelFrequency);
            } else {
                traceSet(IWX_P2P_TRACE_stationChannelDetailsCapturedEntry,
                         0U);
            }
        }
    }

    /* Capture the idle P2P PHY's original frequency while the same guarded
     * owner snapshot is valid. This gives early no-resource exits a real
     * baseline instead of treating two missing values as equality. */
    if (preSampleOwnerValid) {
        if (tahoeP2pRocChannelPointerInTable(
                &sc->sc_ic, entryP2pChannel)) {
            const uint32_t originalFrequency = entryP2pChannel->ic_freq;
            if (originalFrequency != 0) {
                traceSet(IWX_P2P_TRACE_originalChannelDetailsCaptured, 1U);
                traceSet(IWX_P2P_TRACE_originalChannelFrequency,
                         originalFrequency);
            }
        }
    }

    if (channel == NULL)
        return finish(IWX_P2P_PREPARE_STEP_ARGUMENT,
                      IWX_P2P_PREPARE_REASON_NULL_CHANNEL, EINVAL, 0);
    if (token == 0)
        return finish(IWX_P2P_PREPARE_STEP_ARGUMENT,
                      IWX_P2P_PREPARE_REASON_ZERO_TOKEN, EINVAL, 0);
    u_int channelIndex = 0;
    if (!tahoeP2pRocCurrentChannelIndex(&sc->sc_ic, channel,
                                        &channelIndex))
        return finish(IWX_P2P_PREPARE_STEP_CHANNEL_INDEX,
                      IWX_P2P_PREPARE_REASON_CHANNEL_NOT_IN_TABLE,
                      EOPNOTSUPP, 0);
    traceSet(IWX_P2P_TRACE_requestedChannelPresent, 1U);
    traceSet(IWX_P2P_TRACE_channelIndex, channelIndex);
    traceSet(IWX_P2P_TRACE_ieeeChannelNumber,
             ieee80211_chan2ieee(&sc->sc_ic, channel));
    traceSet(IWX_P2P_TRACE_channelFrequency, channel->ic_freq);
    traceSet(IWX_P2P_TRACE_channelFlags, channel->ic_flags);
    traceSet(IWX_P2P_TRACE_channelRegulatoryFlags, channel->ic_flags);
    traceSet(IWX_P2P_TRACE_channelIs2GHz, IEEE80211_IS_CHAN_2GHZ(channel));
    traceSet(IWX_P2P_TRACE_channelIs5GHz, IEEE80211_IS_CHAN_5GHZ(channel));
    traceSet(IWX_P2P_TRACE_channelIsDFS,
             (channel->ic_flags & IEEE80211_CHAN_DFS) != 0);
    traceSet(IWX_P2P_TRACE_channelIsPassive,
             (channel->ic_flags & IEEE80211_CHAN_PASSIVE) != 0);
    if (!tahoeP2pRocConfigurationSupported(configuration))
        return finish(IWX_P2P_PREPARE_STEP_CONFIGURATION,
                      IWX_P2P_PREPARE_REASON_UNSUPPORTED_CONFIGURATION,
                      EOPNOTSUPP, 0);
    if (receiveObservation149 &&
        !tahoeP2pRocObservation149PrepareAllowed(
            channel, channelIndex, configuration, true))
        return finish(IWX_P2P_PREPARE_STEP_RX149_POLICY,
                      IWX_P2P_PREPARE_REASON_RX149_CHANNEL_NOT_ALLOWED,
                      EOPNOTSUPP, 0);
    if (!nativeP2pCommandAllowed())
        return finish(IWX_P2P_PREPARE_STEP_COMMAND_GATE,
                      IWX_P2P_PREPARE_REASON_COMMAND_GATE_BUSY, EBUSY, 0);
    if (sc->sc_p2p_roc.phase != IWX_P2P_ROC_IDLE)
        return finish(IWX_P2P_PREPARE_STEP_ROC_IDLE,
                      IWX_P2P_PREPARE_REASON_ROC_NOT_IDLE, EALREADY, 0);
    if (!sc->sc_p2p.initialized ||
        sc->sc_p2p.fw_generation != static_cast<uint32_t>(sc->sc_generation)) {
        return finish(IWX_P2P_PREPARE_STEP_P2P_OWNER,
                      !sc->sc_p2p.initialized ?
                        IWX_P2P_PREPARE_REASON_P2P_NOT_INITIALIZED :
                        IWX_P2P_PREPARE_REASON_FW_GENERATION_MISMATCH,
                      EBUSY, 0);
    }
    if (sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE)
        return finish(IWX_P2P_PREPARE_STEP_P2P_OWNER,
                      IWX_P2P_PREPARE_REASON_MAC_NOT_ACTIVE, EBUSY, 0);
    if (sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ABSENT)
        return finish(IWX_P2P_PREPARE_STEP_P2P_OWNER,
                      IWX_P2P_PREPARE_REASON_BINDING_NOT_ABSENT, EBUSY, 0);
    if (sc->sc_p2p.mac_id != 1)
        return finish(IWX_P2P_PREPARE_STEP_P2P_OWNER,
                      IWX_P2P_PREPARE_REASON_WRONG_MAC_ID, EBUSY, 0);
    if ((sc->sc_flags & (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE)) !=
        (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE))
        return finish(IWX_P2P_PREPARE_STEP_ACTIVE_FLAGS,
                      IWX_P2P_PREPARE_REASON_ACTIVE_FLAGS_MISSING, EBUSY, 0);
    if (sc->sc_ic.ic_state != IEEE80211_S_RUN)
        return finish(IWX_P2P_PREPARE_STEP_STA_RUN,
                      IWX_P2P_PREPARE_REASON_STA_NOT_RUNNING, EBUSY, 0);
    if (sc->sc_ic.ic_bss == NULL)
        return finish(IWX_P2P_PREPARE_STEP_STA_RUN,
                      IWX_P2P_PREPARE_REASON_STA_BSS_MISSING, EBUSY, 0);

    struct iwx_node *sta = reinterpret_cast<struct iwx_node *>(
        sc->sc_ic.ic_bss);
    if (sta->in_phyctxt != &sc->sc_phyctxt[0])
        return finish(IWX_P2P_PREPARE_STEP_STA_PHY,
                      IWX_P2P_PREPARE_REASON_STA_PHY_POINTER_MISMATCH,
                      EBUSY, 0);
    if (sta->in_phyctxt->id != 0)
        return finish(IWX_P2P_PREPARE_STEP_STA_PHY,
                      IWX_P2P_PREPARE_REASON_STA_PHY_ID_MISMATCH, EBUSY, 0);
    if (sta->in_id == sc->sc_p2p.mac_id)
        return finish(IWX_P2P_PREPARE_STEP_STA_PHY,
                      IWX_P2P_PREPARE_REASON_STA_ID_CONFLICT, EBUSY, 0);
    if (sta->in_ni.ni_chan == NULL)
        return finish(IWX_P2P_PREPARE_STEP_STA_PHY,
                      IWX_P2P_PREPARE_REASON_STA_CHANNEL_MISSING, EBUSY, 0);
    if (sc->sc_phyctxt[0].channel != sta->in_ni.ni_chan)
        return finish(IWX_P2P_PREPARE_STEP_STA_PHY,
                      IWX_P2P_PREPARE_REASON_STA_CONTEXT_CHANNEL_MISMATCH,
                      EBUSY, 0);
    /* Any channel-6 request, including same-channel ROC, must use the live
     * regulatory table entry and must remain legal for the TX-capable P2P
     * firmware path. Do not let pointer equality with the STA bypass this. */
    if (channelIndex == 6 &&
        !tahoeP2pRocSocialChannel6Allowed(&sc->sc_ic, channel))
        return finish(IWX_P2P_PREPARE_STEP_CHANNEL_POLICY,
                      IWX_P2P_PREPARE_REASON_CHANNEL6_POLICY,
                      EOPNOTSUPP, 0);
    if (!receiveObservation149 && sta->in_ni.ni_chan != channel &&
        !tahoeP2pRocOffChannelAllowed(&sc->sc_ic, channel, configuration))
        return finish(IWX_P2P_PREPARE_STEP_CHANNEL_POLICY,
                      IWX_P2P_PREPARE_REASON_OFFCHANNEL_POLICY,
                      EOPNOTSUPP, 0);

    const uint32_t sessionCapability = isset(
        sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD) != 0;
    const uint32_t phyCommandVersion = iwx_lookup_cmd_ver(
        sc, IWX_LONG_GROUP, IWX_PHY_CONTEXT_CMD);
    const uint32_t bindingCommandVersion = iwx_lookup_cmd_ver(
        sc, IWX_LONG_GROUP, IWX_BINDING_CONTEXT_CMD);
    const uint32_t bindingNotificationVersion = iwx_lookup_notif_ver(
        sc, IWX_LONG_GROUP, IWX_BINDING_CONTEXT_CMD);
    const uint32_t sessionCommandVersion = iwx_lookup_cmd_ver(
        sc, IWX_MAC_CONF_GROUP, IWX_SESSION_PROTECTION_CMD);
    const uint32_t sessionNotificationVersion = iwx_lookup_notif_ver(
        sc, IWX_MAC_CONF_GROUP, IWX_SESSION_PROTECTION_NOTIF);
    traceSet(IWX_P2P_TRACE_firmwareCapabilitiesCaptured, 1U);
    traceSet(IWX_P2P_TRACE_sessionCapabilityPresent, sessionCapability);
    traceSet(IWX_P2P_TRACE_phyContextCommandVersion, phyCommandVersion);
    traceSet(IWX_P2P_TRACE_bindingContextCommandVersion,
             bindingCommandVersion);
    traceSet(IWX_P2P_TRACE_bindingContextNotificationVersion,
             bindingNotificationVersion);
    traceSet(IWX_P2P_TRACE_sessionProtectionCommandVersion,
             sessionCommandVersion);
    traceSet(IWX_P2P_TRACE_sessionProtectionNotificationVersion,
             sessionNotificationVersion);

    if (!sessionCapability)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_SESSION_CAPABILITY_MISSING,
                      EOPNOTSUPP, 0);
    if (phyCommandVersion != 3)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_PHY_COMMAND_VERSION,
                      EOPNOTSUPP, 0);
    if (bindingCommandVersion != 2)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_BINDING_COMMAND_VERSION,
                      EOPNOTSUPP, 0);
    if (bindingNotificationVersion != 1)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_BINDING_NOTIFICATION_VERSION,
                      EOPNOTSUPP, 0);
    if (sessionCommandVersion != 1)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_SESSION_COMMAND_VERSION,
                      EOPNOTSUPP, 0);
    if (sessionNotificationVersion != 2)
        return finish(IWX_P2P_PREPARE_STEP_FIRMWARE_CAPABILITY,
                      IWX_P2P_PREPARE_REASON_SESSION_NOTIFICATION_VERSION,
                      EOPNOTSUPP, 0);

    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    tahoeP2pRocResetState(roc);
    roc.token = token;
    roc.fw_generation = static_cast<uint32_t>(sc->sc_generation);
    roc.session_conf_id = static_cast<uint8_t>(configuration);
    roc.session_submit_result = EINPROGRESS;
    roc.phy_id = 0xff;
    __atomic_store_n(&roc.receive_observation_only,
                     receiveObservation149 ? 1 : 0, __ATOMIC_RELEASE);

    uint8_t phyId = 0xff;
    traceSet(IWX_P2P_TRACE_step, IWX_P2P_PREPARE_STEP_PHY_LEASE);
    traceSet(IWX_P2P_TRACE_phyLeaseAttempted, 1U);
    int error = iwx_p2p_phy_lease(sc, &phyId);
    traceSet(IWX_P2P_TRACE_phyLeaseReturned, 1U);
    traceSet(IWX_P2P_TRACE_phyLeaseResult,
             static_cast<uint32_t>(error));
    traceSet(IWX_P2P_TRACE_phyLeaseId, phyId);
    if (error) {
        if (receiveObservation149)
            tahoeP2pRocResetState(roc);
        return finish(IWX_P2P_PREPARE_STEP_PHY_LEASE,
                      IWX_P2P_PREPARE_REASON_PHY_LEASE_FAILED, error, 0);
    }
    if (phyId != 1 || phyId >= IWX_NUM_PHY_CTX ||
        sc->sc_phyctxt[phyId].channel == NULL) {
        traceSet(IWX_P2P_TRACE_phyReleaseAttempted, 1U);
        const int releaseError = iwx_p2p_phy_release(sc);
        traceSet(IWX_P2P_TRACE_phyReleaseReturned, 1U);
        traceSet(IWX_P2P_TRACE_phyReleaseResult,
                 static_cast<uint32_t>(releaseError));
        if (receiveObservation149 && releaseError) {
            roc.phase = IWX_P2P_ROC_QUARANTINED;
            return finish(IWX_P2P_PREPARE_STEP_PHY_RELEASE,
                          IWX_P2P_PREPARE_REASON_PHY_RELEASE_FAILED,
                          releaseError, releaseError);
        }
        if (receiveObservation149)
            tahoeP2pRocResetState(roc);
        return finish(IWX_P2P_PREPARE_STEP_PHY_ID,
                      IWX_P2P_PREPARE_REASON_UNEXPECTED_PHY_ID,
                      EOPNOTSUPP, releaseError);
    }

    roc.phy_id = phyId;
    roc.phy_color = static_cast<uint8_t>(sc->sc_phyctxt[phyId].color);
    roc.original_phy_channel = sc->sc_phyctxt[phyId].channel;
    roc.roc_channel = channel;
    u_int originalChannelIndex = 0;
    if (tahoeP2pRocCurrentChannelIndex(
            &sc->sc_ic, roc.original_phy_channel, &originalChannelIndex)) {
        const uint32_t originalFrequency =
            roc.original_phy_channel->ic_freq;
        if (originalFrequency != 0) {
            traceSet(IWX_P2P_TRACE_originalChannelDetailsCaptured, 1U);
            traceSet(IWX_P2P_TRACE_originalChannelFrequency,
                     originalFrequency);
        } else {
            traceSet(IWX_P2P_TRACE_originalChannelDetailsCaptured, 0U);
            traceSet(IWX_P2P_TRACE_originalChannelFrequency, 0U);
        }
    }
    if (receiveObservation149) {
        roc.station_bss = static_cast<void *>(sc->sc_ic.ic_bss);
        roc.station_epoch = __atomic_load_n(&sc->sc_tx_rate_generation,
                                             __ATOMIC_ACQUIRE);
        roc.station_phy_id = static_cast<uint8_t>(sta->in_phyctxt->id);
        roc.station_phy_color = sta->in_phyctxt->color;
        roc.station_phy_channel = sta->in_ni.ni_chan;
    }

    roc.phase = IWX_P2P_ROC_PHY_REMOVE_UNKNOWN;
    traceSet(IWX_P2P_TRACE_step, IWX_P2P_PREPARE_STEP_PHY_REMOVE);
    traceSet(IWX_P2P_TRACE_phyRemoveAttempted, 1U);
    error = tahoeP2pRocPhyCommand(this, sc, &sc->sc_phyctxt[phyId],
                                  roc.original_phy_channel,
                                  IWX_FW_CTXT_ACTION_REMOVE);
    traceSet(IWX_P2P_TRACE_phyRemoveReturned, 1U);
    traceSet(IWX_P2P_TRACE_phyRemoveResult, static_cast<uint32_t>(error));
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return finish(IWX_P2P_PREPARE_STEP_PHY_REMOVE,
                      IWX_P2P_PREPARE_REASON_PHY_REMOVE_FAILED, error, 0);
    }

    roc.phase = IWX_P2P_ROC_PHY_ADD_UNKNOWN;
    traceSet(IWX_P2P_TRACE_step, IWX_P2P_PREPARE_STEP_PHY_ADD);
    traceSet(IWX_P2P_TRACE_phyAddAttempted, 1U);
    error = tahoeP2pRocPhyCommand(this, sc, &sc->sc_phyctxt[phyId], channel,
                                  IWX_FW_CTXT_ACTION_ADD);
    traceSet(IWX_P2P_TRACE_phyAddReturned, 1U);
    traceSet(IWX_P2P_TRACE_phyAddResult, static_cast<uint32_t>(error));
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return finish(IWX_P2P_PREPARE_STEP_PHY_ADD,
                      IWX_P2P_PREPARE_REASON_PHY_ADD_FAILED, error, 0);
    }
    sc->sc_phyctxt[phyId].channel = channel;
    roc.phase = IWX_P2P_ROC_PHY_READY;

    roc.phase = IWX_P2P_ROC_BINDING_ADD_UNKNOWN;
    traceSet(IWX_P2P_TRACE_step, IWX_P2P_PREPARE_STEP_BINDING_ADD);
    traceSet(IWX_P2P_TRACE_bindingAddAttempted, 1U);
    error = iwx_p2p_binding_add(sc);
    traceSet(IWX_P2P_TRACE_bindingAddReturned, 1U);
    traceSet(IWX_P2P_TRACE_bindingAddResult, static_cast<uint32_t>(error));
    traceSet(IWX_P2P_TRACE_bindingRawStatus, roc.binding_raw_status);
    traceSet(IWX_P2P_TRACE_bindingStatusValid, roc.binding_status_valid);
    traceSet(IWX_P2P_TRACE_bindingRejected, roc.binding_rejected);
    if (error) {
        /* Only a decoded nonzero command status proves that ADD was rejected. */
        if (sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT) {
            if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
                !tahoeP2pRocObservationOwnerValid(
                    sc, roc, IWX_P2P_RESOURCE_ABSENT)) {
                roc.phase = IWX_P2P_ROC_QUARANTINED;
                return finish(IWX_P2P_PREPARE_STEP_OWNER_RECHECK,
                              IWX_P2P_PREPARE_REASON_OWNER_CHANGED,
                              error, 0);
            }
            const int restoreError = tahoeP2pRocRestorePhy(this, sc, &trace);
            traceSet(IWX_P2P_TRACE_cleanupErrno,
                     static_cast<uint32_t>(restoreError));
            if (restoreError) {
                roc.phase = IWX_P2P_ROC_QUARANTINED;
                if (iwx_p2p_roc_prepare_trace_load(
                        &trace, IWX_P2P_TRACE_restoreRemoveResult) != 0)
                    return finish(IWX_P2P_PREPARE_STEP_RESTORE_PHY_REMOVE,
                                  IWX_P2P_PREPARE_REASON_RESTORE_REMOVE_FAILED,
                                  restoreError, restoreError);
                if (iwx_p2p_roc_prepare_trace_load(
                        &trace, IWX_P2P_TRACE_restoreAddResult) != 0)
                    return finish(IWX_P2P_PREPARE_STEP_RESTORE_PHY_ADD,
                                  IWX_P2P_PREPARE_REASON_RESTORE_ADD_FAILED,
                                  restoreError, restoreError);
                return finish(IWX_P2P_PREPARE_STEP_PHY_RELEASE,
                              IWX_P2P_PREPARE_REASON_PHY_RELEASE_FAILED,
                              restoreError, restoreError);
            }
            /* The trace is independent; retire only the fully restored ROC. */
            const bool decodedBindingReject =
                roc.binding_status_valid && roc.binding_rejected;
            tahoeP2pRocResetState(roc);
            return finish(IWX_P2P_PREPARE_STEP_BINDING_ADD,
                          decodedBindingReject ?
                            IWX_P2P_PREPARE_REASON_BINDING_ADD_DECODED_REJECT :
                            IWX_P2P_PREPARE_REASON_BINDING_ADD_NOT_SUBMITTED,
                          error, 0);
        }
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return finish(IWX_P2P_PREPARE_STEP_BINDING_ADD,
                      IWX_P2P_PREPARE_REASON_BINDING_ADD_UNKNOWN,
                      error, 0);
    }

    roc.phase = IWX_P2P_ROC_PREPARED;
    return finish(IWX_P2P_PREPARE_STEP_COMPLETE,
                  IWX_P2P_PREPARE_REASON_PREPARE_SUCCEEDED, 0, 0);
}

int ItlIwx::
tahoeP2pRocSubmit(struct iwx_softc *sc, uint32_t token,
                  uint32_t configuration, uint32_t durationMs,
                  TahoeP2pRocArmTracker armTracker, void *trackerContext)
{
    if (sc == NULL || sc != &com || armTracker == NULL)
        return EINVAL;
    if (!nativeP2pCommandAllowed())
        return EBUSY;

    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    if (roc.phase != IWX_P2P_ROC_PREPARED || roc.token != token ||
        roc.fw_generation != static_cast<uint32_t>(sc->sc_generation))
        return EBUSY;
    if (!tahoeP2pRocConfigurationSupported(configuration))
        return EOPNOTSUPP;
    if (roc.session_conf_id != configuration)
        return EBUSY;
    u_int channelIndex = 0;
    if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        (!tahoeP2pRocCurrentChannelIndex(&sc->sc_ic, roc.roc_channel,
                                         &channelIndex) ||
         !tahoeP2pRocObservation149SubmitAllowed(
             roc, configuration, durationMs, channelIndex)))
        return EOPNOTSUPP;
    if (sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased ||
        sc->sc_p2p.mac_id != 1 || sc->sc_p2p.phy_id != 1)
        return EBUSY;
    if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        !tahoeP2pRocObservationOwnerValid(
            sc, roc, IWX_P2P_RESOURCE_ACTIVE)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return EBUSY;
    }
    if (durationMs != kTahoeRocDurationMs &&
        (durationMs != kTahoeSocialTxRocDurationMs ||
         !tahoeP2pRocLongSocialTxAllowed(sc, roc, configuration)))
        return EOPNOTSUPP;
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD) ||
        iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP,
                           IWX_SESSION_PROTECTION_CMD) != 1 ||
        iwx_lookup_notif_ver(sc, IWX_MAC_CONF_GROUP,
                             IWX_SESSION_PROTECTION_NOTIF) != 2)
        return EOPNOTSUPP;

    const uint32_t macIdAndColor = IWX_FW_CMD_ID_AND_COLOR(
        sc->sc_p2p.mac_id, sc->sc_p2p.mac_color);
    if (!armTracker(trackerContext, roc.fw_generation, macIdAndColor,
                    configuration))
        return ECANCELED;

    struct iwx_session_prot_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(macIdAndColor);
    cmd.action = htole32(IWX_FW_CTXT_ACTION_ADD);
    cmd.conf_id = htole32(configuration);
    cmd.duration_tu = htole32(tahoeP2pMsecToTu(durationMs));
    /* repetition_count and interval are unused by API v1. */

    roc.phase = IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN;
    roc.session_submit_seen = 0;
    roc.session_submit_result = EINPROGRESS;
    const int error = iwx_send_cmd_pdu(
        sc, iwx_cmd_id(IWX_SESSION_PROTECTION_CMD, IWX_MAC_CONF_GROUP, 0),
        0, sizeof(cmd), &cmd);
    roc.session_submit_seen = 1;
    roc.session_submit_result = error;
    if (error == 0)
        roc.phase = IWX_P2P_ROC_SESSION_ACKED;
    /* ACK or timeout alone never authorizes cleanup. The tracker waits for END. */
    return error;
}

int ItlIwx::
tahoeP2pRocAbortPrepared(struct iwx_softc *sc, uint32_t token,
                        uint32_t configuration, bool txResourcesAbsent)
{
    if (sc == NULL || sc != &com)
        return EINVAL;
    if (!nativeP2pCommandAllowed() || !txResourcesAbsent)
        return EBUSY;
    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    // PREPARED is the last phase before any Session Protection command.
    // A timeout/unknown submit must still wait for END or a hardware reset.
    if (!tahoeP2pRocConfigurationSupported(configuration) || token == 0 ||
        roc.phase != IWX_P2P_ROC_PREPARED || roc.token != token ||
        roc.session_conf_id != configuration || roc.session_submit_seen != 0 ||
        roc.session_submit_result != EINPROGRESS ||
        roc.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        sc->sc_p2p.fw_generation != roc.fw_generation ||
        sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased || sc->sc_p2p.mac_id != 1 ||
        sc->sc_p2p.phy_id != roc.phy_id || roc.phy_id != 1)
        return EBUSY;
            if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        !tahoeP2pRocObservationOwnerValid(
            sc, roc, IWX_P2P_RESOURCE_ACTIVE)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return EBUSY;
    }

    roc.phase = IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN;
    int error = iwx_p2p_binding_remove(sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }
    if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        !tahoeP2pRocObservationOwnerValid(
            sc, roc, IWX_P2P_RESOURCE_ABSENT)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return EBUSY;
    }
    if (roc.fw_generation != static_cast<uint32_t>(sc->sc_generation)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return ESTALE;
    }
    error = tahoeP2pRocRestorePhy(this, sc);
    if (error)
        roc.phase = IWX_P2P_ROC_QUARANTINED;
    return error;
}

int ItlIwx::
tahoeP2pRocCleanup(struct iwx_softc *sc, uint32_t token,
                    uint32_t configuration, bool endNotificationConfirmed)
{
    if (sc == NULL || sc != &com)
        return EINVAL;
    if (!nativeP2pCommandAllowed())
        return EBUSY;

    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    if (!tahoeP2pRocConfigurationSupported(configuration))
        return EOPNOTSUPP;
    if (roc.session_conf_id != configuration ||
        !endNotificationConfirmed || roc.token != token ||
        roc.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        (roc.phase != IWX_P2P_ROC_SESSION_ACKED &&
         roc.phase != IWX_P2P_ROC_SESSION_SUBMIT_UNKNOWN &&
         roc.phase != IWX_P2P_ROC_END_CONFIRMED))
        return EBUSY;
    if (sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased || sc->sc_p2p.mac_state !=
            IWX_P2P_RESOURCE_ACTIVE)
        return EBUSY;
    if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        !tahoeP2pRocObservationOwnerValid(
            sc, roc, IWX_P2P_RESOURCE_ACTIVE)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return EBUSY;
    }

    roc.phase = IWX_P2P_ROC_END_CONFIRMED;
    roc.phase = IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN;
    int error = iwx_p2p_binding_remove(sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }

    if (tahoeP2pRocIsReceiveObservationOnly(roc) &&
        !tahoeP2pRocObservationOwnerValid(
            sc, roc, IWX_P2P_RESOURCE_ABSENT)) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return EBUSY;
    }

    error = tahoeP2pRocRestorePhy(this, sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }
    return 0;
}

#endif /* AIRPORT_TAHOE */
