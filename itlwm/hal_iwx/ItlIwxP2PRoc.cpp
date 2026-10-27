/*
 * Tahoe Intel P2P ROC firmware resource adapter.
 *
 * Sessions default to 100 ms / 20 MHz. A single 900 ms management-TX window
 * is allowed only on a legally bound social channel 6 P2P PHY. Same-channel
 * sessions remain supported; other off-channel targets fail closed.
 */
#include "ItlIwx.hpp"

#ifdef AIRPORT_TAHOE

namespace {

static const uint32_t kTahoeRocDurationMs = 100;
static const uint32_t kTahoeSocialTxRocDurationMs = 900;

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
tahoeP2pRocRestorePhy(ItlIwx *owner, struct iwx_softc *sc)
{
    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    if (roc.phy_id >= IWX_NUM_PHY_CTX ||
        roc.original_phy_channel == NULL || roc.roc_channel == NULL)
        return EINVAL;

    struct iwx_phy_ctxt *phy = &sc->sc_phyctxt[roc.phy_id];
    roc.phase = IWX_P2P_ROC_PHY_RESTORE_REMOVE_UNKNOWN;
    int error = tahoeP2pRocPhyCommand(owner, sc, phy, roc.roc_channel,
                                      IWX_FW_CTXT_ACTION_REMOVE);
    if (error)
        return error;

    roc.phase = IWX_P2P_ROC_PHY_RESTORE_ADD_UNKNOWN;
    error = tahoeP2pRocPhyCommand(owner, sc, phy,
                                  roc.original_phy_channel,
                                  IWX_FW_CTXT_ACTION_ADD);
    if (error)
        return error;

    phy->channel = roc.original_phy_channel;
    error = owner->iwx_p2p_phy_release(sc);
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

} // namespace

int ItlIwx::
tahoeP2pRocPrepare(struct iwx_softc *sc,
                    struct ieee80211_channel *channel,
                    uint32_t token, uint32_t configuration)
{
    if (sc == NULL || sc != &com || channel == NULL)
        return EINVAL;
    if (token == 0)
        return EINVAL;
    u_int channelIndex = 0;
    if (!tahoeP2pRocCurrentChannelIndex(&sc->sc_ic, channel,
                                        &channelIndex))
        return EOPNOTSUPP;
    if (!tahoeP2pRocConfigurationSupported(configuration))
        return EOPNOTSUPP;
    if (!nativeP2pCommandAllowed())
        return EBUSY;
    if (sc->sc_p2p_roc.phase != IWX_P2P_ROC_IDLE)
        return EALREADY;
    if (!sc->sc_p2p.initialized ||
        sc->sc_p2p.fw_generation != static_cast<uint32_t>(sc->sc_generation) ||
        sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ABSENT ||
        sc->sc_p2p.mac_id != 1)
        return EBUSY;
    if ((sc->sc_flags & (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE)) !=
        (IWX_FLAG_MAC_ACTIVE | IWX_FLAG_BINDING_ACTIVE))
        return EBUSY;
    if (sc->sc_ic.ic_state != IEEE80211_S_RUN || sc->sc_ic.ic_bss == NULL)
        return EBUSY;

    struct iwx_node *sta = (struct iwx_node *)sc->sc_ic.ic_bss;
    if (sta->in_phyctxt != &sc->sc_phyctxt[0] ||
        sta->in_phyctxt->id != 0 || sta->in_id == sc->sc_p2p.mac_id ||
        sta->in_ni.ni_chan == NULL ||
        sc->sc_phyctxt[0].channel != sta->in_ni.ni_chan)
        return EBUSY;
    /* Any channel-6 request, including same-channel ROC, must use the live
     * regulatory table entry and must remain legal for the TX-capable P2P
     * firmware path. Do not let pointer equality with the STA bypass this. */
    if (channelIndex == 6 &&
        !tahoeP2pRocSocialChannel6Allowed(&sc->sc_ic, channel))
        return EOPNOTSUPP;
    if (sta->in_ni.ni_chan != channel &&
        !tahoeP2pRocOffChannelAllowed(&sc->sc_ic, channel, configuration))
        return EOPNOTSUPP;
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD) == 0 ||
        iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_PHY_CONTEXT_CMD) != 3 ||
        iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP,
                           IWX_BINDING_CONTEXT_CMD) != 2 ||
        iwx_lookup_notif_ver(sc, IWX_LONG_GROUP,
                             IWX_BINDING_CONTEXT_CMD) != 1 ||
        iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP,
                           IWX_SESSION_PROTECTION_CMD) != 1 ||
        iwx_lookup_notif_ver(sc, IWX_MAC_CONF_GROUP,
                             IWX_SESSION_PROTECTION_NOTIF) != 2)
        return EOPNOTSUPP;

    struct iwx_p2p_roc_state &roc = sc->sc_p2p_roc;
    memset(&roc, 0, sizeof(roc));
    roc.token = token;
    roc.fw_generation = static_cast<uint32_t>(sc->sc_generation);
    roc.session_conf_id = static_cast<uint8_t>(configuration);
    roc.session_submit_result = EINPROGRESS;
    roc.phy_id = 0xff;

    uint8_t phyId = 0xff;
    int error = iwx_p2p_phy_lease(sc, &phyId);
    if (error)
        return error;
    if (phyId != 1 || phyId >= IWX_NUM_PHY_CTX ||
        sc->sc_phyctxt[phyId].channel == NULL) {
        (void)iwx_p2p_phy_release(sc);
        return EOPNOTSUPP;
    }

    roc.phy_id = phyId;
    roc.phy_color = static_cast<uint8_t>(sc->sc_phyctxt[phyId].color);
    roc.original_phy_channel = sc->sc_phyctxt[phyId].channel;
    roc.roc_channel = channel;

    roc.phase = IWX_P2P_ROC_PHY_REMOVE_UNKNOWN;
    error = tahoeP2pRocPhyCommand(this, sc, &sc->sc_phyctxt[phyId],
                                  roc.original_phy_channel,
                                  IWX_FW_CTXT_ACTION_REMOVE);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }

    roc.phase = IWX_P2P_ROC_PHY_ADD_UNKNOWN;
    error = tahoeP2pRocPhyCommand(this, sc, &sc->sc_phyctxt[phyId], channel,
                                  IWX_FW_CTXT_ACTION_ADD);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }
    sc->sc_phyctxt[phyId].channel = channel;
    roc.phase = IWX_P2P_ROC_PHY_READY;

    roc.phase = IWX_P2P_ROC_BINDING_ADD_UNKNOWN;
    error = iwx_p2p_binding_add(sc);
    if (error) {
        /* Only a decoded nonzero command status proves that ADD was rejected. */
        if (sc->sc_p2p.binding_state == IWX_P2P_RESOURCE_ABSENT) {
            const int restoreError = tahoeP2pRocRestorePhy(this, sc);
            if (restoreError) {
                roc.phase = IWX_P2P_ROC_QUARANTINED;
                return restoreError;
            }
            return error;
        }
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }

    roc.phase = IWX_P2P_ROC_PREPARED;
    return 0;
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
    if (sc->sc_p2p.mac_state != IWX_P2P_RESOURCE_ACTIVE ||
        sc->sc_p2p.binding_state != IWX_P2P_RESOURCE_ACTIVE ||
        !sc->sc_p2p.phy_leased ||
        sc->sc_p2p.mac_id != 1 || sc->sc_p2p.phy_id != 1)
        return EBUSY;
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

    roc.phase = IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN;
    int error = iwx_p2p_binding_remove(sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
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

    roc.phase = IWX_P2P_ROC_END_CONFIRMED;
    roc.phase = IWX_P2P_ROC_BINDING_REMOVE_UNKNOWN;
    int error = iwx_p2p_binding_remove(sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }

    error = tahoeP2pRocRestorePhy(this, sc);
    if (error) {
        roc.phase = IWX_P2P_ROC_QUARANTINED;
        return error;
    }
    return 0;
}

#endif /* AIRPORT_TAHOE */
