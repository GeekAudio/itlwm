// Frozen Test087 bool-behavior oracle from ab24d3ee909688769342823525466750b2720ca5. Do not edit to follow production.
// The differential test renames this method and drives both functions with identical fake inputs.
bool ItlIwx::tahoeP2pCurrentRxDiagnosticEpochs(
    struct iwx_softc *sc, NativeAwdlRxEntry::Epochs *epochs)
{
    if (!sc || !epochs || !tahoeP2pOnMainGate())
        return false;
    const auto &lease = tahoe_p2p_rx_lease_;
    // Most RX traffic has no active manual P2P lease. Reject it before
    // sampling the ROC reducer or host clock.
    if (!lease.active || lease.contextGeneration == 0 ||
        lease.powerGeneration == 0 || lease.stationGeneration == 0 ||
        lease.contextGeneration != lease.currentContextGeneration ||
        lease.contextGeneration != nativeP2pProbeGeneration_ ||
        lease.powerGeneration != lease.currentPowerGeneration ||
        lease.stationGeneration != lease.currentStationGeneration)
        return false;
    const uint32_t currentPower = uint32_t(sc->sc_generation);
    const uint32_t currentStation = __atomic_load_n(
        &sc->sc_tx_rate_generation, __ATOMIC_ACQUIRE);
    if (lease.powerGeneration != currentPower ||
        lease.powerGeneration != uint32_t(sc->sc_p2p.fw_generation) ||
        lease.stationGeneration != currentStation)
        return false;
    const uint32_t currentRoc = __atomic_load_n(
        &nativeP2pRocGeneration_, __ATOMIC_ACQUIRE);
    if (currentRoc == 0)
        return false;
    const auto session = nativeP2pRocEvents_.snapshot();
    const uint64_t nowUs = tahoeP2pRxMonotonicUs();
    NativeP2PRx149Observation::RocEvidence rx149OwnerEvidence{};
    const NativeP2PRx149Observation::RocEvidence *rx149Owner = nullptr;
#if defined(ITL_NATIVE_AWDL_RX149_OBSERVATION_25G332)
    if (session.configuration ==
        IWX_SESSION_PROTECT_CONF_P2P_DEVICE_DISCOV) {
        const auto traceOwner = nativeAwdlRxEventTimeline_.snapshot();
        // The out-of-range index intentionally supplies no descriptor-channel
        // evidence. This only opens numeric RX-entry telemetry for a current
        // 149 observation owner; packet channel and Action gates remain intact.
        rx149OwnerEvidence = currentRx149ActionEvidence(
            this, sc, lease, static_cast<uint16_t>(0xffffu), session,
            traceOwner);
        rx149Owner = &rx149OwnerEvidence;
    }
#endif
    if (session.generation != lease.contextGeneration ||
        session.generation != currentRoc || !session.commandReturned ||
        session.commandResult != 0 ||
        !rxDiagnosticSessionWindowQualified(session, nowUs, rx149Owner) ||
        sc->sc_p2p_roc.token != session.generation ||
        sc->sc_p2p_roc.phase != IWX_P2P_ROC_SESSION_ACKED)
        return false;

    epochs->contextGeneration = uint32_t(lease.contextGeneration);
    epochs->powerGeneration = uint32_t(lease.powerGeneration);
    epochs->stationGeneration = uint32_t(lease.stationGeneration);
    epochs->rocGeneration = session.generation;
    return true;
}
