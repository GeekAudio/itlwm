#ifndef ITLWM_TAHOE_P2P_ROC_OBSERVATION_POLICY_HPP
#define ITLWM_TAHOE_P2P_ROC_OBSERVATION_POLICY_HPP

#include <stdint.h>

namespace TahoeP2PRocObservationPolicy {

struct Channel {
    uint32_t index;
    uint32_t frequencyMHz;
    bool is5GHz;
    bool is2GHz;
    bool hasFlags;
    bool isDfs;
    bool isPassive;
};

constexpr bool channel149ReceiveOnlyAllowed(const Channel &channel)
{
    return channel.index == 149 && channel.frequencyMHz == 5745 &&
        channel.is5GHz && !channel.is2GHz && channel.hasFlags && !channel.isDfs &&
        !channel.isPassive;
}

/* Ordinary requests retain the existing policy; only an explicit request
 * opts into the narrow, compiled RX-observation policy. */
constexpr bool prepareAllowed(bool featureCompiled, bool requested,
                              bool deviceDiscovery, const Channel &channel)
{
    return !requested || (featureCompiled && deviceDiscovery &&
                          channel149ReceiveOnlyAllowed(channel));
}

constexpr bool submitAllowed(bool featureCompiled, bool receiveOnly,
                             bool deviceDiscovery, uint32_t durationMs,
                             const Channel &channel)
{
    return !receiveOnly ||
        (featureCompiled && deviceDiscovery && durationMs == 100 &&
         channel149ReceiveOnlyAllowed(channel));
}

} // namespace TahoeP2PRocObservationPolicy

#endif
