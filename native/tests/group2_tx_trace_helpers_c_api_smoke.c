#include "native/group2_tx_trace_helpers.h"

/* Both entry points must remain usable from the C11 consumers of
 * ieee80211_var.h: the original signature is preserved, and related sidecar
 * observation is opt-in through the additive _ex form. */
int group2_tx_trace_helpers_c_api_smoke(void)
{
    struct IwxGroup2TxTrace trace = {0};
    struct IwxGroup2TxSlot matched = {0};
    uint32_t related_sidecar = 0;
    const uint32_t legacy = iwx_group2_tx_trace_match_completion(
        &trace, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, &matched);
    const uint32_t extended = iwx_group2_tx_trace_match_completion_ex(
        &trace, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, &matched,
        &related_sidecar);
    return (int)(legacy + extended + related_sidecar);
}
