// SPDX-License-Identifier: GPL-2.0-only
#pragma once

namespace NativeWifi {
// Exact identity admission is separate from Apple wireless/Skywalk ABI review.
// A recognized profile is not proof that this candidate is safe to deploy.
// OS Build Version may be absent during early IOKit matching; that path still
// requires one of the exact known kernel strings. Strict checks require a
// complete build/kernel pair.
bool verifyTahoeRuntime(bool requireOSBuild = false);

// The reconstructed AWDL lifecycle is restricted to the explicit 25G332 and
// 25G416 candidate profiles and always requires the complete build/kernel pair.
// Keep this narrower than ordinary Wi-Fi (which also admits 25G241). The
// lifecycle's native layout/start/cleanup checks remain independently required.
bool verifyTahoeAwdlRuntime();
}
