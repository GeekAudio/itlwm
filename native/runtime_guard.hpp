// SPDX-License-Identifier: GPL-2.0-only
#pragma once

namespace NativeWifi {
// 25G241 is the ABI-reviewed runtime profile. 25G332 is an admission candidate
// for recovery, not evidence that its Apple wireless/Skywalk ABI is compatible.
// OS Build Version may be absent during early IOKit matching; that path still
// requires one of the exact known kernel strings. Strict checks require a
// complete build/kernel pair.
bool verifyTahoeRuntime(bool requireOSBuild = false);
}
