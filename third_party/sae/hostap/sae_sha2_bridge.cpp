/*
 * C ABI bridge for the project's SHA-256 implementation.
 * Copyright (c) 2026 AX201 Native SAE contributors.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/types.h>

#include "../../../itl80211/openbsd/crypto/sha2.h"
#include "sae_sha2_bridge.h"

extern "C" void
sae_sha256_init(void *context)
{
	SHA256Init(static_cast<SHA2_CTX *>(context));
}

extern "C" void
sae_sha256_update(void *context, const void *data, size_t len)
{
	SHA256Update(static_cast<SHA2_CTX *>(context), data, len);
}

extern "C" void
sae_sha256_final(uint8_t digest[32], void *context)
{
	SHA256Final(digest, static_cast<SHA2_CTX *>(context));
}
