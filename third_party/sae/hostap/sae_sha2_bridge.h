/* C ABI bridge to the project's SHA2 translation unit, built as C++. */
#ifndef AX201_SAE_SHA2_BRIDGE_H
#define AX201_SAE_SHA2_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sae_sha256_init(void *context);
void sae_sha256_update(void *context, const void *data, size_t len);
void sae_sha256_final(uint8_t digest[32], void *context);

#ifdef __cplusplus
}
#endif

#endif /* AX201_SAE_SHA2_BRIDGE_H */
