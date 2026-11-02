/*
 * AX201 kernel allocation hooks for the vendored Mbed TLS subset.
 *
 * The implementations live in library/sae_mbedtls_port.c. The headers are
 * declared here because Mbed TLS expands the configured allocation macros in
 * its ECP/MPI translation units.
 */
#ifndef SAE_MBEDTLS_PORT_H
#define SAE_MBEDTLS_PORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *sae_mbedtls_calloc(size_t count, size_t size);
void sae_mbedtls_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* SAE_MBEDTLS_PORT_H */
