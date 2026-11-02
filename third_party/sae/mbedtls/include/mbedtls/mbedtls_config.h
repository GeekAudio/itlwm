/*
 * Minimal Mbed TLS configuration for the AX201 SAE P-256 engine.
 *
 * Based on Mbed TLS 3.6.7. This local configuration enables only the
 * multi-precision integer and short-Weierstrass P-256 implementation used by
 * SAE. See third_party/sae/README.md for the pinned source revision and the
 * selected GPL-2.0-or-later licensing option.
 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#include "sae_mbedtls_port.h"

#define MBEDTLS_CONFIG_VERSION 0x03060700

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_NO_UDBL_DIVISION

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_CALLOC_MACRO sae_mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO sae_mbedtls_free

/* Keep scratch use bounded in the kernel. */
#define MBEDTLS_ECP_WINDOW_SIZE 3
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0

#endif /* MBEDTLS_CONFIG_H */
