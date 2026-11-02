/*
 * AX201 kernel allocation hooks for the vendored Mbed TLS subset.
 * Copyright (c) 2026 AX201 Native SAE contributors.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <mbedtls/sae_mbedtls_port.h>

#include <stdint.h>
#include <string.h>

#ifdef KERNEL
#include <IOKit/IOLib.h>

struct sae_mbedtls_allocation {
    size_t payload_size;
};

void *
sae_mbedtls_calloc(size_t count, size_t size)
{
    struct sae_mbedtls_allocation *allocation;
    size_t payload_size;

    if (count != 0 && size > SIZE_MAX / count)
        return NULL;
    payload_size = count * size;
    if (payload_size > SIZE_MAX - sizeof(*allocation))
        return NULL;

    allocation = (struct sae_mbedtls_allocation *)
        IOMalloc(sizeof(*allocation) + payload_size);
    if (allocation == NULL)
        return NULL;

    allocation->payload_size = payload_size;
    bzero(allocation + 1, payload_size);
    return allocation + 1;
}

void
sae_mbedtls_free(void *ptr)
{
    struct sae_mbedtls_allocation *allocation;
    size_t allocation_size;

    if (ptr == NULL)
        return;
    allocation = ((struct sae_mbedtls_allocation *)ptr) - 1;
    allocation_size = sizeof(*allocation) + allocation->payload_size;
    bzero(ptr, allocation->payload_size);
    allocation->payload_size = 0;
    IOFree(allocation, allocation_size);
}

#else

#include <stdlib.h>

void *
sae_mbedtls_calloc(size_t count, size_t size)
{
    if (count != 0 && size > SIZE_MAX / count)
        return NULL;
    return calloc(count, size);
}

void
sae_mbedtls_free(void *ptr)
{
    free(ptr);
}

#endif
