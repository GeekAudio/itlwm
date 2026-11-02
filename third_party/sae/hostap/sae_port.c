/*
 * Hostap SAE utility and SHA-256 adapters for the AX201 driver.
 * Copyright (c) 2026 AX201 Native SAE contributors.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sae_port.h"

#include <limits.h>
#include <sys/types.h>

#include "../../../itl80211/openbsd/crypto/sha2.h"
#include "sae_sha2_bridge.h"

#ifdef KERNEL
#include <IOKit/IOLib.h>
#include "../../../itl80211/openbsd/sys/_arc4random.h"

struct sae_allocation {
	size_t size;
};
#else
#include <stdlib.h>
#include <string.h>
#endif

#define SAE_WPABUF_MAX 4096

void *
os_malloc(size_t size)
{
#ifdef KERNEL
	struct sae_allocation *allocation;

	if (size > SIZE_MAX - sizeof(*allocation))
		return NULL;
	allocation = (struct sae_allocation *) IOMalloc(sizeof(*allocation) + size);
	if (!allocation)
		return NULL;
	allocation->size = size;
	bzero(allocation + 1, size);
	return allocation + 1;
#else
	return malloc(size ? size : 1);
#endif
}

void
os_free(void *ptr)
{
	if (!ptr)
		return;
#ifdef KERNEL
	struct sae_allocation *allocation =
		((struct sae_allocation *) ptr) - 1;
	size_t allocation_size = sizeof(*allocation) + allocation->size;
	forced_memzero(ptr, allocation->size);
	allocation->size = 0;
	IOFree(allocation, allocation_size);
#else
	free(ptr);
#endif
}

void *
os_zalloc(size_t size)
{
	void *ptr = os_malloc(size);
	if (ptr)
		os_memset(ptr, 0, size);
	return ptr;
}

size_t
os_strlen(const char *str)
{
	size_t len = 0;
	if (!str)
		return 0;
	while (str[len] != '\0')
		len++;
	return len;
}

int
os_memcmp(const void *a, const void *b, size_t len)
{
	const u8 *aa = (const u8 *) a;
	const u8 *bb = (const u8 *) b;
	size_t i;

	for (i = 0; i < len; i++) {
		if (aa[i] < bb[i])
			return -1;
		if (aa[i] > bb[i])
			return 1;
	}
	return 0;
}

int
os_memcmp_const(const void *a, const void *b, size_t len)
{
	return const_time_memcmp(a, b, len);
}

void *
os_memcpy(void *dst, const void *src, size_t len)
{
	u8 *d = (u8 *) dst;
	const u8 *s = (const u8 *) src;
	size_t i;

	if (!dst || !src)
		return dst;
	for (i = 0; i < len; i++)
		d[i] = s[i];
	return dst;
}

void *
os_memset(void *dst, int value, size_t len)
{
	volatile u8 *d = (volatile u8 *) dst;
	size_t i;

	if (!dst)
		return NULL;
	for (i = 0; i < len; i++)
		d[i] = (u8) value;
	return dst;
}

void
forced_memzero(void *ptr, size_t len)
{
	volatile u8 *p = (volatile u8 *) ptr;
	size_t i;

	if (!ptr)
		return;
	for (i = 0; i < len; i++)
		p[i] = 0;
}

void
bin_clear_free(void *ptr, size_t len)
{
	if (!ptr)
		return;
	forced_memzero(ptr, len);
	os_free(ptr);
}

struct wpabuf *
wpabuf_alloc(size_t len)
{
	struct wpabuf *buf;

	if (len > SAE_WPABUF_MAX)
		return NULL;
	buf = (struct wpabuf *) os_zalloc(sizeof(*buf));
	if (!buf)
		return NULL;
	if (len) {
		buf->buf = (u8 *) os_malloc(len);
		if (!buf->buf) {
			os_free(buf);
			return NULL;
		}
	}
	buf->size = len;
	return buf;
}

struct wpabuf *
wpabuf_alloc_copy(const void *data, size_t len)
{
	struct wpabuf *buf;
	if (len && !data)
		return NULL;
	buf = wpabuf_alloc(len);
	if (buf && len) {
		os_memcpy(wpabuf_put(buf, len), data, len);
	}
	return buf;
}

void
wpabuf_free(struct wpabuf *buf)
{
	if (!buf)
		return;
	if (buf->buf)
		bin_clear_free(buf->buf, buf->size);
	forced_memzero(buf, sizeof(*buf));
	os_free(buf);
}

void *
wpabuf_put(struct wpabuf *buf, size_t len)
{
	void *ptr;
	if (!buf || len > buf->size || buf->used > buf->size - len)
		return NULL;
	ptr = buf->buf ? buf->buf + buf->used : NULL;
	buf->used += len;
	return ptr;
}

int
random_get_bytes(u8 *buf, size_t len)
{
	if (len && !buf)
		return -1;
#ifdef KERNEL
	arc4random_buf(buf, len);
#else
	arc4random_buf(buf, len);
#endif
	return 0;
}

const struct dh_group *
dh_groups_get(int group)
{
	(void) group;
	return NULL;
}

int
int_array_len(const int *values)
{
	int i;
	if (!values)
		return 0;
	for (i = 0; i < 64 && values[i]; i++)
		;
	return i;
}

int
wpa_key_mgmt_sae_ext_key(int akmp)
{
	(void) akmp;
	return 0;
}

u32
wpa_akm_to_suite(int akmp)
{
	if (akmp == WPA_KEY_MGMT_SAE_EXT_KEY)
		return RSN_AUTH_KEY_MGMT_SAE_EXT_KEY;
	if (akmp == WPA_KEY_MGMT_FT_SAE_EXT_KEY)
		return RSN_AUTH_KEY_MGMT_FT_SAE_EXT_KEY;
	return RSN_AUTH_KEY_MGMT_SAE;
}

const char *
wpa_key_mgmt_txt(int akmp, int proto)
{
	(void) proto;
	return akmp == WPA_KEY_MGMT_SAE ? "SAE" : "unsupported";
}

int
hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		   const u8 *addr[], const size_t len[], u8 *mac)
{
	SHA2_CTX ctx;
	u8 key_block[SHA256_BLOCK_LENGTH];
	u8 inner[SHA256_MAC_LEN];
	u8 hashed_key[SHA256_MAC_LEN];
	size_t i;

	if ((!key && key_len) || (!addr && num_elem) || (!len && num_elem) ||
	    !mac || key_len > UINT_MAX || num_elem > 8)
		return -1;
	os_memset(key_block, 0, sizeof(key_block));
	if (key_len > sizeof(key_block)) {
		sae_sha256_init(&ctx);
		sae_sha256_update(&ctx, key, key_len);
		sae_sha256_final(hashed_key, &ctx);
		key = hashed_key;
		key_len = sizeof(hashed_key);
	}
	os_memcpy(key_block, key, key_len);
	for (i = 0; i < sizeof(key_block); i++)
		key_block[i] ^= 0x36;
	sae_sha256_init(&ctx);
	sae_sha256_update(&ctx, key_block, sizeof(key_block));
	for (i = 0; i < num_elem; i++) {
		if ((!addr[i] && len[i]) || len[i] > UINT_MAX) {
			forced_memzero(&ctx, sizeof(ctx));
			forced_memzero(key_block, sizeof(key_block));
			forced_memzero(inner, sizeof(inner));
			forced_memzero(hashed_key, sizeof(hashed_key));
			return -1;
		}
		sae_sha256_update(&ctx, addr[i], len[i]);
	}
	sae_sha256_final(inner, &ctx);
	for (i = 0; i < sizeof(key_block); i++)
		key_block[i] ^= 0x36 ^ 0x5c;
	sae_sha256_init(&ctx);
	sae_sha256_update(&ctx, key_block, sizeof(key_block));
	sae_sha256_update(&ctx, inner, sizeof(inner));
	sae_sha256_final(mac, &ctx);
	forced_memzero(&ctx, sizeof(ctx));
	forced_memzero(key_block, sizeof(key_block));
	forced_memzero(inner, sizeof(inner));
	forced_memzero(hashed_key, sizeof(hashed_key));
	return 0;
}

int
sha256_prf_bits(const u8 *key, size_t key_len, const char *label,
		const u8 *data, size_t data_len, u8 *buf,
		size_t buf_len_bits)
{
	u8 counter_le[2], length_le[2], hash[SHA256_MAC_LEN];
	const u8 *parts[4];
	size_t lengths[4], out_len, pos = 0, copy_len;
	u32 counter = 1;
	size_t label_len;

	if (!key || !label || (!data && data_len) || (!buf && buf_len_bits) ||
	    key_len > UINT_MAX || data_len > UINT_MAX || buf_len_bits > 65535)
		return -1;
	label_len = os_strlen(label);
	if (label_len > UINT_MAX)
		return -1;
	out_len = (buf_len_bits + 7) / 8;
	WPA_PUT_LE16(length_le, (u16) buf_len_bits);
	parts[0] = counter_le;
	lengths[0] = sizeof(counter_le);
	parts[1] = (const u8 *) label;
	lengths[1] = label_len;
	parts[2] = data;
	lengths[2] = data_len;
	parts[3] = length_le;
	lengths[3] = sizeof(length_le);

	while (pos < out_len) {
		WPA_PUT_LE16(counter_le, (u16) counter);
		counter++;
		if (hmac_sha256_vector(key, key_len, 4, parts, lengths, hash) < 0) {
			forced_memzero(hash, sizeof(hash));
			return -1;
		}
		copy_len = out_len - pos;
		if (copy_len > sizeof(hash))
			copy_len = sizeof(hash);
		os_memcpy(buf + pos, hash, copy_len);
		pos += copy_len;
	}
	if (out_len && (buf_len_bits & 7))
		buf[out_len - 1] &= (u8) (0xffU << (8 - (buf_len_bits & 7)));
	forced_memzero(hash, sizeof(hash));
	return 0;
}

int
sha256_prf(const u8 *key, size_t key_len, const char *label,
	   const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
	if (buf_len > SIZE_MAX / 8)
		return -1;
	return sha256_prf_bits(key, key_len, label, data, data_len, buf,
			       buf_len * 8);
}

int
hkdf_extract(size_t hash_len, const u8 *salt, size_t salt_len,
	     size_t num_elem, const u8 *addr[], const size_t len[], u8 *prk)
{
	u8 zeros[SHA256_MAC_LEN] = { 0 };
	if (hash_len != SHA256_MAC_LEN)
		return -1;
	if (salt_len == 0) {
		salt = zeros;
		salt_len = sizeof(zeros);
	}
	return hmac_sha256_vector(salt, salt_len, num_elem, addr, len, prk);
}

int
hkdf_expand(size_t hash_len, const u8 *prk, size_t prk_len,
	    const char *info, u8 *okm, size_t okm_len)
{
	u8 previous[SHA256_MAC_LEN], counter;
	const u8 *parts[3];
	size_t lengths[3], pos = 0, take, previous_len = 0;

	if (hash_len != SHA256_MAC_LEN || !prk || !info ||
	    (!okm && okm_len) || prk_len > UINT_MAX ||
	    os_strlen(info) > UINT_MAX || okm_len > 255 * hash_len)
		return -1;
	parts[0] = previous;
	parts[1] = (const u8 *) info;
	lengths[1] = os_strlen(info);
	parts[2] = &counter;
	lengths[2] = sizeof(counter);
	while (pos < okm_len) {
		counter = (u8) (pos / hash_len + 1);
		parts[0] = previous;
		lengths[0] = previous_len;
		if (hmac_sha256_vector(prk, prk_len, 3, parts, lengths, previous) < 0) {
			forced_memzero(previous, sizeof(previous));
			return -1;
		}
		previous_len = sizeof(previous);
		take = okm_len - pos;
		if (take > sizeof(previous))
			take = sizeof(previous);
		os_memcpy(okm + pos, previous, take);
		pos += take;
	}
	forced_memzero(previous, sizeof(previous));
	return 0;
}

int
sha384_prf(const u8 *key, size_t key_len, const char *label,
	   const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
	(void) key; (void) key_len; (void) label; (void) data;
	(void) data_len; (void) buf; (void) buf_len;
	return -1;
}

int
sha512_prf(const u8 *key, size_t key_len, const char *label,
	   const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
	(void) key; (void) key_len; (void) label; (void) data;
	(void) data_len; (void) buf; (void) buf_len;
	return -1;
}
