/*
 * Narrow Hostap compatibility layer for the AX201 SAE implementation.
 *
 * Hostap's SAE and Dragonfly sources are retained from the pinned upstream
 * revision. This header supplies only the common/crypto interfaces needed by
 * those two translation units; it deliberately disables debug output so SAE
 * secrets are never written to the driver log.
 */
#ifndef AX201_SAE_PORT_H
#define AX201_SAE_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ETH_ALEN 6
#define SHA256_MAC_LEN 32
#define RSN_SELECTOR_LEN 4
#define WPA_PROTO_RSN 0x02
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_ANTI_CLOGGING_TOKEN_REQ 76
#define WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED 77
#define WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER 123

#define WLAN_EID_EXTENSION 255
#define WLAN_EID_EXT_PASSWORD_IDENTIFIER 33
#define WLAN_EID_EXT_REJECTED_GROUPS 92
#define WLAN_EID_EXT_ANTI_CLOGGING_TOKEN 93
#define WLAN_EID_EXT_AKM_SUITE_SELECTOR 114

#define RSN_AUTH_KEY_MGMT_SAE 0x000fac08U
#define RSN_AUTH_KEY_MGMT_FT_SAE 0x000fac09U
#define RSN_AUTH_KEY_MGMT_SAE_EXT_KEY 0x000fac18U
#define RSN_AUTH_KEY_MGMT_FT_SAE_EXT_KEY 0x000fac19U
#define WPA_KEY_MGMT_SAE 0x00000001
#define WPA_KEY_MGMT_SAE_EXT_KEY 0x00000002
#define WPA_KEY_MGMT_FT_SAE_EXT_KEY 0x00000004

#define WPA_GET_LE16(p) ((u16) ((const u8 *) (p))[0] | \
			 ((u16) ((const u8 *) (p))[1] << 8))
#define WPA_PUT_LE16(p, v) do { \
	((u8 *) (p))[0] = (u8) (v); \
	((u8 *) (p))[1] = (u8) ((v) >> 8); \
} while (0)
#define RSN_SELECTOR_GET(p) ((u32) ((const u8 *) (p))[0] << 24 | \
			     (u32) ((const u8 *) (p))[1] << 16 | \
			     (u32) ((const u8 *) (p))[2] << 8 | \
			     (u32) ((const u8 *) (p))[3])
#define RSN_SELECTOR_PUT(p, v) do { \
	((u8 *) (p))[0] = (u8) ((v) >> 24); \
	((u8 *) (p))[1] = (u8) ((v) >> 16); \
	((u8 *) (p))[2] = (u8) ((v) >> 8); \
	((u8 *) (p))[3] = (u8) (v); \
} while (0)

#define MSG_INFO 1
#define MSG_DEBUG 2

struct wpabuf;

/* Never expose passwords, PWE values, scalars, PMKs, or confirms in logs. */
#ifdef SAE_TEST_LOG
#include <stdarg.h>
#include <stdio.h>
static inline void wpa_printf(int level, const char *format, ...)
{
	va_list args;
	(void) level;
	va_start(args, format);
	vfprintf(stderr, format, args);
	fputc('\n', stderr);
	va_end(args);
}
#else
static inline void wpa_printf(int level, const char *format, ...)
{
	(void) level;
	(void) format;
}
#endif

static inline void wpa_hexdump(int level, const char *title,
			       const void *data, size_t len)
{
	(void) level; (void) title; (void) data; (void) len;
}

static inline void wpa_hexdump_key(int level, const char *title,
				   const void *data, size_t len)
{
	(void) level; (void) title; (void) data; (void) len;
}

static inline void wpa_hexdump_ascii(int level, const char *title,
				     const void *data, size_t len)
{
	(void) level; (void) title; (void) data; (void) len;
}

static inline void wpa_hexdump_ascii_key(int level, const char *title,
					 const void *data, size_t len)
{
	(void) level; (void) title; (void) data; (void) len;
}

static inline void wpa_hexdump_buf(int level, const char *title,
				   const struct wpabuf *buf)
{
	(void) level; (void) title; (void) buf;
}

static inline void wpa_hexdump_key_buf(int level, const char *title,
					const struct wpabuf *buf)
{
	(void) level; (void) title; (void) buf;
}

struct os_reltime {
	int64_t sec;
	int64_t usec;
};

/* Only the member layout touched by the upstream, unsupported FFC paths. */
struct dh_group {
	const u8 *prime;
	size_t prime_len;
	const u8 *order;
	size_t order_len;
	int safe_prime;
};

struct wpabuf {
	size_t size;
	size_t used;
	u8 *buf;
};

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_zalloc(size_t size);
size_t os_strlen(const char *str);
int os_memcmp(const void *a, const void *b, size_t len);
int os_memcmp_const(const void *a, const void *b, size_t len);
void *os_memcpy(void *dst, const void *src, size_t len);
void *os_memset(void *dst, int value, size_t len);
void forced_memzero(void *ptr, size_t len);
void bin_clear_free(void *ptr, size_t len);

struct crypto_bignum;
struct crypto_ec;
struct crypto_ec_point;
struct crypto_ec_key;

struct wpabuf *wpabuf_alloc(size_t len);
struct wpabuf *wpabuf_alloc_copy(const void *data, size_t len);
void wpabuf_free(struct wpabuf *buf);
void *wpabuf_put(struct wpabuf *buf, size_t len);

static inline size_t
wpabuf_len(const struct wpabuf *buf)
{
	return buf ? buf->used : 0;
}

static inline const void *
wpabuf_head(const struct wpabuf *buf)
{
	return buf ? buf->buf : NULL;
}

static inline void
wpabuf_put_data(struct wpabuf *buf, const void *data, size_t len)
{
	void *dst = wpabuf_put(buf, len);
	if (dst && data && len)
		os_memcpy(dst, data, len);
}

static inline void
wpabuf_put_buf(struct wpabuf *dst, const struct wpabuf *src)
{
	if (src)
		wpabuf_put_data(dst, src->buf, src->used);
}

static inline void
wpabuf_put_u8(struct wpabuf *buf, u8 value)
{
	u8 *dst = (u8 *) wpabuf_put(buf, 1);
	if (dst)
		*dst = value;
}

static inline void
wpabuf_put_le16(struct wpabuf *buf, u16 value)
{
	u8 *dst = (u8 *) wpabuf_put(buf, 2);
	if (dst)
		WPA_PUT_LE16(dst, value);
}

static inline unsigned int
const_time_fill_msb(unsigned int value)
{
	return (value >> (sizeof(value) * 8 - 1)) * ~0U;
}

static inline unsigned int
const_time_is_zero(unsigned int value)
{
	return const_time_fill_msb(~value & (value - 1));
}

static inline unsigned int
const_time_eq(unsigned int a, unsigned int b)
{
	return const_time_is_zero(a ^ b);
}

static inline u8
const_time_eq_u8(unsigned int a, unsigned int b)
{
	return (u8) const_time_eq(a, b);
}

static inline int
const_time_select_int(unsigned int mask, int if_true, int if_false)
{
	return (int) ((mask & (unsigned int) if_true) |
		      (~mask & (unsigned int) if_false));
}

static inline u8
const_time_select_u8(u8 mask, u8 if_true, u8 if_false)
{
	return (u8) ((mask & if_true) | ((u8) ~mask & if_false));
}

static inline void
const_time_select_bin(u8 mask, const u8 *if_true, const u8 *if_false,
		      size_t len, u8 *out)
{
	size_t i;
	for (i = 0; i < len; i++)
		out[i] = const_time_select_u8(mask, if_true[i], if_false[i]);
}

static inline int
const_time_memcmp(const void *a, const void *b, size_t len)
{
	const u8 *aa = (const u8 *) a;
	const u8 *bb = (const u8 *) b;
	int diff, result = 0;
	unsigned int mask;
	if (len == 0)
		return 0;
	do {
		len--;
		diff = (int) aa[len] - (int) bb[len];
		mask = const_time_is_zero((unsigned int) diff);
		result = const_time_select_int(mask, result, diff);
	} while (len);
	return result;
}

static inline void
buf_shift_right(u8 *buf, size_t len, size_t bits)
{
	size_t i;
	if (!buf || !len || bits == 0 || bits >= 8)
		return;
	for (i = len - 1; i > 0; i--)
		buf[i] = (u8) ((buf[i - 1] << (8 - bits)) | (buf[i] >> bits));
	buf[0] >>= bits;
}

static inline int
sae_abs_int(int value)
{
	return value < 0 ? -value : value;
}

#define abs(value) sae_abs_int(value)

int random_get_bytes(u8 *buf, size_t len);
const struct dh_group *dh_groups_get(int group);
int int_array_len(const int *values);
int wpa_key_mgmt_sae_ext_key(int akmp);
u32 wpa_akm_to_suite(int akmp);
const char *wpa_key_mgmt_txt(int akmp, int proto);

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		       const u8 *addr[], const size_t *len, u8 *mac);
int sha256_prf(const u8 *key, size_t key_len, const char *label,
	       const u8 *data, size_t data_len, u8 *buf, size_t buf_len);
int sha256_prf_bits(const u8 *key, size_t key_len, const char *label,
		    const u8 *data, size_t data_len, u8 *buf,
		    size_t buf_len_bits);
int sha384_prf(const u8 *key, size_t key_len, const char *label,
	       const u8 *data, size_t data_len, u8 *buf, size_t buf_len);
int sha512_prf(const u8 *key, size_t key_len, const char *label,
	       const u8 *data, size_t data_len, u8 *buf, size_t buf_len);
int hkdf_extract(size_t hash_len, const u8 *salt, size_t salt_len,
		 size_t num_elem, const u8 *addr[], const size_t len[], u8 *prk);
int hkdf_expand(size_t hash_len, const u8 *prk, size_t prk_len,
		const char *info, u8 *okm, size_t okm_len);

#include "sae_mbedtls.h"

#endif /* AX201_SAE_PORT_H */
