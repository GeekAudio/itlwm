/*
 * Offline Hostap SAE + Mbed TLS engine tests.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hostap/sae_port.h"
#include "../hostap/sae.h"

static const u8 sta_addr[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const u8 ap_addr[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const u8 ssid[] = { 's','a','e','-','o','f','f','l','i','n','e' };
static const u8 password[] = {
	'A','X','2','0','1','-','S','A','E','-','6','4','-',
	'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
	'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V',
	'W','X','Y','Z','!','@','#','$','%','^','&','*','(',')','_','+',
	'=', '?', '~'
};
static const u8 p256_generator[64] = {
	0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
	0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
	0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
	0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
};

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		goto fail; \
	} \
} while (0)

static int
test_p256_generator(void)
{
	struct crypto_ec *ec = crypto_ec_init(19);
	struct crypto_ec_point *point = NULL;
	struct crypto_bignum *x = NULL, *y = NULL, *curve_y2 = NULL,
		*point_y2 = NULL;
	int ret = -1;
	if (!ec)
		goto done;
	point = crypto_ec_point_from_bin(ec, p256_generator);
	x = crypto_bignum_init_set(p256_generator, 32);
	y = crypto_bignum_init_set(p256_generator + 32, 32);
	curve_y2 = x ? crypto_ec_point_compute_y_sqr(ec, x) : NULL;
	point_y2 = crypto_bignum_init();
	if (curve_y2 && point_y2 &&
	    crypto_bignum_sqrmod(y, crypto_ec_get_prime(ec), point_y2) == 0 &&
	    crypto_bignum_cmp(curve_y2, point_y2) == 0 && point)
		ret = 0;
done:
	crypto_bignum_deinit(x, 1);
	crypto_bignum_deinit(y, 1);
	crypto_bignum_deinit(curve_y2, 1);
	crypto_bignum_deinit(point_y2, 1);
	crypto_ec_point_deinit(point, 1);
	crypto_ec_deinit(ec);
	return ret;
}

static int
prepare_party(struct sae_data *sae, int h2e, const struct sae_pt *pt,
	      const u8 *own_addr, const u8 *peer_addr)
{
	if (sae_set_group(sae, 19) < 0)
		return -1;
	sae->akmp = WPA_KEY_MGMT_SAE;
	/* A standard SAE commit does not carry the SAE-EXT-KEY selector IE. */
	if (h2e)
		return sae_prepare_commit_pt(sae, pt, own_addr, peer_addr,
					     NULL, NULL);
	return sae_prepare_commit(own_addr, peer_addr, password,
			  sizeof(password), sae);
}

static int
test_bad_commit(int h2e, const struct sae_pt *pt)
{
	struct sae_data probe = { 0 };
	struct sae_pt *owned_pt = NULL;
	struct wpabuf *own = NULL;
	int allowed_groups[] = { 19, 0 };
	const u8 *token = NULL;
	size_t token_len = 0;
	int ie_offset = 0;
	u8 damaged[128];
	int ret = -1;

	if (h2e && !pt) {
		int groups[] = { 19, 0 };
		owned_pt = sae_derive_pt(groups, ssid, sizeof(ssid), password,
					 sizeof(password), NULL, 0);
		if (!owned_pt)
			goto done;
		pt = owned_pt;
	}
	if (prepare_party(&probe, h2e, pt, sta_addr, ap_addr) < 0)
		goto done;
	own = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
	if (!own || sae_write_commit(&probe, own, NULL, NULL, 0) < 0)
		goto done;
	CHECK(wpabuf_len(own) == 98);

	/* Reflection of our own scalar and element must be silently discarded. */
	CHECK(sae_parse_commit(&probe, wpabuf_head(own), wpabuf_len(own),
			       &token, &token_len, allowed_groups, h2e,
			       &ie_offset) == SAE_SILENTLY_DISCARD);

	/* A zero scalar is out of range. */
	memcpy(damaged, wpabuf_head(own), wpabuf_len(own));
	memset(damaged + 2, 0, 32);
	CHECK(sae_parse_commit(&probe, damaged, wpabuf_len(own), &token,
			       &token_len, allowed_groups, h2e, &ie_offset) !=
	      WLAN_STATUS_SUCCESS);

	/* A zero affine point is not a valid P-256 point. */
	memcpy(damaged, wpabuf_head(own), wpabuf_len(own));
	memset(damaged + 34, 0, 64);
	CHECK(sae_parse_commit(&probe, damaged, wpabuf_len(own), &token,
			       &token_len, allowed_groups, h2e, &ie_offset) !=
	      WLAN_STATUS_SUCCESS);

	/* Group 20 is explicitly unsupported by this group-19-only backend. */
	memcpy(damaged, wpabuf_head(own), wpabuf_len(own));
	damaged[0] = 20;
	damaged[1] = 0;
	CHECK(sae_parse_commit(&probe, damaged, wpabuf_len(own), &token,
			       &token_len, allowed_groups, h2e, &ie_offset) ==
	      WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED);
	ret = 0;
fail:
	forced_memzero(damaged, sizeof(damaged));
done:
	wpabuf_free(own);
	sae_clear_data(&probe);
	sae_deinit_pt(owned_pt);
	return ret;
}

static int
test_exchange(int h2e)
{
	struct sae_data sta = { 0 }, ap = { 0 };
	struct sae_pt *pt = NULL;
	struct wpabuf *sta_commit = NULL, *ap_commit = NULL;
	struct wpabuf *sta_confirm = NULL, *ap_confirm = NULL;
	int groups[] = { 19, 0 };
	int allowed_sta[] = { 19, 0 }, allowed_ap[] = { 19, 0 };
	const u8 *token = NULL;
	size_t token_len = 0;
	int ie_offset = 0;
	u8 bad_confirm[SAE_CONFIRM_MAX_LEN];
	int prepare_status;
	int ret = -1;

	if (h2e) {
		pt = sae_derive_pt(groups, ssid, sizeof(ssid), password,
				   sizeof(password), NULL, 0);
		CHECK(pt != NULL);
	}
	prepare_status = prepare_party(&sta, h2e, pt, sta_addr, ap_addr);
	if (prepare_status < 0)
		fprintf(stderr, "SAE prepare failed (H2E=%d, party=STA)\n", h2e);
	CHECK(prepare_status == 0);
	prepare_status = prepare_party(&ap, h2e, pt, ap_addr, sta_addr);
	if (prepare_status < 0)
		fprintf(stderr, "SAE prepare failed (H2E=%d, party=AP)\n", h2e);
	CHECK(prepare_status == 0);

	sta_commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
	ap_commit = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
	CHECK(sta_commit && ap_commit);
	CHECK(sae_write_commit(&sta, sta_commit, NULL, NULL, 0) == 0);
	CHECK(sae_write_commit(&ap, ap_commit, NULL, NULL, 0) == 0);
	CHECK(wpabuf_len(sta_commit) == 98 && wpabuf_len(ap_commit) == 98);

	CHECK(sae_parse_commit(&sta, wpabuf_head(ap_commit),
			       wpabuf_len(ap_commit), &token, &token_len,
			       allowed_sta, h2e, &ie_offset) ==
	      WLAN_STATUS_SUCCESS);
	CHECK(sae_process_commit(&sta) == 0);
	CHECK(sae_parse_commit(&ap, wpabuf_head(sta_commit),
			       wpabuf_len(sta_commit), &token, &token_len,
			       allowed_ap, h2e, &ie_offset) ==
	      WLAN_STATUS_SUCCESS);
	CHECK(sae_process_commit(&ap) == 0);
	CHECK(sta.pmk_len == 32 && ap.pmk_len == 32);
	CHECK(const_time_memcmp(sta.pmk, ap.pmk, 32) == 0);

	sta_confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
	ap_confirm = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
	CHECK(sta_confirm && ap_confirm);
	CHECK(sae_write_confirm(&sta, sta_confirm) == 0);
	CHECK(sae_write_confirm(&ap, ap_confirm) == 0);
	CHECK(wpabuf_len(sta_confirm) == 34 && wpabuf_len(ap_confirm) == 34);

	/* Bad confirm data is rejected; the valid transcript still verifies. */
	memcpy(bad_confirm, wpabuf_head(sta_confirm), wpabuf_len(sta_confirm));
	bad_confirm[2 + 7] ^= 0x80;
	CHECK(sae_check_confirm(&ap, bad_confirm, wpabuf_len(sta_confirm),
				&ie_offset) < 0);
	CHECK(sae_check_confirm(&ap, wpabuf_head(sta_confirm),
				wpabuf_len(sta_confirm), &ie_offset) == 0);
	CHECK(sae_check_confirm(&sta, wpabuf_head(ap_confirm),
				wpabuf_len(ap_confirm), &ie_offset) == 0);
	ret = 0;
fail:
	forced_memzero(bad_confirm, sizeof(bad_confirm));
	wpabuf_free(sta_commit);
	wpabuf_free(ap_commit);
	wpabuf_free(sta_confirm);
	wpabuf_free(ap_confirm);
	sae_clear_data(&sta);
	sae_clear_data(&ap);
	sae_deinit_pt(pt);
	return ret;
}

int
main(void)
{
	if (sizeof(password) != 64) {
		fprintf(stderr, "test fixture password must remain 64 bytes\n");
		return 1;
	}
	if (test_p256_generator() < 0) {
		fprintf(stderr, "P-256 generator arithmetic test failed\n");
		return 1;
	}
	if (test_exchange(0) < 0 || test_bad_commit(0, NULL) < 0 ||
	    test_exchange(1) < 0 || test_bad_commit(1, NULL) < 0) {
		fprintf(stderr, "SAE offline engine test failed\n");
		return 1;
	}
	puts("SAE group 19 H&P/H2E offline engine tests passed");
	return 0;
}
