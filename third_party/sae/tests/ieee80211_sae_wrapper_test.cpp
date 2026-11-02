/*
 * Offline tests of the production net80211 SAE wrapper and Authentication
 * frame body. The included implementation is the exact Tahoe .c source.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "../hostap/sae_port.h"
#include "../hostap/sae.h"
#ifdef __cplusplus
}
#endif

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_sae.h>

struct test_capture {
	u_int8_t body[512];
	size_t length;
	unsigned int sends;
	int last_sequence;
};

struct test_radio {
	struct ieee80211com ic;
	struct ieee80211_node ni;
	struct test_capture capture;
};

static const u_int8_t test_password[] = "test-sae-password";
static const u_int8_t test_ssid[] = "sae-wrapper-lab";

static int
test_fake_send_mgmt(struct ieee80211com *ic, struct ieee80211_node *ni,
	int sequence)
{
	struct test_capture *capture = (struct test_capture *)ic->test_context;
	int error;

	error = ieee80211_sae_build_auth(ic, ni, (u_int16_t)sequence,
	    capture->body, sizeof(capture->body), &capture->length);
	if (error != 0)
		return error;
	capture->last_sequence = sequence;
	capture->sends++;
	return 0;
}

#include "../../../itl80211/openbsd/net80211/ieee80211_sae.c"

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		goto fail; \
	} \
} while (0)

static void
init_radio(struct test_radio *radio, const u_int8_t *own,
	const u_int8_t *peer, int h2e)
{
	memset(radio, 0, sizeof(*radio));
	radio->ic.ic_opmode = IEEE80211_M_STA;
	radio->ic.ic_state = IEEE80211_S_AUTH;
	radio->ic.ic_bss = &radio->ni;
	radio->ic.test_context = &radio->capture;
	memcpy(radio->ic.ic_myaddr, own, IEEE80211_ADDR_LEN);
	memcpy(radio->ni.ni_bssid, peer, IEEE80211_ADDR_LEN);
	memcpy(radio->ni.ni_essid, test_ssid, sizeof(test_ssid) - 1);
	radio->ni.ni_esslen = sizeof(test_ssid) - 1;
	radio->ni.ni_rsnakms = IEEE80211_AKM_SAE;
	radio->ni.ni_sae_h2e = h2e;
}

static int
start_radio(struct test_radio *radio)
{
	return ieee80211_sae_set_password(&radio->ic, test_password,
	    sizeof(test_password) - 1) == 0 &&
	    ieee80211_sae_start(&radio->ic, &radio->ni) == 0;
}

static int
build_auth(struct test_radio *radio, int sequence, u_int8_t *body,
	size_t capacity, size_t *length)
{
	return ieee80211_sae_build_auth(&radio->ic, &radio->ni,
	    (u_int16_t)sequence, body, capacity, length);
}

static int
input_auth(struct test_radio *radio, const u_int8_t *body, size_t length)
{
	if (length < 6)
		return IEEE80211_SAE_AUTH_FAILED;
	return ieee80211_sae_input_auth(&radio->ic, &radio->ni,
	    WPA_GET_LE16(body + 2), WPA_GET_LE16(body + 4), body + 6,
	    length - 6);
}

static int
make_counted_confirm(struct test_radio *radio, u_int16_t count,
	u_int8_t body[6 + 2 + SAE_KCK_LEN])
{
	struct ieee80211_sae_exchange *exchange;
	struct wpabuf *confirm;
	int error = -1;

	exchange = (struct ieee80211_sae_exchange *)radio->ic.ic_sae_exchange;
	if (exchange == NULL || count == 0)
		return -1;
	confirm = wpabuf_alloc(2 + SAE_KCK_LEN);
	if (confirm == NULL)
		return -1;
	/* Wrapper has emitted count 1 already. Generate the real next MIC. */
	exchange->sae.send_confirm = (u_int16_t)(count - 1);
	if (sae_write_confirm(&exchange->sae, confirm) != 0 ||
	    wpabuf_len(confirm) != 2 + SAE_KCK_LEN)
		goto done;
	LE_WRITE_2(body, 3);
	LE_WRITE_2(body + 2, IEEE80211_AUTH_OPEN_RESPONSE);
	LE_WRITE_2(body + 4, 0);
	memcpy(body + 6, wpabuf_head(confirm), wpabuf_len(confirm));
	error = 0;
done:
	wpabuf_free(confirm);
	return error;
}

static int
test_full_exchange(int h2e)
{
	const u_int8_t sta_addr[6] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x01 };
	const u_int8_t ap_addr[6] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x02 };
	struct test_radio sta, ap;
	u_int8_t sta_commit[IEEE80211_SAE_AUTH_MAX];
	u_int8_t ap_commit[IEEE80211_SAE_AUTH_MAX];
	u_int8_t bad_confirm[6 + 2 + SAE_KCK_LEN];
	u_int8_t confirm2[6 + 2 + SAE_KCK_LEN];
	u_int8_t bad_count[6 + 2 + SAE_KCK_LEN];
	u_int8_t early_confirm[6 + 2 + SAE_KCK_LEN] = { 0 };
	u_int8_t first_local_confirm[512];
	u_int8_t changed_confirm[6 + 2 + SAE_KCK_LEN];
	struct ieee80211_sae_exchange *completed_exchange;
	size_t sta_commit_len = 0, ap_commit_len = 0;
	size_t first_local_confirm_len = 0;
	u_int16_t accepted_count = h2e ? 0xfffe : 2;
	int ret = -1;

	init_radio(&sta, sta_addr, ap_addr, h2e);
	init_radio(&ap, ap_addr, sta_addr, h2e);
	CHECK(start_radio(&sta) && start_radio(&ap));
	CHECK(sta.ic.ic_sae_password_len == sizeof(test_password) - 1 &&
	    memcmp(sta.ic.ic_sae_password, test_password,
	    sizeof(test_password) - 1) == 0);
	CHECK(build_auth(&sta, 1, sta_commit, sizeof(sta_commit),
	    &sta_commit_len) == 0);
	CHECK(build_auth(&ap, 1, ap_commit, sizeof(ap_commit),
	    &ap_commit_len) == 0);
	CHECK(WPA_GET_LE16(sta_commit) == 3 &&
	    WPA_GET_LE16(sta_commit + 2) == 1 &&
	    WPA_GET_LE16(sta_commit + 4) == (h2e ? 126 : 0));
	CHECK(WPA_GET_LE16(sta_commit + 6) == 19);
	CHECK(WPA_GET_LE16(early_confirm + 2) == 0);
	CHECK(ieee80211_sae_input_auth(&sta.ic, &sta.ni, 2, 0,
	    early_confirm + 6, sizeof(early_confirm) - 6) ==
	    IEEE80211_SAE_AUTH_IGNORED);
	/* Reflection of the local commit is silently discarded by Hostap SAE. */
	CHECK(input_auth(&sta, sta_commit, sta_commit_len) ==
	    IEEE80211_SAE_AUTH_IGNORED);
	CHECK(input_auth(&ap, sta_commit, sta_commit_len) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(input_auth(&sta, ap_commit, ap_commit_len) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(sta.capture.last_sequence == IEEE80211_AUTH_OPEN_RESPONSE &&
	    ap.capture.last_sequence == IEEE80211_AUTH_OPEN_RESPONSE);
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	CHECK((ap.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	/* A duplicate Commit is ignored and does not emit a second Confirm. */
	{
		int duplicate_result = input_auth(&ap, sta_commit, sta_commit_len);
		if (duplicate_result != IEEE80211_SAE_AUTH_IGNORED)
			fprintf(stderr, "duplicate commit result %d (h2e=%d)\n",
			    duplicate_result, h2e);
		CHECK(duplicate_result == IEEE80211_SAE_AUTH_IGNORED);
	}
	CHECK(ap.capture.sends == 1);
	/* A bad MIC must not set PMK or PMKID; the later valid confirm still works. */
	memcpy(bad_confirm, ap.capture.body, ap.capture.length);
	bad_confirm[6 + 7] ^= 0x80;
	CHECK(input_auth(&sta, bad_confirm, ap.capture.length) ==
	    IEEE80211_SAE_AUTH_FAILED);
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	memcpy(bad_count, ap.capture.body, ap.capture.length);
	LE_WRITE_2(bad_count + 6, 0);
	CHECK(input_auth(&sta, bad_count, ap.capture.length) ==
	    IEEE80211_SAE_AUTH_FAILED);
	CHECK(make_counted_confirm(&ap, 0xffff, bad_count) == 0);
	CHECK(input_auth(&sta, bad_count, sizeof(bad_count)) ==
	    IEEE80211_SAE_AUTH_FAILED);
	CHECK(make_counted_confirm(&ap, accepted_count, confirm2) == 0);
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_COMPLETE);
	completed_exchange = (struct ieee80211_sae_exchange *)
	    sta.ic.ic_sae_exchange;
	CHECK(sta.capture.last_sequence == IEEE80211_AUTH_OPEN_RESPONSE &&
	    sta.capture.length <= sizeof(first_local_confirm));
	CHECK(completed_exchange != NULL && completed_exchange->completed &&
	    completed_exchange->sae.tmp == NULL);
	for (size_t i = 0; i < sizeof(completed_exchange->sae.pmk); i++)
		CHECK(completed_exchange->sae.pmk[i] == 0);
	memcpy(first_local_confirm, sta.capture.body, sta.capture.length);
	first_local_confirm_len = sta.capture.length;
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) ==
	    (IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID));
	CHECK(sta.ic.ic_sae_exchange != NULL);
	CHECK(sta.ni.ni_port_valid == 0 && sta.ni.ni_replaycnt_ok == 0);
	/*
	 * Model an immediate-confirm AP: deliver its Confirm but drop the STA's
	 * first outgoing Confirm. The AP must remain pending until our cached
	 * Confirm is retransmitted after the station enters S_ASSOC.
	 */
	CHECK((ap.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	sta.ic.ic_state = IEEE80211_S_ASSOC;
	ieee80211_sae_state_transition(&sta.ic, IEEE80211_S_AUTH,
	    IEEE80211_S_ASSOC);
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(sta.capture.sends == 2 &&
	    sta.capture.length == first_local_confirm_len &&
	    memcmp(sta.capture.body, first_local_confirm,
	    first_local_confirm_len) == 0);
	CHECK(sta.ni.ni_port_valid == 0 && sta.ni.ni_replaycnt_ok == 0);
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) ==
	    (IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID));
	/* Non-identical confirms and new Commits cannot use the retry cache. */
	memcpy(changed_confirm, confirm2, sizeof(changed_confirm));
	changed_confirm[sizeof(changed_confirm) - 1] ^= 0x01;
	CHECK(input_auth(&sta, changed_confirm, sizeof(changed_confirm)) ==
	    IEEE80211_SAE_AUTH_IGNORED);
	CHECK(input_auth(&sta, ap_commit, ap_commit_len) ==
	    IEEE80211_SAE_AUTH_IGNORED);
	CHECK(sta.capture.sends == 2);
	/* A few exact retries are permitted, then the S_ASSOC cache is bounded. */
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(sta.capture.sends == 4 &&
	    memcmp(sta.capture.body, first_local_confirm,
	    first_local_confirm_len) == 0);
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_HANDLED);
	CHECK(sta.capture.sends == 4);
	/* AP accepts only after receiving the retransmitted local Confirm. */
	CHECK(input_auth(&ap, sta.capture.body, sta.capture.length) ==
	    IEEE80211_SAE_AUTH_COMPLETE);
	CHECK(memcmp(sta.ni.ni_pmk, ap.ni.ni_pmk, IEEE80211_PMK_LEN) == 0);
	CHECK(memcmp(sta.ni.ni_pmkid, ap.ni.ni_pmkid,
	    IEEE80211_PMKID_LEN) == 0);
	/* RUN discards retry state while preserving password and 4-way PMK. */
	sta.ic.ic_state = IEEE80211_S_RUN;
	ieee80211_sae_state_transition(&sta.ic, IEEE80211_S_ASSOC,
	    IEEE80211_S_RUN);
	CHECK(sta.ic.ic_sae_exchange == NULL &&
	    sta.ic.ic_sae_password_len == sizeof(test_password) - 1);
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) ==
	    (IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID));
	/* Completed-session confirm replay after RUN is ignored. */
	CHECK(input_auth(&sta, confirm2, sizeof(confirm2)) ==
	    IEEE80211_SAE_AUTH_IGNORED);
	ieee80211_sae_clear(&sta.ic);
	ieee80211_sae_clear(&ap.ic);
	CHECK(sta.ic.ic_sae_exchange == NULL && ap.ic.ic_sae_exchange == NULL);
	CHECK(sta.ic.ic_sae_password_len == 0 && ap.ic.ic_sae_password_len == 0);
	CHECK((sta.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	CHECK((ap.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	ret = 0;
fail:
	ieee80211_sae_clear(&sta.ic);
	ieee80211_sae_clear(&ap.ic);
	return ret;
}

static int
test_session_lifecycle(void)
{
	const u_int8_t own[6] = { 0x02, 0x12, 0x20, 0x30, 0x40, 0x11 };
	const u_int8_t peer[6] = { 0x02, 0x12, 0x20, 0x30, 0x40, 0x12 };
	struct test_radio radio;
	int ret = -1;

	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	memset(radio.ni.ni_pmk, 0xa5, sizeof(radio.ni.ni_pmk));
	memset(radio.ni.ni_pmkid, 0x5a, sizeof(radio.ni.ni_pmkid));
	radio.ni.ni_flags |= IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID;
	radio.ni.ni_port_valid = 1;
	radio.ni.ni_replaycnt_ok = 1;
	radio.ic.ic_state = IEEE80211_S_SCAN;
	ieee80211_sae_state_transition(&radio.ic, IEEE80211_S_AUTH,
	    IEEE80211_S_SCAN);
	CHECK(radio.ic.ic_sae_exchange == NULL);
	CHECK(radio.ic.ic_sae_password_len == sizeof(test_password) - 1 &&
	    memcmp(radio.ic.ic_sae_password, test_password,
	    sizeof(test_password) - 1) == 0);
	CHECK((radio.ni.ni_flags & (IEEE80211_NODE_PMK |
	    IEEE80211_NODE_PMKID)) == 0);
	CHECK(radio.ni.ni_port_valid == 0 && radio.ni.ni_replaycnt_ok == 0);
	for (size_t i = 0; i < sizeof(radio.ni.ni_pmk); i++)
		CHECK(radio.ni.ni_pmk[i] == 0);
	for (size_t i = 0; i < sizeof(radio.ni.ni_pmkid); i++)
		CHECK(radio.ni.ni_pmkid[i] == 0);
	radio.ic.ic_state = IEEE80211_S_AUTH;
	CHECK(ieee80211_sae_start(&radio.ic, &radio.ni) == 0);
	radio.ic.ic_state = IEEE80211_S_INIT;
	ieee80211_sae_state_transition(&radio.ic, IEEE80211_S_AUTH,
	    IEEE80211_S_INIT);
	CHECK(radio.ic.ic_sae_exchange == NULL &&
	    radio.ic.ic_sae_password_len == 0);
	for (size_t i = 0; i < sizeof(radio.ic.ic_sae_password); i++)
		CHECK(radio.ic.ic_sae_password[i] == 0);
	ret = 0;
fail:
	ieee80211_sae_clear(&radio.ic);
	return ret;
}

static int
test_challenge(int h2e)
{
	const u_int8_t own[6] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x11 };
	const u_int8_t peer[6] = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x12 };
	struct test_radio radio;
	u_int8_t challenge[2 + 3 + 129];
	u_int8_t auth[IEEE80211_SAE_AUTH_MAX];
	u_int8_t token[32];
	size_t auth_len = 0, challenge_len;
	int ret = -1;

	memset(token, 0x5a, sizeof(token));
	memset(challenge, 0, sizeof(challenge));
	LE_WRITE_2(challenge, 19);
	if (h2e) {
		challenge[2] = 255;
		challenge[3] = 1 + sizeof(token);
		challenge[4] = 93;
		memcpy(challenge + 5, token, sizeof(token));
		challenge_len = 5 + sizeof(token);
	} else {
		memcpy(challenge + 2, token, sizeof(token));
		challenge_len = 2 + sizeof(token);
	}
	init_radio(&radio, own, peer, h2e);
	CHECK(start_radio(&radio));
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, challenge_len) == IEEE80211_SAE_AUTH_HANDLED);
	CHECK(radio.capture.sends == 1 &&
	    radio.capture.last_sequence == IEEE80211_AUTH_OPEN_REQUEST);
	CHECK(build_auth(&radio, 1, auth, sizeof(auth), &auth_len) == 0);
	CHECK(auth_len >= 6 + 2 + 96);
	if (h2e) {
		CHECK(auth[auth_len - sizeof(token) - 3] == 255);
		CHECK(auth[auth_len - sizeof(token) - 2] == 1 + sizeof(token));
		CHECK(auth[auth_len - sizeof(token) - 1] == 93);
		CHECK(memcmp(auth + auth_len - sizeof(token), token,
		    sizeof(token)) == 0);
	} else {
		CHECK(WPA_GET_LE16(auth + 6) == 19);
		CHECK(memcmp(auth + 8, token, sizeof(token)) == 0);
	}
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, challenge_len) == IEEE80211_SAE_AUTH_FAILED);
	CHECK(radio.capture.sends == 1);
	ieee80211_sae_clear(&radio.ic);
	/* Challenge with unsupported group is rejected before token allocation. */
	init_radio(&radio, own, peer, h2e);
	CHECK(start_radio(&radio));
	LE_WRITE_2(challenge, 20);
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, challenge_len) == IEEE80211_SAE_AUTH_FAILED);
	ieee80211_sae_clear(&radio.ic);
	ret = 0;
fail:
	ieee80211_sae_clear(&radio.ic);
	return ret;
}

static int
test_invalid_challenge_and_identity(void)
{
	const u_int8_t own[6] = { 0x02, 0x11, 0x20, 0x30, 0x40, 0x11 };
	const u_int8_t peer[6] = { 0x02, 0x11, 0x20, 0x30, 0x40, 0x12 };
	struct test_radio radio;
	u_int8_t challenge[2 + 3 + 129] = { 0 };
	u_int8_t body[IEEE80211_SAE_AUTH_MAX];
	size_t body_len;
	int ret = -1;

	init_radio(&radio, own, peer, 1);
	CHECK(start_radio(&radio));
	LE_WRITE_2(challenge, 19);
	challenge[2] = 255;
	challenge[3] = 33;
	challenge[4] = 92; /* Rejected-groups extension, not token container. */
	memset(challenge + 5, 0xa5, 32);
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, 2 + 3 + 32) == IEEE80211_SAE_AUTH_FAILED);
	ieee80211_sae_clear(&radio.ic);

	/* H2E token length must fit the body and stay inside the configured cap. */
	init_radio(&radio, own, peer, 1);
	CHECK(start_radio(&radio));
	LE_WRITE_2(challenge, 19);
	challenge[2] = 255;
	challenge[3] = 130;
	challenge[4] = 93;
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, sizeof(challenge)) == IEEE80211_SAE_AUTH_FAILED);
	ieee80211_sae_clear(&radio.ic);
	/* H&P token shorter than SHA-256 or larger than the bounded buffer fails. */
	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	LE_WRITE_2(challenge, 19);
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, 2 + 31) == IEEE80211_SAE_AUTH_FAILED);
	ieee80211_sae_clear(&radio.ic);
	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	CHECK(ieee80211_sae_input_auth(&radio.ic, &radio.ni, 1, 76,
	    challenge, 2 + 129) == IEEE80211_SAE_AUTH_FAILED);
	ieee80211_sae_clear(&radio.ic);

	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	CHECK(ieee80211_sae_start(&radio.ic, &radio.ni) == 0);
	CHECK(ieee80211_sae_start(&radio.ic, &radio.ni) == 0);
	CHECK(ieee80211_sae_start(&radio.ic, &radio.ni) == 0);
	CHECK(ieee80211_sae_start(&radio.ic, &radio.ni) == EAGAIN);
	CHECK(radio.ic.ic_sae_exchange != NULL);
	/* A changed BSSID, local MAC, or SSID cancels the bound exchange. */
	radio.ni.ni_bssid[5] ^= 0x20;
	CHECK(build_auth(&radio, 1, body, sizeof(body), &body_len) == ENOENT);
	CHECK(radio.ic.ic_sae_exchange == NULL);
	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	radio.ic.ic_myaddr[5] ^= 0x20;
	CHECK(build_auth(&radio, 1, body, sizeof(body), &body_len) == ENOENT);
	CHECK(radio.ic.ic_sae_exchange == NULL);
	init_radio(&radio, own, peer, 0);
	CHECK(start_radio(&radio));
	radio.ni.ni_essid[0] ^= 0x01;
	CHECK(build_auth(&radio, 1, body, sizeof(body), &body_len) == ENOENT);
	CHECK(radio.ic.ic_sae_exchange == NULL);
	ret = 0;
fail:
	ieee80211_sae_clear(&radio.ic);
	return ret;
}

int
main(void)
{
	if (test_full_exchange(0) < 0 || test_full_exchange(1) < 0 ||
	    test_challenge(0) < 0 || test_challenge(1) < 0 ||
	    test_invalid_challenge_and_identity() < 0 ||
	    test_session_lifecycle() < 0) {
		fputs("Production net80211 SAE wrapper test failed\n", stderr);
		return 1;
	}
	puts("Production net80211 SAE H&P/H2E wrapper body tests passed");
	return 0;
}
