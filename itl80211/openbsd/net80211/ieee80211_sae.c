/*
 * AX201 station-mode SAE authentication state machine.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>

#include <IOKit/IOLib.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_sae.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "../../../../third_party/sae/hostap/sae_port.h"
#include "../../../../third_party/sae/hostap/sae.h"
#ifdef __cplusplus
}
#endif

#define IEEE80211_SAE_AUTH_ALG		3
#define IEEE80211_SAE_GROUP		19
#define IEEE80211_SAE_H2E_STATUS	126
#define IEEE80211_SAE_TOKEN_STATUS	76
#define IEEE80211_SAE_TOKEN_CONTAINER	255
#define IEEE80211_SAE_TOKEN_EXTENSION	93
#define IEEE80211_SAE_AUTH_MAX		512
#define IEEE80211_SAE_TOKEN_MAX		128
#define IEEE80211_SAE_ATTEMPTS_MAX	4
#define IEEE80211_SAE_CONFIRM_RETRIES_MAX	3

struct ieee80211_sae_exchange {
	struct sae_data sae;
	struct wpabuf *token;
	u_int8_t peer[IEEE80211_ADDR_LEN];
	u_int8_t own[IEEE80211_ADDR_LEN];
	u_int8_t essid[IEEE80211_NWID_LEN];
	u_int8_t esslen;
	u_int8_t commit[IEEE80211_SAE_AUTH_MAX];
	u_int8_t confirm[2 + SAE_KCK_LEN];
	u_int8_t peer_confirm[2 + SAE_KCK_LEN];
	size_t commit_len;
	size_t confirm_len;
	size_t peer_confirm_len;
	u_int16_t last_peer_confirm;
	u_int8_t attempts;
	u_int8_t token_retries;
	u_int8_t confirm_retries;
	u_int8_t h2e;
	u_int8_t peer_commit_seen;
	u_int8_t confirm_sent;
	u_int8_t completed;
};

static int
ieee80211_sae_context_matches(struct ieee80211com *ic,
			      struct ieee80211_node *ni,
			      struct ieee80211_sae_exchange *exchange)
{
	return exchange != NULL && ni != NULL &&
	    ni->ni_rsnakms == IEEE80211_AKM_SAE &&
	    IEEE80211_ADDR_EQ(exchange->peer, ni->ni_bssid) &&
	    IEEE80211_ADDR_EQ(exchange->own, ic->ic_myaddr) &&
	    exchange->esslen == ni->ni_esslen &&
	    exchange->h2e == (ni->ni_sae_h2e != 0) &&
	    exchange->esslen <= sizeof(exchange->essid) &&
	    memcmp(exchange->essid, ni->ni_essid, exchange->esslen) == 0;
}

static void
ieee80211_sae_free_exchange(struct ieee80211com *ic)
{
	struct ieee80211_sae_exchange *exchange;

	exchange = (struct ieee80211_sae_exchange *)ic->ic_sae_exchange;
	if (exchange == NULL)
		return;
	ic->ic_sae_exchange = NULL;
	sae_clear_data(&exchange->sae);
	wpabuf_free(exchange->token);
	explicit_bzero(exchange, sizeof(*exchange));
	IOFree(exchange, sizeof(*exchange));
}

static int
ieee80211_sae_write_commit(struct ieee80211_sae_exchange *exchange)
{
	struct wpabuf *buf;
	size_t length;
	int error;

	buf = wpabuf_alloc(sizeof(exchange->commit));
	if (buf == NULL)
		return ENOMEM;
	error = sae_write_commit(&exchange->sae, buf, exchange->token,
				NULL, 0);
	length = wpabuf_len(buf);
	if (error == 0 && length <= sizeof(exchange->commit)) {
		memcpy(exchange->commit, wpabuf_head(buf), length);
		exchange->commit_len = length;
	} else if (error == 0)
		error = EMSGSIZE;
	wpabuf_free(buf);
	return error;
}

static int
ieee80211_sae_send_commit(struct ieee80211com *ic,
			  struct ieee80211_node *ni,
			  struct ieee80211_sae_exchange *exchange)
{
	int error;

	error = ieee80211_sae_write_commit(exchange);
	if (error != 0)
		return error;
	return IEEE80211_SEND_MGMT(ic, ni,
	    IEEE80211_FC0_SUBTYPE_AUTH, IEEE80211_AUTH_OPEN_REQUEST) == 0 ?
	    0 : EIO;
}

int
ieee80211_sae_set_password(struct ieee80211com *ic, const uint8_t *password,
	size_t length)
{
	u_int8_t copy[sizeof(ic->ic_sae_password)];

	if (ic == NULL || password == NULL || length == 0 ||
	    length > sizeof(ic->ic_sae_password))
		return EINVAL;

	memcpy(copy, password, length);
	ieee80211_sae_clear(ic);
	memcpy(ic->ic_sae_password, copy, length);
	ic->ic_sae_password_len = (u_int8_t)length;
	explicit_bzero(copy, sizeof(copy));
	return 0;
}

void
ieee80211_sae_reset_session(struct ieee80211com *ic)
{
	if (ic == NULL)
		return;
	ieee80211_sae_free_exchange(ic);
	if (ic->ic_bss != NULL) {
		explicit_bzero(ic->ic_bss->ni_pmk,
		    sizeof(ic->ic_bss->ni_pmk));
		explicit_bzero(ic->ic_bss->ni_pmkid,
		    sizeof(ic->ic_bss->ni_pmkid));
		ic->ic_bss->ni_flags &=
		    ~(IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID);
		ic->ic_bss->ni_port_valid = 0;
		ic->ic_bss->ni_replaycnt_ok = 0;
	}
}

void
ieee80211_sae_finish_auth(struct ieee80211com *ic)
{
	if (ic == NULL)
		return;
	ieee80211_sae_free_exchange(ic);
}

void
ieee80211_sae_clear(struct ieee80211com *ic)
{
	if (ic == NULL)
		return;
	ieee80211_sae_reset_session(ic);
	explicit_bzero(ic->ic_sae_password, sizeof(ic->ic_sae_password));
	ic->ic_sae_password_len = 0;
}

void
ieee80211_sae_state_transition(struct ieee80211com *ic, int oldstate,
	int newstate)
{
	if (ic == NULL || ic->ic_opmode != IEEE80211_M_STA)
		return;
	if (newstate == IEEE80211_S_INIT) {
		ieee80211_sae_clear(ic);
	} else if (newstate == IEEE80211_S_SCAN &&
	    (oldstate == IEEE80211_S_AUTH || oldstate == IEEE80211_S_ASSOC) &&
	    ic->ic_bss != NULL &&
	    ic->ic_bss->ni_rsnakms == IEEE80211_AKM_SAE) {
		/* Retry another BSS without carrying an exchange or stale PMK. */
		ieee80211_sae_reset_session(ic);
	} else if (newstate == IEEE80211_S_RUN &&
	    oldstate == IEEE80211_S_ASSOC && ic->ic_bss != NULL &&
	    ic->ic_bss->ni_rsnakms == IEEE80211_AKM_SAE) {
		/* PMK is now owned by the 4-way handshake; Confirm cache is not. */
		ieee80211_sae_finish_auth(ic);
	}
}

int
ieee80211_sae_start(struct ieee80211com *ic, struct ieee80211_node *ni)
{
	struct ieee80211_sae_exchange *previous, *exchange;
	struct sae_pt *pt = NULL;
	int groups[] = { IEEE80211_SAE_GROUP, 0 };
	u_int8_t attempts = 1;
	int error = EIO;

	if (ic == NULL || ni == NULL || ic->ic_opmode != IEEE80211_M_STA ||
	    ic->ic_state != IEEE80211_S_AUTH ||
	    ni->ni_esslen > IEEE80211_NWID_LEN ||
	    ic->ic_sae_password_len == 0 ||
	    ic->ic_sae_password_len > sizeof(ic->ic_sae_password) ||
	    ni->ni_rsnakms != IEEE80211_AKM_SAE)
		return EINVAL;

	previous = (struct ieee80211_sae_exchange *)ic->ic_sae_exchange;
	if (ieee80211_sae_context_matches(ic, ni, previous)) {
		if (previous->attempts >= IEEE80211_SAE_ATTEMPTS_MAX)
			return EAGAIN;
		attempts = previous->attempts + 1;
	}
	ieee80211_sae_free_exchange(ic);

	exchange = (struct ieee80211_sae_exchange *)IOMallocZero(sizeof(*exchange));
	if (exchange == NULL)
		return ENOMEM;
	memcpy(exchange->peer, ni->ni_bssid, sizeof(exchange->peer));
	memcpy(exchange->own, ic->ic_myaddr, sizeof(exchange->own));
	exchange->esslen = ni->ni_esslen;
	memcpy(exchange->essid, ni->ni_essid, exchange->esslen);
	exchange->attempts = attempts;
	exchange->h2e = ni->ni_sae_h2e != 0;
	if (sae_set_group(&exchange->sae, IEEE80211_SAE_GROUP) != 0)
		goto fail;
	exchange->sae.akmp = WPA_KEY_MGMT_SAE;

	if (exchange->h2e) {
		if (ni->ni_esslen == 0 || ni->ni_esslen > IEEE80211_NWID_LEN)
			goto fail;
		pt = sae_derive_pt(groups, ni->ni_essid, ni->ni_esslen,
		    ic->ic_sae_password, ic->ic_sae_password_len, NULL, 0);
		if (pt == NULL || sae_prepare_commit_pt(&exchange->sae, pt,
		    ic->ic_myaddr, ni->ni_bssid, NULL, NULL) != 0)
			goto fail;
		sae_deinit_pt(pt);
		pt = NULL;
	} else if (sae_prepare_commit(ic->ic_myaddr, ni->ni_bssid,
	    ic->ic_sae_password, ic->ic_sae_password_len,
	    &exchange->sae) != 0)
		goto fail;

	if (ieee80211_sae_write_commit(exchange) != 0)
		goto fail;
	ic->ic_sae_exchange = exchange;
	explicit_bzero(ni->ni_pmk, sizeof(ni->ni_pmk));
	explicit_bzero(ni->ni_pmkid, sizeof(ni->ni_pmkid));
	ni->ni_flags &= ~(IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID);
	return 0;

fail:
	if (pt != NULL)
		sae_deinit_pt(pt);
	if (exchange != NULL) {
		sae_clear_data(&exchange->sae);
		wpabuf_free(exchange->token);
		explicit_bzero(exchange, sizeof(*exchange));
		IOFree(exchange, sizeof(*exchange));
	}
	return error;
}

int
ieee80211_sae_build_auth(struct ieee80211com *ic,
	struct ieee80211_node *ni, uint16_t sequence, uint8_t *output,
	size_t capacity, size_t *output_length)
{
	struct ieee80211_sae_exchange *exchange;
	const u_int8_t *payload;
	size_t payload_length;
	u_int16_t status;

	if (ic == NULL || ni == NULL || output == NULL || output_length == NULL)
		return EINVAL;
	exchange = (struct ieee80211_sae_exchange *)ic->ic_sae_exchange;
	if (!ieee80211_sae_context_matches(ic, ni, exchange)) {
		ieee80211_sae_reset_session(ic);
		return ENOENT;
	}

	if (exchange->completed) {
		if (ic->ic_state != IEEE80211_S_ASSOC ||
		    sequence != IEEE80211_AUTH_OPEN_RESPONSE ||
		    exchange->confirm_len == 0)
			return EINVAL;
		payload = exchange->confirm;
		payload_length = exchange->confirm_len;
		status = 0;
	} else if (sequence == IEEE80211_AUTH_OPEN_REQUEST) {
		payload = exchange->commit;
		payload_length = exchange->commit_len;
		status = exchange->h2e ? IEEE80211_SAE_H2E_STATUS : 0;
	} else if (sequence == IEEE80211_AUTH_OPEN_RESPONSE &&
	    exchange->confirm_sent) {
		payload = exchange->confirm;
		payload_length = exchange->confirm_len;
		status = 0;
	} else
		return EINVAL;

	if (payload_length > capacity || capacity - payload_length < 6)
		return EMSGSIZE;
	LE_WRITE_2(output, IEEE80211_SAE_AUTH_ALG);
	LE_WRITE_2(output + 2, sequence);
	LE_WRITE_2(output + 4, status);
	memcpy(output + 6, payload, payload_length);
	*output_length = 6 + payload_length;
	return 0;
}

int
ieee80211_sae_input_auth(struct ieee80211com *ic, struct ieee80211_node *ni,
	uint16_t sequence, uint16_t status, const uint8_t *data, size_t length)
{
	struct ieee80211_sae_exchange *exchange;
	int groups[] = { IEEE80211_SAE_GROUP, 0 };
	u_int16_t confirm_count;
	u_int16_t expected_status;
	int parse_status;

	if (ic == NULL || ni == NULL || ic->ic_opmode != IEEE80211_M_STA ||
	    (ic->ic_state != IEEE80211_S_AUTH &&
	     ic->ic_state != IEEE80211_S_ASSOC) || ni != ic->ic_bss)
		return IEEE80211_SAE_AUTH_IGNORED;
	exchange = (struct ieee80211_sae_exchange *)ic->ic_sae_exchange;
	if (!ieee80211_sae_context_matches(ic, ni, exchange)) {
		ieee80211_sae_reset_session(ic);
		return IEEE80211_SAE_AUTH_IGNORED;
	}
	if (exchange->completed) {
		/*
		 * Some APs send their Confirm immediately after Commit. If our
		 * Confirm was lost, accept only the byte-identical authenticated
		 * peer Confirm while association is pending and retransmit the
		 * cached local Confirm. No SAE keys or KCK are retained here.
		 */
		if (ic->ic_state != IEEE80211_S_ASSOC ||
		    sequence != IEEE80211_AUTH_OPEN_RESPONSE || status != 0 ||
		    data == NULL || length != exchange->peer_confirm_len ||
		    memcmp(data, exchange->peer_confirm, length) != 0)
			return IEEE80211_SAE_AUTH_IGNORED;
		if (exchange->confirm_retries >=
		    IEEE80211_SAE_CONFIRM_RETRIES_MAX)
			return IEEE80211_SAE_AUTH_HANDLED;
		/* Reserve this bounded retry before send can revalidate context. */
		exchange->confirm_retries++;
		if (IEEE80211_SEND_MGMT(ic, ni,
		    IEEE80211_FC0_SUBTYPE_AUTH, IEEE80211_AUTH_OPEN_RESPONSE) != 0)
			return IEEE80211_SAE_AUTH_FAILED;
		return IEEE80211_SAE_AUTH_HANDLED;
	}
	if (ic->ic_state != IEEE80211_S_AUTH)
		return IEEE80211_SAE_AUTH_IGNORED;

	if (sequence == IEEE80211_AUTH_OPEN_REQUEST &&
	    status == IEEE80211_SAE_TOKEN_STATUS) {
		const u_int8_t *token_data;
		size_t token_length;

		if (exchange->peer_commit_seen || exchange->token_retries != 0 ||
		    data == NULL || length < 2 ||
		    WPA_GET_LE16(data) != IEEE80211_SAE_GROUP)
			return IEEE80211_SAE_AUTH_FAILED;
		token_data = data + 2;
		token_length = length - 2;
		if (exchange->h2e) {
			u_int8_t element_length;

			if (token_length < 3 ||
			    token_data[0] != IEEE80211_SAE_TOKEN_CONTAINER)
				return IEEE80211_SAE_AUTH_FAILED;
			element_length = token_data[1];
			if (element_length < 2 ||
			    element_length > token_length - 2 ||
			    token_data[2] != IEEE80211_SAE_TOKEN_EXTENSION)
				return IEEE80211_SAE_AUTH_FAILED;
			token_length = element_length - 1;
			token_data += 3;
		} else if (token_length < SHA256_MAC_LEN) {
			/* Hostap's H&P commit parser only recognizes tokens of at
			 * least one SHA-256 output; shorter tokens are ambiguous
			 * with the scalar/element fields. */
			return IEEE80211_SAE_AUTH_FAILED;
		}
		if (token_length == 0 || token_length > IEEE80211_SAE_TOKEN_MAX)
			return IEEE80211_SAE_AUTH_FAILED;
		exchange->token = wpabuf_alloc_copy(token_data, token_length);
		if (exchange->token == NULL)
			return IEEE80211_SAE_AUTH_FAILED;
		exchange->token_retries++;
		if (ieee80211_sae_send_commit(ic, ni, exchange) != 0)
			return IEEE80211_SAE_AUTH_FAILED;
		return IEEE80211_SAE_AUTH_HANDLED;
	}

	if (sequence == IEEE80211_AUTH_OPEN_REQUEST) {
		expected_status = exchange->h2e ? IEEE80211_SAE_H2E_STATUS : 0;
		if (exchange->peer_commit_seen)
			return IEEE80211_SAE_AUTH_IGNORED;
		if (status != expected_status || data == NULL || length < 2 ||
		    length > IEEE80211_SAE_AUTH_MAX)
			return IEEE80211_SAE_AUTH_FAILED;
		parse_status = sae_parse_commit(&exchange->sae, data, length,
		    NULL, NULL, groups, exchange->h2e, NULL);
		if (parse_status == SAE_SILENTLY_DISCARD)
			return IEEE80211_SAE_AUTH_IGNORED;
		if (parse_status != WLAN_STATUS_SUCCESS ||
		    sae_process_commit(&exchange->sae) != 0)
			return IEEE80211_SAE_AUTH_FAILED;
		exchange->peer_commit_seen = 1;
		{
			struct wpabuf *confirm = wpabuf_alloc(sizeof(exchange->confirm));
			if (confirm == NULL ||
			    sae_write_confirm(&exchange->sae, confirm) != 0 ||
			    wpabuf_len(confirm) > sizeof(exchange->confirm)) {
				wpabuf_free(confirm);
				return IEEE80211_SAE_AUTH_FAILED;
			}
			exchange->confirm_len = wpabuf_len(confirm);
			memcpy(exchange->confirm, wpabuf_head(confirm),
			    exchange->confirm_len);
			wpabuf_free(confirm);
		}
		exchange->confirm_sent = 1;
		if (IEEE80211_SEND_MGMT(ic, ni,
		    IEEE80211_FC0_SUBTYPE_AUTH, IEEE80211_AUTH_OPEN_RESPONSE) != 0)
			return IEEE80211_SAE_AUTH_FAILED;
		return IEEE80211_SAE_AUTH_HANDLED;
	}

	if (sequence == IEEE80211_AUTH_OPEN_RESPONSE) {
		if (status != 0 || data == NULL || length != sizeof(exchange->confirm) ||
		    !exchange->peer_commit_seen || !exchange->confirm_sent)
			return status != 0 ? IEEE80211_SAE_AUTH_FAILED :
			    IEEE80211_SAE_AUTH_IGNORED;
		confirm_count = WPA_GET_LE16(data);
		if (confirm_count == 0 || confirm_count == 0xffff ||
		    confirm_count <= exchange->last_peer_confirm ||
		    sae_check_confirm(&exchange->sae, data, length, NULL) != 0)
			return IEEE80211_SAE_AUTH_FAILED;
		exchange->last_peer_confirm = confirm_count;
		memcpy(ni->ni_pmk, exchange->sae.pmk, IEEE80211_PMK_LEN);
		memcpy(ni->ni_pmkid, exchange->sae.pmkid, IEEE80211_PMKID_LEN);
		/* Bind the freshly derived PMK to this SAE association. */
		ni->ni_flags |= IEEE80211_NODE_PMK | IEEE80211_NODE_PMKID;
		ni->ni_port_valid = 0;
		ni->ni_replaycnt_ok = 0;
		memcpy(exchange->peer_confirm, data, length);
		exchange->peer_confirm_len = length;
		exchange->completed = 1;
		/* Retain only the two public Confirm bodies for bounded retry. */
		sae_clear_data(&exchange->sae);
		wpabuf_free(exchange->token);
		exchange->token = NULL;
		explicit_bzero(exchange->commit, sizeof(exchange->commit));
		exchange->commit_len = 0;
		return IEEE80211_SAE_AUTH_COMPLETE;
	}

	return IEEE80211_SAE_AUTH_IGNORED;
}
