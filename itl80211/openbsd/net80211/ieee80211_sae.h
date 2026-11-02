/*
 * AX201 native SAE interface.
 *
 * The public entry points are available only to the Tahoe target, which links
 * the separately compiled, pinned SAE crypto archive. Legacy targets receive
 * fail-closed inline stubs so shared net80211 sources remain linkable.
 */
#ifndef IEEE80211_SAE_H
#define IEEE80211_SAE_H

#include <stddef.h>
#include <stdint.h>

struct ieee80211com;
struct ieee80211_node;

enum ieee80211_sae_auth_result {
	IEEE80211_SAE_AUTH_FAILED = -1,
	IEEE80211_SAE_AUTH_IGNORED = 0,
	IEEE80211_SAE_AUTH_HANDLED = 1,
	IEEE80211_SAE_AUTH_COMPLETE = 2
};

#ifdef AIRPORT_TAHOE
#ifdef __cplusplus
extern "C" {
#endif

int ieee80211_sae_set_password(struct ieee80211com *, const uint8_t *, size_t);
void ieee80211_sae_clear(struct ieee80211com *);
void ieee80211_sae_reset_session(struct ieee80211com *);
void ieee80211_sae_finish_auth(struct ieee80211com *);
void ieee80211_sae_state_transition(struct ieee80211com *, int, int);
int ieee80211_sae_start(struct ieee80211com *, struct ieee80211_node *);
int ieee80211_sae_build_auth(struct ieee80211com *, struct ieee80211_node *,
			     uint16_t, uint8_t *, size_t, size_t *);
int ieee80211_sae_input_auth(struct ieee80211com *, struct ieee80211_node *,
			     uint16_t, uint16_t, const uint8_t *, size_t);

#ifdef __cplusplus
}
#endif
#else
static inline int
ieee80211_sae_set_password(struct ieee80211com *ic, const uint8_t *password,
			   size_t length)
{
	(void)ic;
	(void)password;
	(void)length;
	return -1;
}

static inline void
ieee80211_sae_clear(struct ieee80211com *ic)
{
	(void)ic;
}

static inline void
ieee80211_sae_reset_session(struct ieee80211com *ic)
{
	(void)ic;
}

static inline void
ieee80211_sae_finish_auth(struct ieee80211com *ic)
{
	(void)ic;
}

static inline void
ieee80211_sae_state_transition(struct ieee80211com *ic, int oldstate,
			       int newstate)
{
	(void)ic;
	(void)oldstate;
	(void)newstate;
}

static inline int
ieee80211_sae_start(struct ieee80211com *ic, struct ieee80211_node *ni)
{
	(void)ic;
	(void)ni;
	return -1;
}

static inline int
ieee80211_sae_build_auth(struct ieee80211com *ic, struct ieee80211_node *ni,
			 uint16_t sequence, uint8_t *output, size_t capacity,
			 size_t *output_length)
{
	(void)ic;
	(void)ni;
	(void)sequence;
	(void)output;
	(void)capacity;
	(void)output_length;
	return -1;
}

static inline int
ieee80211_sae_input_auth(struct ieee80211com *ic, struct ieee80211_node *ni,
			 uint16_t sequence, uint16_t status, const uint8_t *data,
			 size_t length)
{
	(void)ic;
	(void)ni;
	(void)sequence;
	(void)status;
	(void)data;
	(void)length;
	return -1;
}
#endif

#endif /* IEEE80211_SAE_H */
