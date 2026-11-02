#ifndef AX201_SAE_TEST_IEEE80211_VAR_H
#define AX201_SAE_TEST_IEEE80211_VAR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef unsigned int u_int;

#define IEEE80211_ADDR_LEN 6
#define IEEE80211_NWID_LEN 32
#define IEEE80211_PMK_LEN 32
#define IEEE80211_PMKID_LEN 16
#define IEEE80211_M_STA 1
#define IEEE80211_S_INIT 0
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_AUTH 2
#define IEEE80211_S_ASSOC 3
#define IEEE80211_S_RUN 4
#define IEEE80211_AKM_SAE 0x10
#define IEEE80211_NODE_PMK 0x0100
#define IEEE80211_NODE_PMKID 0x0200
#define IEEE80211_FC0_SUBTYPE_AUTH 0xb0
#define IEEE80211_AUTH_OPEN_REQUEST 1
#define IEEE80211_AUTH_OPEN_RESPONSE 2
#define IEEE80211_ADDR_EQ(a, b) (memcmp((a), (b), IEEE80211_ADDR_LEN) == 0)
#ifndef WPA_GET_LE16
#define WPA_GET_LE16(p) ((u_int16_t)((const u_int8_t *)(p))[0] | \
	((u_int16_t)((const u_int8_t *)(p))[1] << 8))
#endif
#define LE_WRITE_2(p, v) do { \
	((u_int8_t *)(p))[0] = (u_int8_t)(v); \
	((u_int8_t *)(p))[1] = (u_int8_t)((v) >> 8); \
} while (0)

struct ieee80211_node {
	u_int8_t ni_bssid[IEEE80211_ADDR_LEN];
	u_int8_t ni_essid[IEEE80211_NWID_LEN];
	u_int8_t ni_esslen;
	u_int8_t ni_sae_h2e;
	u_int ni_rsnakms;
	u_int8_t ni_pmk[IEEE80211_PMK_LEN];
	u_int8_t ni_pmkid[IEEE80211_PMKID_LEN];
	u_int ni_flags;
	int ni_port_valid;
	u_int8_t ni_replaycnt_ok;
};

struct ieee80211com {
	int ic_opmode;
	int ic_state;
	struct ieee80211_node *ic_bss;
	u_int8_t ic_myaddr[IEEE80211_ADDR_LEN];
	u_int8_t ic_sae_password[64];
	u_int8_t ic_sae_password_len;
	void *ic_sae_exchange;
	void *test_context;
};

static int test_fake_send_mgmt(struct ieee80211com *, struct ieee80211_node *, int);
#define IEEE80211_SEND_MGMT(ic, ni, subtype, sequence) \
	test_fake_send_mgmt((ic), (ni), (sequence))

#endif
