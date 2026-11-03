/* SPDX-License-Identifier: GPL-2.0-only */
/* Offline parser regression for Test122's bounded TX-status classifier. */
#define main test122_sender_entry
#include "awdl_router_status_sender_test122.c"
#undef main

#define CHECK(condition, label) do { \
    if (!(condition)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static void set_sequence(uint8_t *mpdu, unsigned wifi, unsigned awdl) {
    uint16_t sequence_control=(uint16_t)((wifi&0x0fffU)<<4);
    mpdu[22]=(uint8_t)sequence_control;
    mpdu[23]=(uint8_t)(sequence_control>>8);
    mpdu[34]=(uint8_t)awdl;
    mpdu[35]=(uint8_t)(awdl>>8);
    memcpy(mpdu+88,"T086RX01",8);
}

int main(void) {
    CHECK(capture_loss_free_state(true,false,false,false,false,0,0,0)==-1,
          "missing_kernel_stats_is_unknown");
    CHECK(capture_loss_free_state(true,false,false,true,false,0,0,0)==0,
          "known_truncation_is_not_unknown");
    CHECK(capture_loss_free_state(false,false,false,false,true,4,0,4)==0,
          "unfinished_window_is_lossy_or_incomplete");
    CHECK(capture_loss_free_state(true,false,false,false,true,4,0,4)==1,
          "complete_equal_kernel_and_user_counts_is_clean");
    CHECK(capture_loss_free_state(true,false,false,false,true,4,1,4)==0,
          "kernel_drop_is_not_loss_free");

    uint8_t mpdu[MPDU_LEN]={0};
    set_sequence(mpdu,291U,0x1230U);
    struct packet_set set;memset(&set,0,sizeof(set));
    for(unsigned i=0;i<FRAME_COUNT;i++) {
        uint8_t *expected=set.bytes+HEADER_LEN+i*PACKET_LEN+RTAP_LEN;
        memcpy(expected,mpdu,sizeof(mpdu));
        set_sequence(expected,291U+i,0x1230U+i);
    }

    /* T121's real radiotap shape: one TX_FLAGS field, NOSEQNO only. */
    const uint8_t base_rtap[RTAP_LEN]={0x00,0x00,0x0a,0x00,0x00,0x80,0x00,0x00,0x10,0x00};
    uint8_t packet[STATUS_RAW_BYTES]={0};
    memcpy(packet,base_rtap,sizeof(base_rtap));
    memcpy(packet+RTAP_LEN,mpdu,sizeof(mpdu));
    struct t089_observation parsed;
    CHECK(t089_parse_observation(packet,RTAP_LEN+MPDU_LEN,T089_PACKET_OUTGOING,
                                mpdu,&parsed)==T089_PARSE_VALID,
          "base_radiotap_parse");
    CHECK(parsed.exact_probe_match && parsed.is_outgoing_echo &&
          parsed.has_tx_flags && parsed.tx_flags==0x0010U &&
          !parsed.has_data_retries,
          "outgoing_echo_classification");

    /* TX completion can alter a header byte; preserve only an exact payload
     * marker + sequence-linked candidate, never broaden exact attribution. */
    uint8_t status_packet[STATUS_RAW_BYTES]={0};
    static const uint8_t status_rtap[11]={
        0x00,0x00,0x0b,0x00,0x00,0x80,0x02,0x00,0x10,0x00,0x03
    };
    memcpy(status_packet,status_rtap,sizeof(status_rtap));
    uint8_t changed[MPDU_LEN];memcpy(changed,mpdu,sizeof(changed));
    changed[2]^=0x01U;
    memcpy(status_packet+sizeof(status_rtap),changed,sizeof(changed));
    CHECK(t089_parse_observation(status_packet,sizeof(status_rtap)+MPDU_LEN,
                                T089_PACKET_OTHERHOST,mpdu,&parsed)==T089_PARSE_VALID,
          "status_radiotap_parse");
    CHECK(!parsed.exact_probe_match && parsed.has_tx_flags &&
          parsed.tx_flags==0x0010U && parsed.has_data_retries &&
          parsed.data_retries==3U,
          "changed_header_not_exact");
    CHECK(is_status_candidate(status_packet,sizeof(status_rtap)+MPDU_LEN,
                             T089_PACKET_OTHERHOST,&parsed),
          "changed_header_marker_candidate");
    CHECK(probe_ordinal_from_sequences(status_packet,&parsed,&set)==0,
          "sequence_maps_to_packetset_ordinal");
    CHECK(!is_status_candidate(status_packet,sizeof(status_rtap)+MPDU_LEN,
                              T089_PACKET_OUTGOING,&parsed),
          "outgoing_not_completion_candidate");

    /* A radiotap FCS flag must not prevent exact MPDU attribution. */
    uint8_t fcs_packet[STATUS_RAW_BYTES]={0};
    const uint8_t fcs_rtap[12]={
        0x00,0x00,0x0c,0x00,0x02,0x80,0x00,0x00,0x10,0x00,0x10,0x00
    };
    memcpy(fcs_packet,fcs_rtap,sizeof(fcs_rtap));
    memcpy(fcs_packet+sizeof(fcs_rtap),mpdu,sizeof(mpdu));
    memset(fcs_packet+sizeof(fcs_rtap)+MPDU_LEN,0xa5,4);
    CHECK(t089_parse_observation(fcs_packet,sizeof(fcs_rtap)+MPDU_LEN+4,
                                T089_PACKET_OUTGOING,mpdu,&parsed)==T089_PARSE_VALID &&
          parsed.has_radiotap_flags && (parsed.radiotap_flags&0x10U) &&
          parsed.mpdu_length==MPDU_LEN && parsed.exact_probe_match,
          "radiotap_fcs_handling");

    uint8_t no_marker[MPDU_LEN];memcpy(no_marker,changed,sizeof(no_marker));
    memcpy(status_packet+sizeof(status_rtap),no_marker,sizeof(no_marker));
    status_packet[sizeof(status_rtap)+95]^=0xffU;
    CHECK(t089_parse_observation(status_packet,sizeof(status_rtap)+MPDU_LEN,
                                T089_PACKET_OTHERHOST,mpdu,&parsed)==T089_PARSE_VALID &&
          !is_status_candidate(status_packet,sizeof(status_rtap)+MPDU_LEN,
                              T089_PACKET_OTHERHOST,&parsed),
          "marker_mismatch_rejected");

    uint8_t unsupported[8+MPDU_LEN]={0};
    unsupported[2]=8;unsupported[7]=0x40; /* vendor namespace bit */
    memcpy(unsupported+8,mpdu,sizeof(mpdu));
    CHECK(t089_parse_observation(unsupported,sizeof(unsupported),
                                T089_PACKET_OTHERHOST,mpdu,&parsed)==T089_PARSE_UNSUPPORTED,
          "unknown_vendor_namespace_fails_closed");
    CHECK(t089_parse_observation(packet,7,T089_PACKET_OUTGOING,mpdu,&parsed)==T089_PARSE_INVALID,
          "truncated_radiotap_fails_closed");
    uint8_t bad_len[RTAP_LEN+MPDU_LEN];memcpy(bad_len,packet,sizeof(bad_len));
    bad_len[2]=0xff;bad_len[3]=0x00;
    CHECK(t089_parse_observation(bad_len,sizeof(bad_len),
                                T089_PACKET_OUTGOING,mpdu,&parsed)==T089_PARSE_INVALID,
          "radiotap_length_overrun_fails_closed");

    puts("PASS Test122 radiotap status parser and candidate attribution");
    return 0;
}
