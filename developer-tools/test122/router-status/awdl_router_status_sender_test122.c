/* SPDX-License-Identifier: GPL-2.0-only */
/* Test122 router-only unicast sender with an independent TX-status tail. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include "radiotap_parser.h"
#ifdef __linux__
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#define FRAME_COUNT 4U
#define INTERVAL_MS 10U
#define SEND_BUDGET_NS UINT64_C(40000000)
#define STATUS_TAIL_NS UINT64_C(2000000000)
#define STATUS_TAIL_MS 2000U
#define GO_TIMEOUT_MS 30000U
#define IFNAME_MAX 15U
#define RUN_TOKEN_HEX_LEN 32U
#define WIRE_NONCE_LEN 8U
#define WIRE_NONCE_HEX_LEN 16U
#define RTAP_LEN 10U
#define MPDU_LEN 96U
#define PACKET_LEN (RTAP_LEN + MPDU_LEN)
#define HEADER_LEN 112U
#define PACKET_SET_LEN (HEADER_LEN + FRAME_COUNT * PACKET_LEN)
#define RAW_CAPTURE_BYTES 4096U
#define RAW_CAPTURE_READ_LIMIT 4096U
#define EXACT_SAMPLE_LIMIT 16U
#define STATUS_SAMPLE_LIMIT 8U
#define NONMATCH_SAMPLE_LIMIT 8U
#define STATUS_RAW_BYTES 256U
#define NONMATCH_RAW_BYTES 256U
#define STALE_QUEUE_READ_LIMIT 256U
#define GO_TO_START_MAX_NS UINT64_C(5000000)
#define EXIT_ARGUMENT 2
#define EXIT_GATE 3
#define EXIT_INTERFACE 4
#define EXIT_SEND 5

static const uint8_t magic[8] = {'T','1','2','2','P','K','T','2'};
static const uint8_t rtap_noack_clear[RTAP_LEN] = {
    0x00,0x00,0x0a,0x00,0x00,0x80,0x00,0x00,0x10,0x00
};
static const uint8_t template_sha256[32] = {
    0xb7,0xc2,0x34,0x20,0x0d,0x11,0x7c,0xa1,
    0x7d,0x5e,0xea,0x34,0x9b,0xb3,0x22,0xd3,
    0x0f,0x0f,0xfd,0xb1,0xf0,0xf3,0x23,0xe3,
    0x6d,0x08,0xe2,0x42,0x8c,0xd5,0xee,0x61
};
static const uint8_t base[FRAME_COUNT][MPDU_LEN] = {
    {0x08,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x01,0x02,0x86,0x00,0x00,0x00,0x01,0x00,0x25,0x00,0xff,0x94,0x73,0x30,0x12,0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00,0x03,0x04,0x01,0x86,0x00,0x00,0x86,0xdd,0x60,0x00,0x00,0x00,0x00,0x10,0x11,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x86,0x00,0xff,0xfe,0x00,0x00,0x01,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xc0,0x00,0xc0,0x01,0x00,0x10,0x73,0xd0,0x54,0x30,0x38,0x36,0x52,0x58,0x30,0x31},
    {0x08,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x01,0x02,0x86,0x00,0x00,0x00,0x01,0x00,0x25,0x00,0xff,0x94,0x73,0x40,0x12,0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00,0x03,0x04,0x02,0x86,0x00,0x00,0x86,0xdd,0x60,0x00,0x00,0x00,0x00,0x10,0x11,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x86,0x00,0xff,0xfe,0x00,0x00,0x01,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xc0,0x00,0xc0,0x01,0x00,0x10,0x73,0xd0,0x54,0x30,0x38,0x36,0x52,0x58,0x30,0x31},
    {0x08,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x01,0x02,0x86,0x00,0x00,0x00,0x01,0x00,0x25,0x00,0xff,0x94,0x73,0x50,0x12,0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00,0x03,0x04,0x03,0x86,0x00,0x00,0x86,0xdd,0x60,0x00,0x00,0x00,0x00,0x10,0x11,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x86,0x00,0xff,0xfe,0x00,0x00,0x01,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xc0,0x00,0xc0,0x01,0x00,0x10,0x73,0xd0,0x54,0x30,0x38,0x36,0x52,0x58,0x30,0x31},
    {0x08,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x01,0x02,0x86,0x00,0x00,0x00,0x01,0x00,0x25,0x00,0xff,0x94,0x73,0x60,0x12,0xaa,0xaa,0x03,0x00,0x17,0xf2,0x08,0x00,0x03,0x04,0x04,0x86,0x00,0x00,0x86,0xdd,0x60,0x00,0x00,0x00,0x00,0x10,0x11,0x01,0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x86,0x00,0xff,0xfe,0x00,0x00,0x01,0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xc0,0x00,0xc0,0x01,0x00,0x10,0x73,0xd0,0x54,0x30,0x38,0x36,0x52,0x58,0x30,0x31}
};

struct options {
    bool verify_only, send, wait_go, have_file, have_mon, have_source, have_nonce;
    const char *file, *monitor, *source, *nonce;
};
struct packet_set {
    uint8_t bytes[PACKET_SET_LEN];
    uint8_t source_mac[6], target_mac[6];
    struct in6_addr source_ip, target_ip;
    uint16_t wifi_sequence_base, awdl_sequence_base;
    uint8_t wire_nonce[WIRE_NONCE_LEN];
};
struct send_sample {
    unsigned ordinal;
    unsigned ieee80211_sequence;
    unsigned ieee80211_sequence_control;
    unsigned awdl_sequence;
    uint64_t before_ns, after_ns;
    long long return_bytes;
    int error;
};
struct rx_sample {
    uint64_t observed_ns;
    bool packet_type_present;
    bool ifindex_present;
    unsigned packet_type;
    unsigned ifindex;
    unsigned msg_flags;
    size_t received_len;
    size_t copied_len;
    int exact_ordinal;
    bool parse_supported;
    bool exact_match;
    bool completion_candidate;
    bool outgoing_echo;
    bool has_tx_flags;
    uint16_t tx_flags;
    bool has_data_retries;
    uint8_t data_retries;
    unsigned ieee80211_sequence;
    unsigned ieee80211_sequence_control;
    unsigned awdl_sequence;
};
struct status_sample {
    uint64_t observed_ns;
    unsigned ordinal;
    unsigned packet_type;
    unsigned ifindex;
    unsigned msg_flags;
    size_t received_len;
    size_t copied_len;
    bool raw_truncated;
    bool exact_match;
    bool has_tx_flags;
    uint16_t tx_flags;
    bool has_data_retries;
    uint8_t data_retries;
    unsigned ieee80211_sequence;
    unsigned ieee80211_sequence_control;
    unsigned awdl_sequence;
    uint8_t raw[STATUS_RAW_BYTES];
};
struct nonmatch_sample {
    uint64_t observed_ns;
    const char *parse_status;
    bool packet_type_present;
    bool ifindex_present;
    unsigned packet_type;
    unsigned ifindex;
    unsigned msg_flags;
    size_t received_len;
    size_t copied_len;
    size_t raw_len;
    bool raw_prefix_truncated;
    uint8_t raw[NONMATCH_RAW_BYTES];
};
struct rx_observation {
    uint64_t started_ns;
    uint64_t ended_ns;
    unsigned packets_received;
    unsigned read_attempts;
    bool capture_finished;
    bool capture_limit_reached;
    bool kernel_stats_available;
    unsigned kernel_packets;
    unsigned kernel_dropped;
    int receive_error;
    unsigned exact_match[FRAME_COUNT];
    unsigned outgoing_exact[FRAME_COUNT];
    unsigned non_outgoing_exact[FRAME_COUNT];
    unsigned completion_candidate[FRAME_COUNT];
    unsigned other_exact[FRAME_COUNT];
    unsigned exact_identity_unavailable;
    unsigned radiotap_invalid;
    unsigned radiotap_unsupported;
    unsigned unmatched_valid_packets;
    unsigned truncated_packets;
    unsigned exact_samples_overflow;
    unsigned exact_samples_recorded;
    struct rx_sample samples[EXACT_SAMPLE_LIMIT];
    unsigned status_candidate_match[FRAME_COUNT];
    unsigned status_samples_recorded;
    unsigned status_samples_overflow;
    unsigned status_identity_unavailable;
    struct status_sample status_samples[STATUS_SAMPLE_LIMIT];
    unsigned nonmatch_samples_recorded;
    unsigned nonmatch_samples_overflow;
    struct nonmatch_sample nonmatch_samples[NONMATCH_SAMPLE_LIMIT];
};
struct stale_queue_observation {
    unsigned read_attempts;
    unsigned packets_drained;
    int receive_error;
    bool drain_complete;
    bool kernel_stats_available;
    unsigned kernel_packets;
    unsigned kernel_dropped;
};

static int probe_ordinal_from_sequences(const uint8_t *packet,
                                        size_t packet_length,
                                        const struct t089_observation *parsed,
                                        const struct packet_set *set);

/* -1 means unknown, 0 means known incomplete/lossy, 1 means measured clean. */
static int capture_loss_free_state(bool finished, bool receive_error,
                                   bool capture_limit, bool truncated,
                                   bool stats_available, unsigned kernel_packets,
                                   unsigned kernel_dropped, unsigned user_packets) {
    if(!finished || receive_error || capture_limit || truncated) return 0;
    if(!stats_available) return -1;
    return kernel_dropped==0 && kernel_packets==user_packets ? 1 : 0;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint16_t le16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8)); }
static bool has_wire_nonce(const uint8_t *packet, size_t packet_length,
                           const struct t089_observation *parsed,
                           const struct packet_set *set) {
    return parsed->mpdu_length == MPDU_LEN &&
        parsed->mpdu_offset <= packet_length &&
        MPDU_LEN <= packet_length - parsed->mpdu_offset &&
        memcmp(packet + parsed->mpdu_offset + 88U,
               set->wire_nonce, WIRE_NONCE_LEN) == 0;
}
static int exact_frame_ordinal(const uint8_t *packet, size_t packet_length,
                               const struct t089_observation *parsed,
                               const struct packet_set *set) {
    if (parsed->mpdu_length != MPDU_LEN ||
        parsed->mpdu_offset > packet_length ||
        MPDU_LEN > packet_length - parsed->mpdu_offset) return -1;
    const uint8_t *mpdu = packet + parsed->mpdu_offset;
    for (unsigned ordinal = 0; ordinal < FRAME_COUNT; ++ordinal) {
        const uint8_t *expected = set->bytes + HEADER_LEN +
            ordinal * PACKET_LEN + RTAP_LEN;
        if (memcmp(mpdu, expected, MPDU_LEN) == 0) return (int)ordinal;
    }
    return -1;
}
static int probe_ordinal_from_sequences(const uint8_t *packet,
                                        size_t packet_length,
                                        const struct t089_observation *parsed,
                                        const struct packet_set *set) {
    if (!has_wire_nonce(packet, packet_length, parsed, set)) return -1;
    const uint8_t *mpdu = packet + parsed->mpdu_offset;
    uint16_t sequence_control = le16(mpdu + 22U);
    uint16_t awdl_sequence = le16(mpdu + 34U);
    for (unsigned ordinal = 0; ordinal < FRAME_COUNT; ++ordinal) {
        uint16_t expected_wifi = (uint16_t)((set->wifi_sequence_base + ordinal) & 0x0fffU);
        uint16_t expected_sequence_control = (uint16_t)(expected_wifi << 4);
        uint16_t expected_awdl = (uint16_t)(set->awdl_sequence_base + ordinal);
        if (sequence_control == expected_sequence_control &&
            awdl_sequence == expected_awdl) return (int)ordinal;
    }
    return -1;
}
static bool is_status_candidate(const uint8_t *packet, size_t packet_length,
                                unsigned packet_type,
                                const struct t089_observation *parsed,
                                const struct packet_set *set,
                                int *ordinal) {
    if (ordinal) *ordinal = -1;
    if (packet_type != T089_PACKET_OTHERHOST || !parsed->has_tx_flags ||
        !parsed->has_data_retries) return false;
    int matched = probe_ordinal_from_sequences(packet, packet_length, parsed, set);
    if (matched < 0) return false;
    if (ordinal) *ordinal = matched;
    return true;
}
#ifdef __linux__
static void print_bytes_hex(const uint8_t *bytes, size_t length) {
    for(size_t i=0;i<length;i++) printf("%02x",bytes[i]);
}
#endif
static void format_bytes_hex(const uint8_t *bytes,size_t length,char *out) {
    static const char digits[]="0123456789abcdef";
    for(size_t i=0;i<length;i++){out[i*2U]=digits[bytes[i]>>4];out[i*2U+1U]=digits[bytes[i]&0x0fU];}
    out[length*2U]='\0';
}
static bool valid_name(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (!n || n > IFNAME_MAX) return false;
    for (size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)s[i];
        bool allowed = (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.';
        if (!allowed) return false;
    }
    return true;
}
static bool valid_nonce(const char *s) {
    if (!s || strlen(s)!=RUN_TOKEN_HEX_LEN) return false;
    for (size_t i=0;i<RUN_TOKEN_HEX_LEN;i++) if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false;
    return true;
}
static void usage(FILE *f,const char *p) {
    fprintf(f,"Usage: %s --verify-only --packet-set FILE\n   or: %s --send --packet-set FILE --interface MON --source-interface AP --nonce 32hex --wait-go\n",p,p);
}
static bool parse_options(int argc,char **argv,struct options *o) {
    memset(o,0,sizeof(*o));
    for (int i=1;i<argc;i++) {
        const char *a=argv[i];
        if (!strcmp(a,"--verify-only")) { if(o->verify_only)return false;o->verify_only=true;continue; }
        if (!strcmp(a,"--send")) { if(o->send)return false;o->send=true;continue; }
        if (!strcmp(a,"--wait-go")) { if(o->wait_go)return false;o->wait_go=true;continue; }
        if (!strcmp(a,"--packet-set")||!strcmp(a,"--interface")||!strcmp(a,"--source-interface")||!strcmp(a,"--nonce")) {
            if (++i>=argc)return false;const char *v=argv[i];
            if(!strcmp(a,"--packet-set")) {if(o->have_file||v[0]!='/')return false;o->have_file=true;o->file=v;}
            else if(!strcmp(a,"--interface")) {if(o->have_mon||!valid_name(v))return false;o->have_mon=true;o->monitor=v;}
            else if(!strcmp(a,"--source-interface")) {if(o->have_source||!valid_name(v))return false;o->have_source=true;o->source=v;}
            else {if(o->have_nonce||!valid_nonce(v))return false;o->have_nonce=true;o->nonce=v;}
            continue;
        }
        return false;
    }
    if(!o->have_file)return false;
    if(o->verify_only)return !o->send&&!o->wait_go&&!o->have_mon&&!o->have_source&&!o->have_nonce;
    return o->send&&o->wait_go&&o->have_mon&&o->have_source&&o->have_nonce;
}
static uint32_t sum_bytes(const uint8_t *p,size_t n,uint32_t sum) {
    size_t i=0;for(;i+1<n;i+=2)sum+=((uint32_t)p[i]<<8)|p[i+1];if(i<n)sum+=(uint32_t)p[i]<<8;return sum;
}
static uint16_t udp_checksum(const struct in6_addr *s,const struct in6_addr *d,const uint8_t *udp) {
    uint32_t sum=0;sum=sum_bytes(s->s6_addr,16,sum);sum=sum_bytes(d->s6_addr,16,sum);
    const uint8_t tail[8]={0,0,0,16,0,0,0,17};sum=sum_bytes(tail,8,sum);sum=sum_bytes(udp,16,sum);
    while(sum>>16)sum=(sum&0xffffU)+(sum>>16);
    uint16_t v=(uint16_t)~sum;return v?v:0xffffU;
}
static bool valid_mac(const uint8_t *m) { uint8_t any=0;for(unsigned i=0;i<6;i++)any|=m[i];return any&&(m[0]&1U)==0; }
static void write_le16(uint8_t *p,uint16_t value) { p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8); }
static bool build_expected_mpdu(const struct packet_set *s,unsigned ord,uint8_t out[MPDU_LEN]) {
    if(ord>=FRAME_COUNT)return false;
    memcpy(out,base[ord],MPDU_LEN);
    memcpy(out+4,s->target_mac,6);memcpy(out+10,s->source_mac,6);
    memcpy(out+48,s->source_ip.s6_addr,16);memcpy(out+64,s->target_ip.s6_addr,16);
    uint16_t wifi=(uint16_t)((s->wifi_sequence_base+ord)&0x0fffU);
    write_le16(out+22,(uint16_t)(wifi<<4));
    write_le16(out+34,(uint16_t)(s->awdl_sequence_base+ord));
    memcpy(out+88,s->wire_nonce,WIRE_NONCE_LEN);
    out[86]=out[87]=0;
    uint16_t checksum=udp_checksum(&s->source_ip,&s->target_ip,out+80);
    out[86]=(uint8_t)(checksum>>8);out[87]=(uint8_t)checksum;
    return true;
}
static bool validate_frame(const uint8_t *packet,unsigned ord,const struct packet_set *s) {
    if(ord>=FRAME_COUNT||memcmp(packet,rtap_noack_clear,RTAP_LEN))return false;
    uint8_t expected[MPDU_LEN];if(!build_expected_mpdu(s,ord,expected))return false;
    return memcmp(packet+RTAP_LEN,expected,MPDU_LEN)==0;
}
static bool validate_set(struct packet_set *s) {
    const uint8_t *h=s->bytes;
    if(memcmp(h,magic,8)||h[8]!=2||h[9]!=4||be16(h+10)!=10||be16(h+12)!=40||be16(h+14)!=10||be16(h+16)!=96||be16(h+18)!=106)return false;
    s->wifi_sequence_base=be16(h+20);
    s->awdl_sequence_base=be16(h+22);
    if(s->wifi_sequence_base>0x0fffU)return false;
    if(memcmp(h+68,template_sha256,32))return false;
    for(unsigned i=100;i<104;i++)if(h[i])return false;
    memcpy(s->wire_nonce,h+104,WIRE_NONCE_LEN);
    uint8_t nonce_any=0;for(unsigned i=0;i<WIRE_NONCE_LEN;i++)nonce_any|=s->wire_nonce[i];
    if(!nonce_any)return false;
    memcpy(s->source_mac,h+24,6);memcpy(s->target_mac,h+30,6);
    memcpy(s->source_ip.s6_addr,h+36,16);memcpy(s->target_ip.s6_addr,h+52,16);
    if(!valid_mac(s->source_mac)||!valid_mac(s->target_mac)||!memcmp(s->source_mac,s->target_mac,6)||
       !IN6_IS_ADDR_LINKLOCAL(&s->source_ip)||!IN6_IS_ADDR_LINKLOCAL(&s->target_ip)||
       IN6_IS_ADDR_UNSPECIFIED(&s->source_ip)||IN6_IS_ADDR_UNSPECIFIED(&s->target_ip)||
       IN6_IS_ADDR_MULTICAST(&s->source_ip)||IN6_IS_ADDR_MULTICAST(&s->target_ip)||
       !memcmp(&s->source_ip,&s->target_ip,16))return false;
    for(unsigned i=0;i<4;i++) {
        const uint8_t *packet=h+HEADER_LEN+i*PACKET_LEN;
        if(!validate_frame(packet,i,s))return false;
        struct t089_observation status_shape;memset(&status_shape,0,sizeof(status_shape));
        status_shape.mpdu_offset=RTAP_LEN;status_shape.mpdu_length=MPDU_LEN;
        status_shape.has_tx_flags=true;status_shape.has_data_retries=true;
        int ordinal=-1;
        if(!is_status_candidate(packet,PACKET_LEN,T089_PACKET_OTHERHOST,&status_shape,s,&ordinal)||
           ordinal!=(int)i||exact_frame_ordinal(packet,PACKET_LEN,&status_shape,s)!=(int)i)return false;
    }
    return true;
}
static bool read_packet_set(const char *path,struct packet_set *s) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
    struct stat st;bool ok=fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size==(off_t)PACKET_SET_LEN&&
        (st.st_mode&0777)==0600&&st.st_uid==geteuid();
    size_t off=0;while(ok&&off<PACKET_SET_LEN){ssize_t n=read(fd,s->bytes+off,PACKET_SET_LEN-off);if(n<0&&errno==EINTR)continue;if(n<=0){ok=false;break;}off+=(size_t)n;}
    uint8_t extra;if(ok&&read(fd,&extra,1)!=0)ok=false;int saved=errno;(void)close(fd);errno=saved;
    return ok&&validate_set(s);
}
#ifdef __linux__
static uint64_t now_ns(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)!=0||t.tv_sec<0||t.tv_nsec<0)return 0;
    if((uint64_t)t.tv_sec>UINT64_MAX/UINT64_C(1000000000))return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static int read_control_line(uint64_t deadline,char *out,size_t cap) {
    size_t n=0;for(;;){uint64_t now=now_ns();if(!now||now>=deadline)return 0;
        int ms=(int)((deadline-now+999999U)/1000000U);struct pollfd p={.fd=STDIN_FILENO,.events=POLLIN};
        int r;do{r=poll(&p,1,ms);}while(r<0&&errno==EINTR);if(r==0)return 0;
        if(r<0||(p.revents&(POLLERR|POLLHUP|POLLNVAL))||!(p.revents&POLLIN))return -1;
        char c;ssize_t got;do{got=read(STDIN_FILENO,&c,1);}while(got<0&&errno==EINTR);
        if(got!=1||n+1>=cap)return -1;out[n++]=c;if(c=='\n'){out[n]='\0';return 1;}}
}
static int wait_go(const char *token,const struct packet_set *set,uint64_t *observed) {
    uint64_t start=now_ns();if(!start||start>UINT64_MAX-(uint64_t)GO_TIMEOUT_MS*1000000U)return -1;
    uint64_t deadline=start+(uint64_t)GO_TIMEOUT_MS*1000000U;
    char wire_nonce_hex[WIRE_NONCE_HEX_LEN+1U];format_bytes_hex(set->wire_nonce,WIRE_NONCE_LEN,wire_nonce_hex);
    if(printf("READY schema=test122-router-status-sender/v2 frames=4 interval_ms=10 mpdu_bytes=96 radiotap_bytes=10 packet_bytes=106 send_budget_ms=40 status_tail_ms=2000 tx_flags=NOSEQNO hardware_honoring=unknown noack_requested=false intel_arm_invoked=false boot_claim_used=false wire_nonce_hex=%s\n",wire_nonce_hex)<0||fflush(stdout))return -1;
    char expected[RUN_TOKEN_HEX_LEN+5U];snprintf(expected,sizeof(expected),"GO %s\n",token);
    for(;;){char line[RUN_TOKEN_HEX_LEN+8U];int r=read_control_line(deadline,line,sizeof(line));if(r!=1)return -1;
        if(!strcmp(line,"WAIT\n"))continue;if(!strcmp(line,"ABORT\n"))return 0;if(strcmp(line,expected))return -1;
        *observed=now_ns();return *observed!=0?1:-1;}
}
static bool read_live_source(const char *name,uint8_t mac[6],struct in6_addr *ip) {
    unsigned index=if_nametoindex(name);if(!index)return false;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return false;
    struct ifreq r;memset(&r,0,sizeof(r));strncpy(r.ifr_name,name,sizeof(r.ifr_name)-1);
    bool ok=ioctl(fd,SIOCGIFFLAGS,&r)==0&&(r.ifr_flags&IFF_UP);
    if(ok)ok=ioctl(fd,SIOCGIFHWADDR,&r)==0&&r.ifr_hwaddr.sa_family==ARPHRD_ETHER;
    if(ok)memcpy(mac,r.ifr_hwaddr.sa_data,6);close(fd);if(!ok||!valid_mac(mac))return false;
    FILE *f=fopen("/proc/net/if_inet6","r");if(!f)return false;
    char hex[33],ifname[IFNAME_MAX+1];unsigned idx,prefix,scope,flags;unsigned found=0;
    while(fscanf(f,"%32s %x %x %x %x %15s",hex,&idx,&prefix,&scope,&flags,ifname)==6){
        (void)prefix;(void)scope;(void)flags;if(idx!=index||strcmp(ifname,name)||strlen(hex)!=32)continue;
        char text[40];snprintf(text,sizeof(text),"%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c",
            hex[0],hex[1],hex[2],hex[3],hex[4],hex[5],hex[6],hex[7],hex[8],hex[9],hex[10],hex[11],
            hex[12],hex[13],hex[14],hex[15],hex[16],hex[17],hex[18],hex[19],hex[20],hex[21],hex[22],hex[23],
            hex[24],hex[25],hex[26],hex[27],hex[28],hex[29],hex[30],hex[31]);
        struct in6_addr candidate;if(inet_pton(AF_INET6,text,&candidate)==1&&IN6_IS_ADDR_LINKLOCAL(&candidate)){*ip=candidate;found++;}}
    bool good=!ferror(f)&&found==1;fclose(f);return good;
}
static bool monitor_index(const char *name,int *result) {
    unsigned idx=if_nametoindex(name);if(!idx||idx>INT_MAX)return false;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return false;
    struct ifreq r;memset(&r,0,sizeof(r));strncpy(r.ifr_name,name,sizeof(r.ifr_name)-1);
    bool ok=ioctl(fd,SIOCGIFHWADDR,&r)==0&&(unsigned short)r.ifr_hwaddr.sa_family==ARPHRD_IEEE80211_RADIOTAP;
    close(fd);if(ok)*result=(int)idx;return ok;
}
static int open_packet_socket(int index) {
    int fd=socket(AF_PACKET,SOCK_RAW|SOCK_CLOEXEC,htons(ETH_P_ALL));if(fd<0)return -1;
    struct sockaddr_ll a;memset(&a,0,sizeof(a));a.sll_family=AF_PACKET;a.sll_protocol=htons(ETH_P_ALL);a.sll_ifindex=index;
    if(bind(fd,(struct sockaddr*)&a,sizeof(a))){int e=errno;close(fd);errno=e;return -1;}return fd;
}
static bool sleep_abs(uint64_t deadline) {
    struct timespec t={(time_t)(deadline/UINT64_C(1000000000)),(long)(deadline%UINT64_C(1000000000))};
    int e;do{e=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL);}while(e==EINTR);return e==0;
}
static void retain_nonmatch_sample(struct rx_observation *out,uint64_t observed_ns,
                                   const char *parse_status,const struct msghdr *message,
                                   const struct sockaddr_ll *address,ssize_t received,
                                   const uint8_t *buffer,size_t copied) {
    if(out->nonmatch_samples_recorded>=NONMATCH_SAMPLE_LIMIT) {
        out->nonmatch_samples_overflow++;
        return;
    }
    struct nonmatch_sample *sample=&out->nonmatch_samples[out->nonmatch_samples_recorded++];
    memset(sample,0,sizeof(*sample));
    sample->observed_ns=observed_ns;
    sample->parse_status=parse_status;
    sample->packet_type_present=message->msg_namelen>=
        offsetof(struct sockaddr_ll,sll_pkttype)+sizeof(address->sll_pkttype);
    sample->ifindex_present=message->msg_namelen>=
        offsetof(struct sockaddr_ll,sll_ifindex)+sizeof(address->sll_ifindex);
    sample->packet_type=(unsigned)address->sll_pkttype;
    sample->ifindex=address->sll_ifindex>0?(unsigned)address->sll_ifindex:0U;
    sample->msg_flags=(unsigned)message->msg_flags;
    sample->received_len=(size_t)received;
    sample->raw_len=copied<NONMATCH_RAW_BYTES?copied:NONMATCH_RAW_BYTES;
    /* copied_len is the bounded retained prefix length, not the full iovec
     * length. The latter is represented by received_len. */
    sample->copied_len=sample->raw_len;
    sample->raw_prefix_truncated=(size_t)received>sample->raw_len;
    memcpy(sample->raw,buffer,sample->raw_len);
}
static void observe_monitor_until(int fd, int expected_index, uint64_t deadline,
                                  const struct packet_set *set,
                                  uint64_t capture_started,
                                  struct rx_observation *out) {
    memset(out,0,sizeof(*out));
    out->started_ns=capture_started;
    while (out->started_ns && out->read_attempts < RAW_CAPTURE_READ_LIMIT) {
        uint64_t now=now_ns();
        if (!now || now >= deadline) break;
        uint64_t left=deadline-now;
        int timeout=(int)((left+999999U)/1000000U);
        struct pollfd p={.fd=fd,.events=POLLIN};
        int polled;
        do { polled=poll(&p,1,timeout); } while (polled<0 && errno==EINTR);
        if (polled<0) { out->receive_error=errno?errno:EIO; break; }
        if (polled==0) continue;
        if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) {
            out->receive_error=EIO;
            break;
        }
        if (!(p.revents & POLLIN)) continue;
        uint8_t buffer[RAW_CAPTURE_BYTES];
        struct sockaddr_ll address;memset(&address,0,sizeof(address));
        struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};
        struct msghdr message;memset(&message,0,sizeof(message));
        message.msg_name=&address;message.msg_namelen=sizeof(address);
        message.msg_iov=&iov;message.msg_iovlen=1;
        ssize_t received=recvmsg(fd,&message,MSG_DONTWAIT|MSG_TRUNC);
        int receive_errno=received<0?errno:0;
        uint64_t observed_ns=now_ns();
        out->read_attempts++;
        if (received<0) {
            if (receive_errno==EAGAIN || receive_errno==EWOULDBLOCK || receive_errno==EINTR) continue;
            out->receive_error=receive_errno?receive_errno:EIO;
            break;
        }
        if(!observed_ns) { out->receive_error=EIO; break; }
        out->packets_received++;
        /* Count complete exact MPDUs independently of the bounded raw bank.
         * Even a matching PACKET_OUTGOING is a local pre-driver tap only. */
        size_t copied=(size_t)received<sizeof(buffer)?(size_t)received:sizeof(buffer);
        int exact=-1;
        struct t089_observation parsed_observation;
        enum t089_parse_result parse_result=T089_PARSE_INVALID;
        if ((size_t)received<=sizeof(buffer) && !(message.msg_flags&MSG_TRUNC)) {
            const uint8_t *comparison_mpdu=set->bytes+HEADER_LEN+RTAP_LEN;
            parse_result=t089_parse_observation(buffer,copied,
                (unsigned)address.sll_pkttype,comparison_mpdu,&parsed_observation);
        } else {
            ++out->truncated_packets;
        }
        if (parse_result==T089_PARSE_INVALID) ++out->radiotap_invalid;
        else if (parse_result==T089_PARSE_UNSUPPORTED) ++out->radiotap_unsupported;
        bool type_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_pkttype)+sizeof(address.sll_pkttype);
        bool index_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_ifindex)+sizeof(address.sll_ifindex);
        if(parse_result==T089_PARSE_VALID)
            exact=exact_frame_ordinal(buffer,copied,&parsed_observation,set);
        int status_ordinal=-1;
        bool status_candidate=parse_result==T089_PARSE_VALID && type_present &&
            is_status_candidate(buffer,copied,(unsigned)address.sll_pkttype,
                                &parsed_observation,set,&status_ordinal);
        if (exact<0 && !status_candidate && parse_result==T089_PARSE_VALID)
            ++out->unmatched_valid_packets;
        if(parse_result!=T089_PARSE_VALID || (exact<0&&!status_candidate)) {
            const char *kind=parse_result==T089_PARSE_UNSUPPORTED?"unsupported":
                parse_result==T089_PARSE_VALID?"valid_unmatched":"invalid";
            retain_nonmatch_sample(out,observed_ns,kind,&message,&address,received,buffer,copied);
        }
        if(status_candidate) ++out->status_candidate_match[(unsigned)status_ordinal];
        if(exact>=0) {
            ++out->exact_match[(unsigned)exact];
            if(!type_present || !index_present || address.sll_ifindex!=expected_index)
                ++out->exact_identity_unavailable;
            else if(address.sll_pkttype==PACKET_OUTGOING) {
                ++out->outgoing_exact[(unsigned)exact];
            } else {
                ++out->non_outgoing_exact[(unsigned)exact];
                if (status_candidate)
                    ++out->completion_candidate[(unsigned)exact];
                else
                    ++out->other_exact[(unsigned)exact];
            }
        }
        if(status_candidate) {
            if(!index_present || address.sll_ifindex!=expected_index) {
                ++out->status_identity_unavailable;
            } else {
                if(out->status_samples_recorded>=STATUS_SAMPLE_LIMIT) {
                    ++out->status_samples_overflow;
                } else {
                    struct status_sample *sample=&out->status_samples[out->status_samples_recorded++];
                    sample->ordinal=(unsigned)status_ordinal;
                    sample->observed_ns=observed_ns;
                    sample->packet_type=(unsigned)address.sll_pkttype;
                    sample->ifindex=(unsigned)address.sll_ifindex;
                    sample->msg_flags=(unsigned)message.msg_flags;
                    sample->received_len=(size_t)received;
                    sample->copied_len=copied<STATUS_RAW_BYTES?copied:STATUS_RAW_BYTES;
                    sample->raw_truncated=sample->received_len>sample->copied_len;
                    sample->exact_match=exact_frame_ordinal(buffer,copied,
                        &parsed_observation,set)==status_ordinal;
                    sample->has_tx_flags=parsed_observation.has_tx_flags;
                    sample->tx_flags=parsed_observation.tx_flags;
                    sample->has_data_retries=parsed_observation.has_data_retries;
                    sample->data_retries=parsed_observation.data_retries;
                    const uint8_t *mpdu=buffer+parsed_observation.mpdu_offset;
                    sample->ieee80211_sequence=(unsigned)(le16(mpdu+22U)>>4)&0x0fffU;
                    sample->ieee80211_sequence_control=le16(mpdu+22U);
                    sample->awdl_sequence=le16(mpdu+34U);
                    memcpy(sample->raw,buffer,sample->copied_len);
                }
            }
        }
        if(exact<0) continue;
        if(out->exact_samples_recorded>=EXACT_SAMPLE_LIMIT) {
            out->exact_samples_overflow++;
            continue;
        }
        struct rx_sample *sample=&out->samples[out->exact_samples_recorded++];
        sample->observed_ns=observed_ns;
        sample->packet_type_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_pkttype)+sizeof(address.sll_pkttype);
        sample->ifindex_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_ifindex)+sizeof(address.sll_ifindex);
        sample->packet_type=(unsigned)address.sll_pkttype;
        sample->ifindex=address.sll_ifindex>0?(unsigned)address.sll_ifindex:0U;
        sample->msg_flags=(unsigned)message.msg_flags;
        sample->received_len=(size_t)received;
        sample->copied_len=copied;
        sample->exact_ordinal=exact;
        sample->parse_supported=parse_result==T089_PARSE_VALID;
        sample->exact_match=true;
        sample->completion_candidate=status_candidate;
        sample->outgoing_echo=type_present && address.sll_pkttype==PACKET_OUTGOING;
        sample->has_tx_flags=parsed_observation.has_tx_flags;
        sample->tx_flags=parsed_observation.tx_flags;
        sample->has_data_retries=parsed_observation.has_data_retries;
        sample->data_retries=parsed_observation.data_retries;
        const uint8_t *mpdu=buffer+parsed_observation.mpdu_offset;
        sample->ieee80211_sequence=(unsigned)(le16(mpdu+22U)>>4)&0x0fffU;
        sample->ieee80211_sequence_control=le16(mpdu+22U);
        sample->awdl_sequence=le16(mpdu+34U);
    }
    if (out->read_attempts>=RAW_CAPTURE_READ_LIMIT) out->capture_limit_reached=true;
    out->ended_ns=now_ns();
    out->capture_finished=out->started_ns && out->ended_ns>=deadline &&
                          out->receive_error==0 && !out->capture_limit_reached;
    struct tpacket_stats stats;socklen_t stats_len=sizeof(stats);
    if (getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&stats_len)==0 &&
        stats_len>=sizeof(stats)) {
        out->kernel_stats_available=true;
        out->kernel_packets=stats.tp_packets;
        out->kernel_dropped=stats.tp_drops;
    }
}
static void drain_observer_queue_after_go(int fd, struct stale_queue_observation *out) {
    memset(out,0,sizeof(*out));
    for(unsigned i=0;i<STALE_QUEUE_READ_LIMIT;i++) {
        uint8_t buffer[RAW_CAPTURE_BYTES];
        struct sockaddr_ll address;memset(&address,0,sizeof(address));
        struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};
        struct msghdr message;memset(&message,0,sizeof(message));
        message.msg_name=&address;message.msg_namelen=sizeof(address);
        message.msg_iov=&iov;message.msg_iovlen=1;
        ssize_t received=recvmsg(fd,&message,MSG_DONTWAIT|MSG_TRUNC);
        int receive_errno=received<0?errno:0;
        (void)now_ns();
        out->read_attempts++;
        if(received<0) {
            if(receive_errno==EAGAIN || receive_errno==EWOULDBLOCK) {
                out->drain_complete=true;
                break;
            }
            if(receive_errno==EINTR) continue;
            out->receive_error=receive_errno?receive_errno:EIO;
            break;
        }
        out->packets_drained++;
    }
    /* PACKET_STATISTICS resets on read. Take it after the stale drain so the
     * later bounded capture has a separate kernel-drop accounting epoch. */
    struct tpacket_stats stats;socklen_t stats_len=sizeof(stats);
    if(getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,&stats,&stats_len)==0 &&
       stats_len>=sizeof(stats)) {
        out->kernel_stats_available=true;
        out->kernel_packets=stats.tp_packets;
        out->kernel_dropped=stats.tp_drops;
    }
}
static void emit_aborted_before_go(const struct options *o,
                                   const struct packet_set *set);
static int send_frames(const struct options *o,const struct packet_set *s,int tx_fd,int observer_fd,int observer_index,uint64_t go,const struct stale_queue_observation *stale) {
    const uint64_t capture_window_ns=SEND_BUDGET_NS+STATUS_TAIL_NS;
    uint64_t start=now_ns();if(!start||start>UINT64_MAX-capture_window_ns)return EXIT_SEND;
    uint64_t deadline=start+SEND_BUDGET_NS;
    uint64_t observer_deadline=deadline+STATUS_TAIL_NS;
    struct send_sample row[FRAME_COUNT];memset(row,0,sizeof(row));
    uint64_t go_to_start_ns=start>=go?start-go:UINT64_MAX;
    uint64_t first_send_ns=0;
    uint64_t previous_send_before_ns=0;
    char wire_nonce_hex[WIRE_NONCE_HEX_LEN+1U];format_bytes_hex(s->wire_nonce,WIRE_NONCE_LEN,wire_nonce_hex);
    unsigned attempted=0,completed=0;int last_errno=0;const char *reason="complete";
    /* READY was emitted before GO. This marks actual post-GO send-loop start. */
    printf("{\"event\":\"SENDER_STARTED\",\"schema\":\"test122-router-status-sender/v2\",\"clock_domain\":\"CLOCK_MONOTONIC\",\"run_token\":\"%s\",\"wire_nonce_hex\":\"%s\",\"go_received_ns\":%" PRIu64 ",\"started_ns\":%" PRIu64 ",\"send_deadline_ns\":%" PRIu64 ",\"observer_deadline_ns\":%" PRIu64 ",\"go_to_start_ns\":%" PRIu64 ",\"go_to_start_max_ns\":%" PRIu64 ",\"send_budget_ns\":%" PRIu64 ",\"status_tail_ns\":%" PRIu64 ",\"frames_requested\":4,\"interval_ms\":10,\"tx_flags_requested\":\"NOSEQNO\",\"noack_requested\":false,\"intel_arm_invoked\":false,\"boot_claim_used\":false}\n",
        o->nonce,wire_nonce_hex,go,start,deadline,observer_deadline,go_to_start_ns,
        (uint64_t)GO_TO_START_MAX_NS,(uint64_t)SEND_BUDGET_NS,
        (uint64_t)STATUS_TAIL_NS);fflush(stdout);
    uint64_t loop_start_ns=now_ns();
    bool clean_epoch = stale->drain_complete && stale->receive_error == 0 &&
        stale->kernel_stats_available && stale->kernel_dropped == 0 &&
        stale->kernel_packets == stale->packets_drained;
    if(!clean_epoch) {
        last_errno=EIO;reason="observer_drain_incomplete";
    } else if(go_to_start_ns>GO_TO_START_MAX_NS || !loop_start_ns ||
              loop_start_ns<go || loop_start_ns-go>GO_TO_START_MAX_NS) {
        last_errno=ETIMEDOUT;reason="go_to_start_budget_expired";
    } else if(loop_start_ns>deadline) {
        last_errno=ETIMEDOUT;reason="send_budget_expired";
    }
    for(unsigned i=0;i<FRAME_COUNT && last_errno==0;i++){
        uint64_t due=i?previous_send_before_ns+UINT64_C(10000000):loop_start_ns;
        if(i&& !sleep_abs(due)){last_errno=errno?errno:EIO;reason="schedule_wait_failed";break;}
        uint64_t before=now_ns();if(!before){last_errno=errno?errno:EIO;reason="clock_before_failed";break;}
        if(i && (before<previous_send_before_ns ||
                 before-previous_send_before_ns<UINT64_C(10000000))) {
            last_errno=EIO;reason="send_spacing_violation";break;
        }
        if(i==0 && (before<go || before-go>GO_TO_START_MAX_NS)) {
            last_errno=ETIMEDOUT;reason="go_to_start_budget_expired";break;
        }
        if(before>=deadline){last_errno=ETIMEDOUT;reason="send_budget_expired";break;}
        const uint8_t *packet=s->bytes+HEADER_LEN+i*PACKET_LEN;
        const uint8_t *mpdu=packet+RTAP_LEN;
        uint16_t sequence_control=(uint16_t)(mpdu[22]|((uint16_t)mpdu[23]<<8));
        row[i].ordinal=i;row[i].ieee80211_sequence=(sequence_control>>4)&0x0fffU;
        row[i].ieee80211_sequence_control=sequence_control;
        row[i].awdl_sequence=(unsigned)mpdu[34]|((unsigned)mpdu[35]<<8);
        row[i].before_ns=before;previous_send_before_ns=before;
        if(first_send_ns==0)first_send_ns=before;attempted++;
        ssize_t n=send(tx_fd,packet,PACKET_LEN,MSG_DONTWAIT);
        int e=n<0?errno:0;uint64_t after=now_ns();row[i].return_bytes=(long long)n;row[i].error=e;row[i].after_ns=after;
        if(n!=(ssize_t)PACKET_LEN){last_errno=e?e:EIO;reason=n<0?"send_errno":"short_write";break;}
        completed++;if(!after){last_errno=errno?errno:EIO;reason="clock_after_failed";break;}
        if(after>deadline){last_errno=ETIMEDOUT;reason="send_completed_after_budget";break;}
    }
    struct rx_observation rx;
    observe_monitor_until(observer_fd,observer_index,observer_deadline,s,start,&rx);
    uint64_t finished=rx.ended_ns;
    bool send_complete=completed==FRAME_COUNT&&attempted==FRAME_COUNT&&last_errno==0;
    uint64_t elapsed_ms=0;
    if(completed>0&&row[completed-1].after_ns>=start)
        elapsed_ms=(row[completed-1].after_ns-start)/UINT64_C(1000000);
    bool deadline_hit=!strcmp(reason,"send_budget_expired")||!strcmp(reason,"send_completed_after_budget");
    unsigned stored=rx.exact_samples_recorded;
    bool identity_complete=rx.exact_identity_unavailable==0;
    bool exact_classification_complete=identity_complete &&
        rx.radiotap_invalid==0 && rx.radiotap_unsupported==0 &&
        rx.truncated_packets==0 && rx.exact_samples_overflow==0 &&
        rx.status_samples_overflow==0 && rx.status_identity_unavailable==0 &&
        rx.nonmatch_samples_overflow==0;
    int capture_loss_state=capture_loss_free_state(
        rx.capture_finished,rx.receive_error!=0,rx.capture_limit_reached,
        rx.truncated_packets!=0,rx.kernel_stats_available,rx.kernel_packets,
        rx.kernel_dropped,rx.packets_received);
    bool classification_complete=exact_classification_complete;
    printf("{\"event\":\"SENDER_RESULT\",\"schema\":\"test122-router-status-sender/v2\",\"clock_domain\":\"CLOCK_MONOTONIC\",\"status\":\"%s\",\"run_token\":\"%s\",\"wire_nonce_hex\":\"%s\",\"run_token_in_frame\":false,\"go_received_ns\":%" PRIu64 ",\"frames_requested\":4,\"frames_attempted\":%u,\"frames_completed\":%u,\"send_complete\":%s,\"packet_bytes\":106,\"radiotap_bytes\":10,\"mpdu_bytes\":96,\"elapsed_ms\":%" PRIu64 ",\"deadline_hit\":%s,\"error_count\":%u,\"last_errno\":%d,\"stop_reason\":\"%s\",\"tx_flags_requested\":\"NOSEQNO\",\"noack_requested\":false,\"ack_policy\":\"normal_unicast_requested\",\"hardware_honoring\":\"unknown\",\"raw_txs\":\"unknown\",\"mac_ack\":\"unknown\",\"interval_ms\":10,\"send_budget_ns\":%" PRIu64 ",\"status_tail_ns\":%" PRIu64 ",\"capture_window_ns\":%" PRIu64 ",\"started_ns\":%" PRIu64 ",\"send_deadline_ns\":%" PRIu64 ",\"observer_deadline_ns\":%" PRIu64 ",\"finished_ns\":%" PRIu64 ",\"go_to_start_ns\":%" PRIu64 ",\"go_to_start_max_ns\":%" PRIu64 ",\"first_send_ns\":",
        send_complete?"send_complete":"send_incomplete",o->nonce,wire_nonce_hex,go,attempted,completed,
        send_complete?"true":"false",elapsed_ms,deadline_hit?"true":"false",
        last_errno?1U:0U,last_errno,reason,(uint64_t)SEND_BUDGET_NS,
        (uint64_t)STATUS_TAIL_NS,capture_window_ns,start,deadline,
        observer_deadline,finished,go_to_start_ns,(uint64_t)GO_TO_START_MAX_NS);
    if(first_send_ns)printf("%" PRIu64,first_send_ns); else printf("null");
    printf(",\"pre_capture_queue_drain\":{\"read_attempts\":%u,\"packets_drained\":%u,\"receive_error\":%d,\"drain_complete\":%s,\"kernel_stats_available\":%s,\"kernel_packets\":",
        stale->read_attempts,stale->packets_drained,stale->receive_error,
        stale->drain_complete?"true":"false",
        stale->kernel_stats_available?"true":"false");
    if(stale->kernel_stats_available)printf("%u,\"kernel_dropped_packets\":%u},",stale->kernel_packets,stale->kernel_dropped);
    else printf("null,\"kernel_dropped_packets\":null},");
    printf("\"send_timing\":[");
    for(unsigned i=0;i<attempted;i++)printf("%s{\"ordinal\":%u,\"ieee80211_sequence\":%u,\"ieee80211_sequence_control\":%u,\"awdl_sequence\":%u,\"before_ns\":%" PRIu64 ",\"after_ns\":%" PRIu64 ",\"return_bytes\":%lld,\"errno\":%d}",i?",":"",row[i].ordinal,row[i].ieee80211_sequence,row[i].ieee80211_sequence_control,row[i].awdl_sequence,row[i].before_ns,row[i].after_ns,row[i].return_bytes,row[i].error);
    printf("],\"monitor_observation\":{\"schema\":\"test122-router-status-monitor/v2\",\"clock_domain\":\"CLOCK_MONOTONIC\",\"observation_time_semantics\":\"userspace_recvmsg_return\",\"started_ns\":%" PRIu64 ",\"ended_ns\":%" PRIu64 ",\"actual_horizon_ns\":%" PRIu64 ",\"capture_window_ns\":%" PRIu64 ",\"status_tail_began_ns\":%" PRIu64 ",\"capture_finished\":%s,\"capture_limit_reached\":%s,\"read_attempts\":%u,\"packets_received\":%u,\"exact_samples_recorded\":%u,\"exact_samples_overflow\":%u,\"receive_error\":%d,\"kernel_stats_available\":%s,\"kernel_packets\":",
        rx.started_ns,rx.ended_ns,finished>=start?finished-start:0,
        capture_window_ns,deadline,rx.capture_finished?"true":"false",
        rx.capture_limit_reached?"true":"false",rx.read_attempts,
        rx.packets_received,stored,rx.exact_samples_overflow,rx.receive_error,
        rx.kernel_stats_available?"true":"false");
    if(rx.kernel_stats_available)printf("%u,\"kernel_dropped_packets\":%u,",rx.kernel_packets,rx.kernel_dropped);
    else printf("null,\"kernel_dropped_packets\":null,");
    printf("\"capture_loss_free\":");
    if(capture_loss_state<0) printf("null");
    else printf(capture_loss_state?"true":"false");
    printf(",\"classification_complete\":%s,\"identity_complete\":%s,\"radiotap_invalid\":%u,\"radiotap_unsupported\":%u,\"unmatched_valid_packets\":%u,\"truncated_packets\":%u,\"exact_identity_unavailable\":%u,\"socket_topology\":\"distinct_tx_and_observer\",\"observer_bound_ifindex\":%d,\"outgoing_tap_is_rf_proof\":false,\"exact_match_by_ordinal\":[",classification_complete?"true":"false",identity_complete?"true":"false",rx.radiotap_invalid,rx.radiotap_unsupported,rx.unmatched_valid_packets,rx.truncated_packets,rx.exact_identity_unavailable,observer_index);
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.exact_match[i]);
    printf("],\"outgoing_exact_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.outgoing_exact[i]);
    printf("],\"non_outgoing_exact_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.non_outgoing_exact[i]);
    printf("],\"tx_status_candidate_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.completion_candidate[i]);
    printf("],\"other_exact_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.other_exact[i]);
    printf("],\"samples\":[");
    for(unsigned i=0;i<stored;i++) {
        const struct rx_sample *sample=&rx.samples[i];
        printf("%s{\"observed_ns\":%" PRIu64 ",\"exact_ordinal\":%d,\"packet_type_present\":%s,\"packet_type\":",
               i?",":"",sample->observed_ns,sample->exact_ordinal,
               sample->packet_type_present?"true":"false");
        if(sample->packet_type_present)printf("%u,",sample->packet_type);else printf("null,");
        printf("\"ifindex_present\":%s,\"ifindex\":",sample->ifindex_present?"true":"false");
        if(sample->ifindex_present)printf("%u,",sample->ifindex);else printf("null,");
        printf("\"msg_flags\":%u,\"received_len\":%zu,\"copied_len\":%zu,\"parse_supported\":%s,\"exact_match\":%s,\"outgoing_echo\":%s,\"host_driver_completion_candidate\":%s,\"has_tx_flags\":%s,\"tx_flags\":",
            sample->msg_flags,sample->received_len,sample->copied_len,
            sample->parse_supported?"true":"false",sample->exact_match?"true":"false",
            sample->outgoing_echo?"true":"false",sample->completion_candidate?"true":"false",
            sample->has_tx_flags?"true":"false");
        if(sample->has_tx_flags)printf("%u,",sample->tx_flags);else printf("null,");
        printf("\"has_data_retries\":%s,\"data_retries\":",sample->has_data_retries?"true":"false");
        if(sample->has_data_retries)printf("%u,",sample->data_retries);else printf("null,");
        printf("\"ieee80211_sequence\":%u,\"ieee80211_sequence_control\":%u,\"awdl_sequence\":%u}",
               sample->ieee80211_sequence,sample->ieee80211_sequence_control,
               sample->awdl_sequence);
    }
    printf("],\"nonmatch_samples_recorded\":%u,\"nonmatch_samples_overflow\":%u,\"nonmatch_samples\":[",
        rx.nonmatch_samples_recorded,rx.nonmatch_samples_overflow);
    for(unsigned i=0;i<rx.nonmatch_samples_recorded;i++) {
        const struct nonmatch_sample *sample=&rx.nonmatch_samples[i];
        printf("%s{\"observed_ns\":%" PRIu64 ",\"parse_status\":\"%s\",\"packet_type_present\":%s,\"packet_type\":",
               i?",":"",sample->observed_ns,sample->parse_status,
               sample->packet_type_present?"true":"false");
        if(sample->packet_type_present)printf("%u,",sample->packet_type);else printf("null,");
        printf("\"ifindex_present\":%s,\"ifindex\":",sample->ifindex_present?"true":"false");
        if(sample->ifindex_present)printf("%u,",sample->ifindex);else printf("null,");
        printf("\"msg_flags\":%u,\"received_len\":%zu,\"copied_len\":%zu,\"raw_prefix_truncated\":%s,\"raw_prefix_hex\":\"",
               sample->msg_flags,sample->received_len,sample->copied_len,
               sample->raw_prefix_truncated?"true":"false");
        print_bytes_hex(sample->raw,sample->raw_len);
        printf("\"}");
    }
    printf("],\"status_candidate_matches_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.status_candidate_match[i]);
    printf("],\"status_candidate_samples_recorded\":%u,\"status_candidate_samples_overflow\":%u,\"status_candidate_identity_unavailable\":%u,\"status_candidate_samples\":[",
        rx.status_samples_recorded,rx.status_samples_overflow,
        rx.status_identity_unavailable);
    for(unsigned i=0;i<rx.status_samples_recorded;i++) {
        const struct status_sample *sample=&rx.status_samples[i];
        printf("%s{\"observed_ns\":%" PRIu64 ",\"ordinal\":",i?",":"",sample->observed_ns);
        if(sample->ordinal<FRAME_COUNT)printf("%u,",sample->ordinal);else printf("null,");
        printf("\"packet_type\":%u,\"ifindex\":%u,\"msg_flags\":%u,\"received_len\":%zu,\"bytes_retained\":%zu,\"raw_prefix_truncated\":%s,\"exact_match\":%s,\"has_tx_flags\":%s,\"tx_flags\":%u,\"has_data_retries\":%s,\"data_retries\":%u,\"ieee80211_sequence\":%u,\"ieee80211_sequence_control\":%u,\"awdl_sequence\":%u,\"raw_prefix_hex\":\"",
            sample->packet_type,sample->ifindex,sample->msg_flags,
            sample->received_len,sample->copied_len,
            sample->raw_truncated?"true":"false",sample->exact_match?"true":"false",
            sample->has_tx_flags?"true":"false",sample->tx_flags,
            sample->has_data_retries?"true":"false",sample->data_retries,
            sample->ieee80211_sequence,sample->ieee80211_sequence_control,
            sample->awdl_sequence);
        print_bytes_hex(sample->raw,sample->copied_len);
        printf("\"}");
    }
    printf("]},\"radio_transmission_proven\":false,\"rf_transmission_proven\":false,\"firmware_tx_status_proven\":false,\"peer_receipt_proven\":false,\"airdrop_proven\":false,\"intel_arm_invoked\":false,\"boot_claim_used\":false}\n");
    if(fflush(stdout)) return EXIT_SEND;
    return send_complete && rx.capture_finished ? 0 : EXIT_SEND;
}
static void emit_aborted_before_go(const struct options *o,
                                   const struct packet_set *set) {
    char wire_nonce_hex[WIRE_NONCE_HEX_LEN+1U];
    format_bytes_hex(set->wire_nonce,WIRE_NONCE_LEN,wire_nonce_hex);
    printf("{\"event\":\"SENDER_RESULT\",\"schema\":\"test122-router-status-sender/v2\",\"status\":\"aborted\",\"run_token\":\"%s\",\"wire_nonce_hex\":\"%s\",\"run_token_in_frame\":false,\"frames_requested\":4,\"frames_attempted\":0,\"frames_completed\":0,\"send_complete\":false,\"send_budget_ms\":40,\"status_tail_ms\":2000,\"tx_flags_requested\":\"NOSEQNO\",\"noack_requested\":false,\"radio_transmission_proven\":false,\"rf_transmission_proven\":false,\"firmware_tx_status_proven\":false,\"mac_ack\":\"unknown\",\"peer_receipt_proven\":false,\"airdrop_proven\":false,\"intel_arm_invoked\":false,\"boot_claim_used\":false}\n",o->nonce,wire_nonce_hex);
    fflush(stdout);
}
#endif

int main(int argc,char **argv) {
    struct options o;if(argc==2&&!strcmp(argv[1],"--help")){usage(stdout,argv[0]);return 0;}
    if(!parse_options(argc,argv,&o)){usage(stderr,argv[0]);return EXIT_ARGUMENT;}
    /* Keep the tri-state loss contract exercised even in host verify builds. */
    if(capture_loss_free_state(true,false,false,false,true,0,0,0)!=1 ||
       capture_loss_free_state(true,false,false,true,false,0,0,0)!=0 ||
       capture_loss_free_state(true,false,false,false,false,0,0,0)!=-1) {
        fprintf(stderr,"error=loss_accounting_contract_invalid\n");
        return EXIT_ARGUMENT;
    }
    struct packet_set set;memset(&set,0,sizeof(set));
    if(!read_packet_set(o.file,&set)){fprintf(stderr,"error=packet_set_invalid_or_unsafe\n");return EXIT_ARGUMENT;}
    if(o.verify_only){
        char wire_nonce_hex[WIRE_NONCE_HEX_LEN+1U];
        format_bytes_hex(set.wire_nonce,WIRE_NONCE_LEN,wire_nonce_hex);
        printf("{\"event\":\"PACKET_SET_VALID\",\"schema\":\"test122-correlated-packet-set/v2\",\"frames\":4,\"interval_ms\":10,\"budget_ms\":40,\"noack_requested\":false,\"transmission_capability\":false,\"rf_transmission_proven\":false,\"wire_nonce_hex\":\"%s\"}\n",wire_nonce_hex);
        return fflush(stdout)?EXIT_ARGUMENT:0;
    }
#ifndef __linux__
    fprintf(stderr,"error=send_requires_linux_openwrt\n");return EXIT_INTERFACE;
#else
    uint8_t mac[6];struct in6_addr ip;if(!read_live_source(o.source,mac,&ip)||memcmp(mac,set.source_mac,6)||memcmp(ip.s6_addr,set.source_ip.s6_addr,16)){fprintf(stderr,"error=source_interface_identity_mismatch\n");return EXIT_INTERFACE;}
    int index=-1;if(!monitor_index(o.monitor,&index)){fprintf(stderr,"error=monitor_radiotap_interface_required errno=%d\n",errno);return EXIT_INTERFACE;}
    int tx_fd=open_packet_socket(index);if(tx_fd<0){fprintf(stderr,"error=packet_socket_open_failed errno=%d\n",errno);return EXIT_INTERFACE;}
    int observer_fd=open_packet_socket(index);
    if(observer_fd<0){int e=errno;close(tx_fd);fprintf(stderr,"error=observer_socket_open_failed errno=%d\n",e);return EXIT_INTERFACE;}
    int ignore_outgoing=0;
    if(setsockopt(observer_fd,SOL_PACKET,PACKET_IGNORE_OUTGOING,&ignore_outgoing,sizeof(ignore_outgoing))) {
        int e=errno;close(observer_fd);close(tx_fd);fprintf(stderr,"error=observer_outgoing_tap_enable_failed errno=%d\n",e);return EXIT_INTERFACE;
    }
    uint64_t go=0;int gate=wait_go(o.nonce,&set,&go);
    if(gate==0){emit_aborted_before_go(&o,&set);close(observer_fd);close(tx_fd);return 0;}
    if(gate<0){close(observer_fd);close(tx_fd);fprintf(stderr,"error=go_gate_failed\n");return EXIT_GATE;}
    struct stale_queue_observation stale;
    drain_observer_queue_after_go(observer_fd,&stale);
    int result=send_frames(&o,&set,tx_fd,observer_fd,index,go,&stale);close(observer_fd);close(tx_fd);return result;
#endif
}
