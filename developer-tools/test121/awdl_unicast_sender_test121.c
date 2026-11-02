/* SPDX-License-Identifier: GPL-2.0-only */
/* Test121 dual-socket runtime tool; it is not production driver code. */
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
#define GO_TIMEOUT_MS 30000U
#define IFNAME_MAX 15U
#define NONCE_HEX_LEN 32U
#define RTAP_LEN 10U
#define MPDU_LEN 96U
#define PACKET_LEN (RTAP_LEN + MPDU_LEN)
#define HEADER_LEN 104U
#define PACKET_SET_LEN (HEADER_LEN + FRAME_COUNT * PACKET_LEN)
#define RAW_CAPTURE_LIMIT 64U
#define RAW_CAPTURE_BYTES 512U
#define RAW_CAPTURE_READ_LIMIT 64U
#define STALE_QUEUE_READ_LIMIT 256U
#define GO_TO_START_MAX_NS UINT64_C(5000000)
#define EXIT_ARGUMENT 2
#define EXIT_GATE 3
#define EXIT_INTERFACE 4
#define EXIT_SEND 5

static const uint8_t magic[8] = {'T','1','0','4','P','K','T','1'};
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
};
struct send_sample {
    unsigned ordinal;
    unsigned ieee80211_sequence;
    unsigned awdl_sequence;
    uint64_t before_ns, after_ns;
    long long return_bytes;
    int error;
};
struct rx_sample {
    bool packet_type_present;
    bool ifindex_present;
    unsigned packet_type;
    unsigned ifindex;
    unsigned msg_flags;
    size_t received_len;
    size_t copied_len;
    int exact_ordinal;
    uint8_t raw[RAW_CAPTURE_BYTES];
};
struct rx_observation {
    uint64_t started_ns;
    uint64_t ended_ns;
    unsigned packets_received;
    unsigned samples_overflow;
    unsigned read_attempts;
    bool capture_finished;
    bool capture_limit_reached;
    bool kernel_stats_available;
    unsigned kernel_packets;
    unsigned kernel_dropped;
    int receive_error;
    unsigned outgoing_exact[FRAME_COUNT];
    unsigned non_outgoing_exact[FRAME_COUNT];
    unsigned exact_identity_unavailable;
    struct rx_sample samples[RAW_CAPTURE_LIMIT];
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

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
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
    if (!s || strlen(s)!=NONCE_HEX_LEN) return false;
    for (size_t i=0;i<NONCE_HEX_LEN;i++) if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false;
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
static bool validate_frame(const uint8_t *packet,unsigned ord,const struct packet_set *s) {
    if(ord>=FRAME_COUNT||memcmp(packet,rtap_noack_clear,RTAP_LEN))return false;
    uint8_t expected[MPDU_LEN];memcpy(expected,base[ord],MPDU_LEN);
    memcpy(expected+4,s->target_mac,6);memcpy(expected+10,s->source_mac,6);
    memcpy(expected+48,s->source_ip.s6_addr,16);memcpy(expected+64,s->target_ip.s6_addr,16);
    expected[86]=expected[87]=0;uint16_t c=udp_checksum(&s->source_ip,&s->target_ip,expected+80);
    expected[86]=(uint8_t)(c>>8);expected[87]=(uint8_t)c;
    return memcmp(packet+RTAP_LEN,expected,MPDU_LEN)==0;
}
static bool validate_set(struct packet_set *s) {
    const uint8_t *h=s->bytes;
    if(memcmp(h,magic,8)||h[8]!=1||h[9]!=4||be16(h+10)!=10||be16(h+12)!=40||be16(h+14)!=10||be16(h+16)!=96||be16(h+18)!=106)return false;
    for(unsigned i=20;i<24;i++)if(h[i])return false;
    if(memcmp(h+68,template_sha256,32))return false;
    for(unsigned i=100;i<104;i++)if(h[i])return false;
    memcpy(s->source_mac,h+24,6);memcpy(s->target_mac,h+30,6);
    memcpy(s->source_ip.s6_addr,h+36,16);memcpy(s->target_ip.s6_addr,h+52,16);
    if(!valid_mac(s->source_mac)||!valid_mac(s->target_mac)||!memcmp(s->source_mac,s->target_mac,6)||
       !IN6_IS_ADDR_LINKLOCAL(&s->source_ip)||!IN6_IS_ADDR_LINKLOCAL(&s->target_ip)||
       IN6_IS_ADDR_UNSPECIFIED(&s->source_ip)||IN6_IS_ADDR_UNSPECIFIED(&s->target_ip)||
       IN6_IS_ADDR_MULTICAST(&s->source_ip)||IN6_IS_ADDR_MULTICAST(&s->target_ip)||
       !memcmp(&s->source_ip,&s->target_ip,16))return false;
    for(unsigned i=0;i<4;i++)if(!validate_frame(h+HEADER_LEN+i*PACKET_LEN,i,s))return false;
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
static int wait_go(const char *token,uint64_t *observed) {
    uint64_t start=now_ns();if(!start||start>UINT64_MAX-(uint64_t)GO_TIMEOUT_MS*1000000U)return -1;
    uint64_t deadline=start+(uint64_t)GO_TIMEOUT_MS*1000000U;
    if(printf("READY schema=test121-dual-socket-sender/v1 frames=4 interval_ms=10 mpdu_bytes=96 radiotap_bytes=10 packet_bytes=106 udp_payload_bytes=8 tx_flags=NOSEQNO hardware_honoring=unknown noack_requested=false raw_txs=unknown\n")<0||fflush(stdout))return -1;
    char expected[NONCE_HEX_LEN+5];snprintf(expected,sizeof(expected),"GO %s\n",token);
    for(;;){char line[NONCE_HEX_LEN+8];int r=read_control_line(deadline,line,sizeof(line));if(r!=1)return -1;
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
static int exact_mpdu_ordinal(const uint8_t *raw, size_t length,
                              const struct packet_set *set) {
    if (length < 8U) return -1;
    size_t radiotap = (size_t)raw[2] | ((size_t)raw[3] << 8);
    if (radiotap < 8U || radiotap > length || length - radiotap != MPDU_LEN)
        return -1;
    const uint8_t *mpdu = raw + radiotap;
    for (unsigned i=0;i<FRAME_COUNT;i++) {
        const uint8_t *expected = set->bytes + HEADER_LEN + i * PACKET_LEN + RTAP_LEN;
        if (memcmp(mpdu, expected, MPDU_LEN) == 0) return (int)i;
    }
    return -1;
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
        out->read_attempts++;
        if (received<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) continue;
            out->receive_error=errno?errno:EIO;
            break;
        }
        out->packets_received++;
        /* Count complete exact MPDUs independently of the bounded raw bank.
         * Even a matching PACKET_OUTGOING is a local pre-driver tap only. */
        size_t copied=(size_t)received<sizeof(buffer)?(size_t)received:sizeof(buffer);
        int exact=((size_t)received<=sizeof(buffer) && !(message.msg_flags&MSG_TRUNC))
                  ? exact_mpdu_ordinal(buffer,copied,set) : -1;
        bool type_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_pkttype)+sizeof(address.sll_pkttype);
        bool index_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_ifindex)+sizeof(address.sll_ifindex);
        if(exact>=0) {
            if(!type_present || !index_present || address.sll_ifindex!=expected_index)
                ++out->exact_identity_unavailable;
            else if(address.sll_pkttype==PACKET_OUTGOING)
                ++out->outgoing_exact[(unsigned)exact];
            else
                ++out->non_outgoing_exact[(unsigned)exact];
        }
        if (out->packets_received>RAW_CAPTURE_LIMIT) {
            out->samples_overflow++;
            continue;
        }
        struct rx_sample *sample=&out->samples[out->packets_received-1U];
        sample->packet_type_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_pkttype)+sizeof(address.sll_pkttype);
        sample->ifindex_present=message.msg_namelen>=offsetof(struct sockaddr_ll,sll_ifindex)+sizeof(address.sll_ifindex);
        sample->packet_type=(unsigned)address.sll_pkttype;
        sample->ifindex=address.sll_ifindex>0?(unsigned)address.sll_ifindex:0U;
        sample->msg_flags=(unsigned)message.msg_flags;
        sample->received_len=(size_t)received;
        sample->copied_len=sample->received_len<sizeof(buffer)?sample->received_len:sizeof(buffer);
        memcpy(sample->raw,buffer,sample->copied_len);
        sample->exact_ordinal=exact;
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
        out->read_attempts++;
        if(received<0) {
            if(errno==EAGAIN || errno==EWOULDBLOCK) {
                out->drain_complete=true;
                break;
            }
            if(errno==EINTR) continue;
            out->receive_error=errno?errno:EIO;
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
static void print_hex(const uint8_t *raw,size_t length) {
    for(size_t i=0;i<length;i++)printf("%02x",raw[i]);
}
static void emit_aborted_before_go(const struct options *o);
static int send_frames(const struct options *o,const struct packet_set *s,int tx_fd,int observer_fd,int observer_index,uint64_t go,const struct stale_queue_observation *stale) {
    uint64_t start=now_ns();if(!start||start>UINT64_MAX-SEND_BUDGET_NS)return EXIT_SEND;
    uint64_t deadline=start+SEND_BUDGET_NS;struct send_sample row[FRAME_COUNT];memset(row,0,sizeof(row));
    uint64_t go_to_start_ns=start>=go?start-go:UINT64_MAX;
    uint64_t first_send_ns=0;
    uint64_t previous_send_before_ns=0;
    unsigned attempted=0,completed=0;int last_errno=0;const char *reason="complete";
    /* READY was emitted before GO. This marks actual post-GO send-loop start. */
    printf("{\"event\":\"SENDER_STARTED\",\"schema\":\"test121-dual-socket-sender/v1\",\"timing_schema\":1,\"clock_domain\":\"CLOCK_MONOTONIC\",\"run_token\":\"%s\",\"go_received_ns\":%" PRIu64 ",\"started_ns\":%" PRIu64 ",\"go_to_start_ns\":%" PRIu64 ",\"go_to_start_max_ns\":%" PRIu64 ",\"send_budget_ns\":%" PRIu64 ",\"frames_requested\":4,\"interval_ms\":10,\"tx_flags_requested\":\"NOSEQNO\",\"noack_requested\":false}\n",
        o->nonce,go,start,go_to_start_ns,(uint64_t)GO_TO_START_MAX_NS,(uint64_t)SEND_BUDGET_NS);fflush(stdout);
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
        if(before>=deadline){reason="send_budget_expired";break;}
        const uint8_t *packet=s->bytes+HEADER_LEN+i*PACKET_LEN;
        const uint8_t *mpdu=packet+RTAP_LEN;
        uint16_t sequence_control=(uint16_t)(mpdu[22]|((uint16_t)mpdu[23]<<8));
        row[i].ordinal=i;row[i].ieee80211_sequence=(sequence_control>>4)&0x0fffU;
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
    observe_monitor_until(observer_fd,observer_index,deadline,s,start,&rx);
    uint64_t finished=rx.ended_ns;bool complete=completed==FRAME_COUNT&&attempted==FRAME_COUNT&&last_errno==0;
    if(!complete&&last_errno==0)last_errno=ETIMEDOUT;
    uint64_t elapsed_ms=0;
    if(completed>0&&row[completed-1].after_ns>=start)
        elapsed_ms=(row[completed-1].after_ns-start)/UINT64_C(1000000);
    bool deadline_hit=!strcmp(reason,"send_budget_expired")||!strcmp(reason,"send_completed_after_budget");
    printf("{\"event\":\"SENDER_RESULT\",\"schema\":\"test121-dual-socket-sender/v1\",\"timing_schema\":1,\"clock_domain\":\"CLOCK_MONOTONIC\",\"status\":\"%s\",\"run_token\":\"%s\",\"go_received_ns\":%" PRIu64 ",\"frames_requested\":4,\"frames_attempted\":%u,\"frames_completed\":%u,\"sent\":%u,\"payload_bytes\":96,\"packet_bytes\":106,\"radiotap_bytes\":10,\"mpdu_bytes\":96,\"udp_payload_bytes\":8,\"elapsed_ms\":%" PRIu64 ",\"deadline_hit\":%s,\"error_count\":%u,\"last_errno\":%d,\"stop_reason\":\"%s\",\"tx_flags_requested\":\"NOSEQNO\",\"noack_requested\":false,\"ack_policy\":\"normal_unicast_requested\",\"hardware_honoring\":\"unknown\",\"raw_txs\":\"unknown\",\"mac_ack\":\"unknown\",\"interval_ms\":10,\"send_budget_ns\":%" PRIu64 ",\"started_ns\":%" PRIu64 ",\"finished_ns\":%" PRIu64 ",\"go_to_start_ns\":%" PRIu64 ",\"go_to_start_max_ns\":%" PRIu64 ",\"first_send_ns\":",
        complete?"complete":"failed",o->nonce,go,attempted,completed,completed,elapsed_ms,
        deadline_hit?"true":"false",complete?0U:1U,last_errno,reason,
        (uint64_t)SEND_BUDGET_NS,start,finished,go_to_start_ns,
        (uint64_t)GO_TO_START_MAX_NS);
    if(first_send_ns)printf("%" PRIu64,first_send_ns);
    else printf("null");
    printf(",\"local_send_calls\":%u,\"pre_capture_queue_drain\":{\"schema\":\"test121-pre-capture-drain/v1\",\"read_attempts\":%u,\"packets_drained\":%u,\"receive_error\":%d,\"drain_complete\":%s,\"kernel_stats_available\":%s,\"kernel_packets\":",
        attempted,stale->read_attempts,stale->packets_drained,stale->receive_error,
        stale->drain_complete?"true":"false",
        stale->kernel_stats_available?"true":"false");
    if(stale->kernel_stats_available)printf("%u,\"kernel_dropped_packets\":%u},",stale->kernel_packets,stale->kernel_dropped);
    else printf("null,\"kernel_dropped_packets\":null},");
    printf("\"send_timing\":[");
    for(unsigned i=0;i<attempted;i++)printf("%s{\"ordinal\":%u,\"ieee80211_sequence\":%u,\"awdl_sequence\":%u,\"before_ns\":%" PRIu64 ",\"after_ns\":%" PRIu64 ",\"return_bytes\":%lld,\"errno\":%d}",i?",":"",row[i].ordinal,row[i].ieee80211_sequence,row[i].awdl_sequence,row[i].before_ns,row[i].after_ns,row[i].return_bytes,row[i].error);
    unsigned stored=rx.packets_received<RAW_CAPTURE_LIMIT?rx.packets_received:RAW_CAPTURE_LIMIT;
    bool all_raw_samples_complete=true;
    for(unsigned i=0;i<stored;i++) {
        if(rx.samples[i].copied_len!=rx.samples[i].received_len)
            all_raw_samples_complete=false;
    }
    printf("],\"actual_horizon_ns\":%" PRIu64 ",\"monitor_observation\":{\"schema\":\"test121-dual-socket-monitor/v1\",\"capture_window_ns\":%" PRIu64 ",\"started_ns\":%" PRIu64 ",\"ended_ns\":%" PRIu64 ",\"capture_finished\":%s,\"capture_limit_reached\":%s,\"read_attempts\":%u,\"packets_received\":%u,\"samples_recorded\":%u,\"samples_overflow\":%u,\"receive_error\":%d,\"kernel_stats_available\":%s,\"kernel_packets\":",
        finished>=start?finished-start:0,(uint64_t)SEND_BUDGET_NS,rx.started_ns,rx.ended_ns,
        rx.capture_finished?"true":"false",rx.capture_limit_reached?"true":"false",
        rx.read_attempts,rx.packets_received,
        rx.packets_received<RAW_CAPTURE_LIMIT?rx.packets_received:RAW_CAPTURE_LIMIT,
        rx.samples_overflow,rx.receive_error,rx.kernel_stats_available?"true":"false");
    if(rx.kernel_stats_available)printf("%u,\"kernel_dropped_packets\":%u,",rx.kernel_packets,rx.kernel_dropped);
    else printf("null,\"kernel_dropped_packets\":null,");
    printf("\"loss_free\":");
    if(rx.receive_error!=0 || rx.capture_limit_reached || rx.samples_overflow>0 ||
       !rx.capture_finished || !all_raw_samples_complete)
        printf("false");
    else if(rx.kernel_stats_available)
        printf(rx.kernel_dropped==0 && rx.kernel_packets==rx.packets_received?"true":"false");
    else printf("null");
    printf(",\"socket_topology\":\"distinct_tx_and_observer\",\"observer_bound_ifindex\":%d,\"outgoing_tap_is_rf_proof\":false,\"outgoing_exact_by_ordinal\":[",observer_index);
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.outgoing_exact[i]);
    printf("],\"non_outgoing_exact_by_ordinal\":[");
    for(unsigned i=0;i<FRAME_COUNT;i++)printf("%s%u",i?",":"",rx.non_outgoing_exact[i]);
    printf("],\"exact_identity_unavailable\":%u,\"samples\":[",rx.exact_identity_unavailable);
    for(unsigned i=0;i<stored;i++) {
        struct rx_sample *sample=&rx.samples[i];
        printf("%s{\"packet_type_present\":%s,\"packet_type\":",i?",":"",
               sample->packet_type_present?"true":"false");
        if(sample->packet_type_present)printf("%u,",sample->packet_type);else printf("null,");
        printf("\"ifindex_present\":%s,\"ifindex\":",sample->ifindex_present?"true":"false");
        if(sample->ifindex_present)printf("%u,",sample->ifindex);else printf("null,");
        printf("\"msg_flags\":%u,\"received_len\":%zu,\"copied_len\":%zu,\"raw_packet_complete\":%s,\"exact_ordinal\":",
               sample->msg_flags,sample->received_len,sample->copied_len,
               sample->copied_len==sample->received_len?"true":"false");
        if(sample->exact_ordinal>=0)printf("%d,",sample->exact_ordinal);else printf("null,");
        printf("\"raw_packet_hex\":\"");print_hex(sample->raw,sample->copied_len);printf("\"}");
    }
    printf("]},\"rf_transmission_proven\":false,\"raw_txs\":\"unknown\",\"mac_ack\":\"unknown\",\"peer_receipt_proven\":false,\"airdrop_proven\":false}\n");
    return fflush(stdout)?EXIT_SEND:(complete?0:EXIT_SEND);
}
static void emit_aborted_before_go(const struct options *o) {
    printf("{\"event\":\"SENDER_RESULT\",\"schema\":\"test121-dual-socket-sender/v1\",\"status\":\"aborted\",\"run_token\":\"%s\",\"frames_requested\":4,\"frames_attempted\":0,\"frames_completed\":0,\"sent\":0,\"payload_bytes\":96,\"packet_bytes\":106,\"radiotap_bytes\":10,\"mpdu_bytes\":96,\"udp_payload_bytes\":8,\"elapsed_ms\":0,\"deadline_hit\":false,\"error_count\":0,\"last_errno\":0,\"stop_reason\":\"aborted_before_go\",\"tx_flags_requested\":\"NOSEQNO\",\"hardware_honoring\":\"unknown\"}\n",o->nonce);
    fflush(stdout);
}
#endif

int main(int argc,char **argv) {
    struct options o;if(argc==2&&!strcmp(argv[1],"--help")){usage(stdout,argv[0]);return 0;}
    if(!parse_options(argc,argv,&o)){usage(stderr,argv[0]);return EXIT_ARGUMENT;}
    struct packet_set set;memset(&set,0,sizeof(set));
    if(!read_packet_set(o.file,&set)){fprintf(stderr,"error=packet_set_invalid_or_unsafe\n");return EXIT_ARGUMENT;}
    if(o.verify_only){printf("{\"event\":\"PACKET_SET_VALID\",\"schema\":\"test104-unicast-packet-set/v1\",\"frames\":4,\"interval_ms\":10,\"budget_ms\":40,\"noack_requested\":false,\"transmission_capability\":false,\"rf_transmission_proven\":false}\n");return fflush(stdout)?EXIT_ARGUMENT:0;}
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
    uint64_t go=0;int gate=wait_go(o.nonce,&go);
    if(gate==0){emit_aborted_before_go(&o);close(observer_fd);close(tx_fd);return 0;}
    if(gate<0){close(observer_fd);close(tx_fd);fprintf(stderr,"error=go_gate_failed\n");return EXIT_GATE;}
    struct stale_queue_observation stale;
    drain_observer_queue_after_go(observer_fd,&stale);
    int result=send_frames(&o,&set,tx_fd,observer_fd,index,go,&stale);close(observer_fd);close(tx_fd);return result;
#endif
}

