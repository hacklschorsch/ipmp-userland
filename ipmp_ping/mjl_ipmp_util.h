#ifndef _MJL_IPMP_UTIL_H
#define _MJL_IPMP_UTIL_H

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include "ipmp.h"
#endif

#if defined(__linux__)
#include "ipmp.h"
#endif

typedef struct icmp_packet
{
  struct sockaddr *addr;
  u_int8_t         type;
  u_int8_t         code;
} icmp_packet_t;

typedef struct ipmp_echopacket
{
  struct ipmptime out;
  struct ipmptime there;
  struct ipmptime back;
  u_int16_t       sid;
  u_int8_t        hops_there;
  u_int8_t        hops_back;
  icmp_packet_t  *icmp;
} ipmp_echopacket_t;

typedef struct dns_entry
{
  struct sockaddr *addr;
  char            *name;
} dns_entry_t;

int      get_syscall(char *name, int *num);
long     tv_sec();
long     tv_usec();
char    *rtt_msec_str(struct ipmptime *start, struct ipmptime *finish);
u_short  in_cksum(u_short *addr, int len);

int     timeval_cmp(struct timeval *a, struct timeval *b);
int     timeval_tostr(struct timeval *timeval, char *buf, size_t bufsize);
int     timeval_add(struct timeval *tv, int msec);
int64_t timeval_diff_msec(struct timeval *tv, struct timeval *b);

int ipmptime_tostr(struct ipmptime *t, char *buf, size_t bufsize);
int ipmptime_cmp(struct ipmptime *a, struct ipmptime *b);
int ipmptime_add(struct ipmptime *t, int msec);
int ipmptime_diff_usec(struct ipmptime *a, struct ipmptime *b);
int ipmptime_diff_msec(struct ipmptime *a, struct ipmptime *b);

int sockaddr_tostr(struct sockaddr *sa, char *buf, size_t len);
int sockaddr_cmp(const void **a, const void **b);
struct sockaddr *sockaddr_create(sa_family_t sa_family, void *addr);

void in6addr_tostr(struct in6_addr *addr, char *buf, size_t len);
void in4addr_tostr(struct in_addr  *addr, char *buf, size_t len);

int in6addr_cmp(struct in6_addr *a, struct in6_addr *b);

int learn_localaddresses();
int is_localaddress(struct  sockaddr *addr);
int is_localaddress6(struct in6_addr *addr);
int is_localaddress4(struct in_addr  *addr);

int dnsentry_init();
struct dns_entry *dnsentry_lookup4(struct in_addr  *addr);
struct dns_entry *dnsentry_lookup6(struct in6_addr *addr);
void dnsentry_close();

int  ipmp_echopacket_sidcmp(const void **a, const void **b);
int  ipmp_echopacket_outcmp(const void **a, const void **b);
void ipmp_echopacket_destroy(void *ptr);
int  ipmp_echopacket_tostr(void *ptr, char *str, size_t len);

typedef struct ipmp_sendechorequest
{
  struct sockaddr *src, *dst;
  int              len;
  int              ttl;
  u_int16_t        id, seq;
  u_int16_t        options;
  u_int8_t         tos;
} ipmp_sendechorequest_t;

int ipmp_sendechorequest_mod(int syscall_num, struct ipmp_sendechorequest *er);
int ipmp_sendechorequest_raw(int sock, struct ipmp_sendechorequest *er);
int ipmp_sendechorequest_ioctl(int sock, struct ipmp_sendechorequest *er);

char *gai_strerror_wrap(int ecode);

#endif /* _MJL_IPMP_UTIL_H */
