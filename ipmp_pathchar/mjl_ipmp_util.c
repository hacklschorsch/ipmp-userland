#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
# include <sys/syscall.h>
# include "ipmp.h"
# include <ifaddrs.h>
#endif

#if defined(__linux__)
#define __FAVOR_BSD
# include "ipmp.h"
# include <sys/ioctl.h>
# include <linux/if.h>
#endif

#ifndef s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#include <unistd.h>

#include "mjl_array.h"
#include "mjl_ipmp_util.h"

/*
 * array to store local IPv4 / IPv6 addresses that we learn through a call
 * to learn_localaddresses()
 */
static mjl_array_t *localaddresses;

#if defined(__FreeBSD__)
#if __FreeBSD_version < 310000
#include <sys/lkm.h>
#include <sys/ioctl.h>
#include <fcntl.h>
int get_syscall(char *name, int *num)
{  
  struct lmc_stat stat;
  int             devlkmfd;
  int             error;

  /*
   * get the necessary data all ready to go so that we have /dev/lkm open
   * for the shortest possible time.  not sure if /dev/lkm can be shared or not
   * but in case it can't, the following open call does not block waiting
   */
  bzero(&stat, sizeof(stat));
  stat.id = -1;
  snprintf(stat.name, sizeof(stat.name), "%s_mod", name);

  /*
   * unfortunately, modfind does not seem to work with lkms, so i have to
   * open the lkm device and query that
   */
  if((devlkmfd = open("/dev/lkm", O_RDONLY | O_NONBLOCK, 0)) == -1)
    {
      return errno;
    }

  error = ioctl(devlkmfd, LMSTAT, &stat);
  close(devlkmfd);
 
  if(error == -1)
    {
      return errno;
    }

  *num = stat.offset;

  return 0;
}
#else
#include <sys/module.h>
int get_syscall(char *modname, int *num)
{
  struct module_stat stat;
  int                modid;

  modid = modfind(modname);
  if(modid == -1)
    {
      return errno;
    }

  stat.version = sizeof(stat);
  modstat(modid, &stat);
  *num = stat.data.intval;

  return 0; 
}
#endif
#endif

/*
 * rtt()
 * this is the fixed? version of rtt that does all its work in nanoseconds
 * because of this, it is necessary to work with int64's so that we have
 * adequate space to store trillions of nanoseconds
 */
char *rtt_msec_str(struct ipmptime *start, struct ipmptime *finish)
{
  int64_t nano;
  int32_t milli, remainder;
  static char rtt[128];

  /*
   * work out how much the seconds have changed by, and convert that to a 
   * nanosecond representation
   */
  nano =  (finish->sec  - start->sec) * (int64_t)1000000000;
  nano += (finish->nsec - start->nsec);

  /*
   * convert the nanoseconds to a milli second representation, and round up
   * if necessary
   */
  milli     = (int32_t)(nano / 1000000);
  remainder = (int32_t)(nano % 1000000);
  if(remainder > 500000) milli++;

  /*
   * store in the static buffer the string representation of the milliseconds
   * and return it
   */
  snprintf(rtt, sizeof(rtt), "%d", milli);
  return rtt;
}

/*
 * tv_sec
 */
long tv_sec()
{
  struct  timeval   tv;
  struct  timezone  tz;
  gettimeofday(&tv, &tz);
  return tv.tv_sec;
}

/*
 * tv_usec
 * return the usec component of the current time
 * suitable for random number seeding?
 */
long tv_usec()
{
  struct timeval tv;
  struct timezone tz;
  gettimeofday(&tv, &tz);
  return tv.tv_usec;
}

int timeval_tostr(struct timeval *timeval, char *buf, size_t bufsize)
{
  char   ctime_buf[26];
  time_t t = timeval->tv_sec;

  ctime_r(&t, ctime_buf);
  ctime_buf[24] = '\0';

  snprintf(buf, bufsize, "%s %d", ctime_buf, (int)timeval->tv_usec);
  return 1;
}

int ipmptime_tostr(struct ipmptime *ipmptime, char *buf, size_t bufsize)
{
  char   ctime_buf[26];
  time_t t = ipmptime->sec;

  strncpy(ctime_buf, ctime(&t), 24);
  ctime_buf[24] = '\0';

  snprintf(buf, bufsize, "%s %d", ctime_buf, (int)ipmptime->nsec);
  return 1;
}

int ipmptime_cmp(struct ipmptime *ta, struct ipmptime *tb)
{
  if(ta == NULL || tb == NULL)
    {
      return 0;
    }

  if(ta->sec == tb->sec)
    {
      if(ta->nsec == tb->nsec)
	{
	  return 0;
	}
      else if(ta->nsec < tb->nsec)
	{
	  return -1;
	}
      else
	{
	  return 1;
	}
    }
  else if(ta->sec < tb->sec)
    {
      return -1;
    }
  else             
    {
      return 1;
    }
}

/*
 * timeval_cmp
 *
 * this is used for array_heapsort() and for array_find()
 *
 * "the comparison function must return an integer less than, equal to, or
 *  greater than zero if the first argument is considered to be respectively
 *  less than, equal to, or greater than the second."
 *
 *   - QSORT(3)
 *
 */
int timeval_cmp(struct timeval *ta, struct timeval *tb)
{
  if(ta == NULL || tb == NULL)
    {
      return 0;
    }

  if(ta->tv_sec == tb->tv_sec)
    {
      if(ta->tv_usec == tb->tv_usec)
	{
	  return 0;
	}
      else if(ta->tv_usec < tb->tv_usec)
	{
	  return -1;
	}
      else
	{
	  return 1;
	}
    }
  else if(ta->tv_sec < tb->tv_sec)
    {
      return -1;
    }
  else             
    {
      return 1;
    }
}

int timeval_add(struct timeval *tv, int msec)
{
  /* sanity checks */
  if(tv == NULL || msec < 0)
    {
      return 0;
    }

  /* work out how many seconds away */
  while(msec > 1000)
    {
      tv->tv_sec++;
      msec -= 1000;
    }

  /* check for overflow of usec's */
  tv->tv_usec += (msec * 1000);
  if(tv->tv_usec >= 1000000)
    {
      tv->tv_sec++;
      tv->tv_usec -= 1000000;
    }

  return 1;
}

int ipmptime_add(struct ipmptime *ts, int msec)
{
  /* sanity checks */
  if(ts == NULL || msec < 0)
    {
      return 0;
    }

  /* work out how many seconds away */
  while(msec > 1000)
    {
      ts->sec++;
      msec -= 1000;
    }

  /* check for overflow of usec's */
  ts->nsec += (msec * 1000);
  if(ts->nsec >= 100000000)
    {
      ts->sec++;
      ts->nsec -= 100000000;
    }

  return 1;
}

/*
 * timeval_diff_msec
 * return the millisecond difference between the two timevals.
 * a - b
 */
int64_t timeval_diff_msec(struct timeval *a, struct timeval *b)
{
  int64_t temp, a_sec,  a_usec, b_sec, b_usec;

  a_sec  = (int64_t)a->tv_sec  * (int64_t)1000;
  a_usec = (int64_t)a->tv_usec / (int64_t)1000;
  b_sec  = (int64_t)b->tv_sec  * (int64_t)1000;
  b_usec = (int64_t)b->tv_usec / (int64_t)1000;

  temp = a_sec - b_sec + a_usec - b_usec;
  return temp;
}

/*
 * timeval_diff_usec
 * return the microsecond difference between the two timevals.
 * a - b
 */
int ipmptime_diff_usec(struct ipmptime *a, struct ipmptime *b)
{
  int64_t temp, a_sec, a_nsec, b_sec, b_nsec;

  a_sec  = (int64_t)a->sec  * (int64_t)1000000;
  a_nsec = (int64_t)a->nsec / (int64_t)1000;
  b_sec  = (int64_t)b->sec  * (int64_t)1000000;
  b_nsec = (int64_t)b->nsec / (int64_t)1000;

  temp = a_sec - b_sec + a_nsec - b_nsec;
  return (int)temp;
}

int ipmptime_diff_msec(struct ipmptime *a, struct ipmptime *b)
{
  int64_t temp, a_sec, a_nsec, b_sec, b_nsec;

  a_sec  = (int64_t)a->sec  * (int64_t)1000;
  a_nsec = (int64_t)a->nsec / (int64_t)1000000;
  b_sec  = (int64_t)b->sec  * (int64_t)1000;
  b_nsec = (int64_t)b->nsec / (int64_t)1000000;

  temp = a_sec - b_sec + a_nsec - b_nsec;
  return (int)temp;
}

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 *
 * this was taken from /usr/src/sbin/ping/ping.c
 *
 */
u_short in_cksum(u_short *addr, int len)
{
  register int nleft = len;
  register u_short *w = addr;
  register int sum = 0;
  u_short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(u_char *)(&answer) = *(u_char *)w ;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;                        /* truncate to 16 bits */
  return(answer);
}

struct sockaddr *sockaddr_create(sa_family_t sa_family, void *addr)
{
  struct sockaddr *sa = NULL;
  size_t           size;

  if(sa_family == AF_INET)
    {
      size = sizeof(struct sockaddr_in);
      sa = (struct sockaddr *)malloc(size);
      if(sa == NULL) return NULL;

      bzero(sa, size);
      sa->sa_family = AF_INET;
      bcopy(addr, &((struct sockaddr_in *)sa)->sin_addr, 4);

#if defined(__FreeBSD__) || defined(__NetBSD__)
      sa->sa_len = size;
#endif
    }
  else if(sa_family == AF_INET6)
    {
      size = sizeof(struct sockaddr_in6);
      sa = (struct sockaddr *)malloc(size);
      if(sa == NULL) return 0;

      bzero(sa, size);
      sa->sa_family = AF_INET6;
      bcopy(addr, &((struct sockaddr_in6 *)sa)->sin6_addr, 16); 

#if defined(__FreeBSD__) || defined(__NetBSD__)
      sa->sa_len = size;
#endif
    }

  return sa;
}

int sockaddr_tostr(struct sockaddr *sa, char *buf, size_t len)
{
  char addr[256];

  if(sa->sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr,
		addr, sizeof(addr));
    }
  else if(sa->sa_family == AF_INET6)
    {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr,
		addr, sizeof(addr));
    }
  else
    {
      return 0;
    }

  snprintf(buf, len, "%s", addr); buf[len-1] = '\0';

  return 1;
}

int in6addr_cmp(struct in6_addr *a, struct in6_addr *b)
{
  int i;

  for(i=0; i<4; i++)
    {
      if(a->s6_addr32[i] < b->s6_addr32[i]) return -1;
      if(a->s6_addr32[i] > b->s6_addr32[i]) return  1;
    }

  return 0;
}

int sockaddr_in_cmp(struct sockaddr_in *a, struct sockaddr_in *b)
{
  if(a->sin_addr.s_addr < b->sin_addr.s_addr) return -1;
  if(a->sin_addr.s_addr > b->sin_addr.s_addr) return  1;
  return 0;
}

int sockaddr_in6_cmp(struct sockaddr_in6 *a, struct sockaddr_in6 *b)
{
  int i;

  for(i=0; i<4; i++)
    {
      if(a->sin6_addr.s6_addr32[i] < b->sin6_addr.s6_addr32[i]) return -1;
      if(a->sin6_addr.s6_addr32[i] > b->sin6_addr.s6_addr32[i]) return 1;
    }

  return 0;
}

/*
 * do a numerical comparison of the addresses contained in each sockaddr
 * only understands AF_INET and AF_INET6, if the sockaddr's passed aren't
 * compatible, it returns zero.
 */
int sockaddr_cmp(const void **a, const void **b)
{
  struct sockaddr     *sa, *sb;
  int                  i;

  /* sanity checks */
  if(a == NULL || *a == NULL || b == NULL || *b == NULL)
    {
      return 0;
    }

  sa = (struct sockaddr *)*a;
  sb = (struct sockaddr *)*b;

  if(sa->sa_family < sb->sa_family) return -1;
  if(sa->sa_family > sb->sa_family) return 1;

  if(sa->sa_family == AF_INET)
    {
      i = sockaddr_in_cmp((struct sockaddr_in *)sa,(struct sockaddr_in *)sb);
      return i;
    }
  
  if(sa->sa_family == AF_INET6)
    {
      i = sockaddr_in6_cmp((struct sockaddr_in6*)sa,(struct sockaddr_in6*)sb);
      return i;
    }

  return 0;
}

void in6addr_tostr(struct in6_addr *addr, char *buf, size_t len)
{
  if(addr == NULL || buf == NULL || len < 1) return;
  inet_ntop(AF_INET6, addr, buf, len);
  buf[len-1] = '\0';
  return;
}

void in4addr_tostr(struct in_addr *addr, char *buf, size_t len)
{
  if(addr == NULL || buf == NULL || len < 1) return;
  inet_ntop(AF_INET, addr, buf, len);
  buf[len-1] = '\0';
  return;
}

#if defined(__FreeBSD__) || defined(__NetBSD__)
int learn_localaddresses()
{
  struct ifaddrs      *ifa, *ifa0;
  struct sockaddr     *sin;
  size_t               size;

  if(getifaddrs(&ifa0) == -1)
    {
      return 0;
    }

  if(localaddresses == NULL)
    {
      localaddresses = array_create(5, sockaddr_cmp);
    }

  array_remove(localaddresses, 0, array_getcount(localaddresses));

  for(ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next)
    {
      if(ifa->ifa_addr != NULL)
	{
	  switch(ifa->ifa_addr->sa_family)
	    {
	    case AF_INET:
	    case AF_INET6:
	      size = ifa->ifa_addr->sa_len;
	      sin  = (struct sockaddr *)malloc(size);
	      bcopy(ifa->ifa_addr, sin, size);
	      array_insert(localaddresses, sin);
	      break;
	      
	    default:
	      break;
	    }
	}
    }

  freeifaddrs(ifa0);
  array_quicksort(localaddresses);

  return 1;
}
#elif defined(__linux__)
int learn_localaddresses()
{
  struct ifreq        ifr;
  int                 fd;
  struct sockaddr_in *sin, *ptr;
  struct ifconf       ifc;
  struct ifreq       *ifr_ptr;
  int                 i, numreqs = 5;

  if(localaddresses == NULL)
    {
      localaddresses = array_create(5, sockaddr_cmp);
    }

  array_remove(localaddresses, 0, array_getcount(localaddresses));

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd == -1) return 0;

  ifc.ifc_buf = NULL;
  while(1)
    {
      ifc.ifc_len = sizeof(struct ifreq) * numreqs;
      ifc.ifc_buf = (char *)realloc(ifc.ifc_buf, ifc.ifc_len);

      if(ioctl(fd, SIOCGIFCONF, &ifc) < 0)
	{
	  free(ifc.ifc_buf);
	  return 0;
	}

      if((unsigned int)(ifc.ifc_len) < (sizeof(struct ifreq) * numreqs)) break;
      else numreqs += 5;
    }

  numreqs = ifc.ifc_len / sizeof(struct ifreq);
  ifr_ptr = ifc.ifc_req;

  for(i=0; i<numreqs; i++)
    {
      strncpy(ifr.ifr_name, ifr_ptr->ifr_name, sizeof(ifr.ifr_name));
      ifr.ifr_addr.sa_family = AF_INET;

      if(ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
	  sin = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	  bzero(sin, sizeof(struct sockaddr_in));
	  
	  ptr = (struct sockaddr_in *)&ifr.ifr_addr;
	  sin->sin_family = AF_INET;
	  sin->sin_addr   = ptr->sin_addr;
	  
	  array_insert(localaddresses, sin);
	}

      ifr_ptr++;
    }

  free(ifc.ifc_buf);
  close(fd);

  array_quicksort(localaddresses);

  return 1;
}
#endif

int is_localaddress(struct sockaddr *addr)
{
  if(array_find(localaddresses, addr) != NULL) return 1;
  return 0;
}

int is_localaddress6(struct in6_addr *addr)
{
  struct sockaddr_in6 sin6;
  sin6.sin6_family = AF_INET6;
  bcopy(addr, &sin6.sin6_addr, sizeof(struct in6_addr));
  return is_localaddress((struct sockaddr *)&sin6);
}

int is_localaddress4(struct in_addr *addr)
{
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  bcopy(addr, &sin.sin_addr, sizeof(struct in_addr));

  /*
   * char buf[128];
   * sockaddr_tostr((struct sockaddr *)&sin, buf, sizeof(buf));
   * printf("is_localaddress4: %s\n", buf);
   */

  return is_localaddress((struct sockaddr *)&sin);
}

int ipmp_echopacket_tostr(void *ptr, char *str, size_t len)
{
  ipmp_echopacket_t *ep;
  char ta[50], tb[50], tc[50];

  if(ptr == NULL || str == NULL || len < 1) return 0;

  ep = (ipmp_echopacket_t *)ptr;

  ipmptime_tostr(&ep->out,   ta, sizeof(ta));
  ipmptime_tostr(&ep->there, tb, sizeof(tb));
  ipmptime_tostr(&ep->back,  tc, sizeof(tc));

  snprintf(str, len, "%s\n%s\n%s\nhops there %d hops back %d",
	   ta, tb, tc, ep->hops_there, ep->hops_back);

  str[len-1] = '\0';

  return 1;
}

/*
 * ipmp_echopacket_cmp
 *
 * this function will compare two records based on their sid
 *
 * i really want an option to compare based on their out timeval but don't
 * know the best way to achieve this yet
 */
int ipmp_echopacket_sidcmp(const void **a, const void **b)
{
  struct ipmp_echopacket *pkt_a, *pkt_b;

  if(a == NULL || b == NULL) return 0;
  pkt_a = (struct ipmp_echopacket *)*a;
  pkt_b = (struct ipmp_echopacket *)*b;

  if(pkt_a->sid < pkt_b->sid) return -1;
  if(pkt_a->sid > pkt_b->sid) return 1;
  return 0;
}

int ipmp_echopacket_outcmp(const void **a, const void **b)
{
  struct ipmp_echopacket *pkt_a, *pkt_b;

  if(a == NULL || b == NULL) return 0;
  pkt_a = (struct ipmp_echopacket *)*a;
  pkt_b = (struct ipmp_echopacket *)*b;

  return ipmptime_cmp(&pkt_a->out, &pkt_b->out);
}

void ipmp_echopacket_destroy(void *ptr)
{
  ipmp_echopacket_t *ep = (ipmp_echopacket_t *)ptr;
  if(ep != NULL) free(ep);
  return;
}

#if defined(__FreeBSD__) || defined(__NetBSD__)

int ipmp_sendechorequest_mod(int syscall_num, struct ipmp_sendechorequest *er)
{
  struct ipmp_ping_args args;

  if(er->dst->sa_family == AF_INET6)
    {
      args.ip_v = 6;
      if(er->len < 88) return EINVAL;
      else             args.len = er->len;
    }
  else if(er->dst->sa_family == AF_INET)
    {
      args.ip_v = 4;
      if(er->len < 52) return EINVAL;
      else             args.len = er->len;
    }
  else return EINVAL;

  args.id  = er->id;
  args.seq = er->seq;
  args.ttl = er->ttl;
  args.dst = er->dst;
  args.src = er->src;
  args.tos = er->tos;

  if(syscall(syscall_num, &args, er->dst, er->src) == -1)
    {
      return errno;
    }

  return 0; 
}

#elif defined(__linux__)

int ipmp_sendechorequest_ioctl(int sock, struct ipmp_sendechorequest *er)
{
  struct ipmp_ping_args args;

  if(er->dst->sa_family == AF_INET6)
    {
      args.ip_v = 6;
      if(er->len < 88) return EINVAL;
      else             args.len = er->len;
    }
  else if(er->dst->sa_family == AF_INET)
    {
      args.ip_v = 4;
      if(er->len < 52) return EINVAL;
      else             args.len = er->len;
    }
  else return EINVAL;

  args.id  = er->id;
  args.seq = er->seq;
  args.ttl = er->ttl;
  args.dst = er->dst;
  args.src = er->src;
  args.tos = er->tos;

  if(ioctl(sock, SIOCSENDECHOREQUEST, &args) == -1)
    {
      return errno;
    }

  return 0;
}

#endif

int ipmp_sendechorequest_raw(int sock, struct ipmp_sendechorequest *er)
{
  struct ip               *ip;
  struct ipmp             *ipmp;
  struct ipmp_trailer     *ipmp_trailer;
  u_int16_t                pp;
  socklen_t                sa_len;
  u_char                  *buf;
  struct ipmp_pathrecord  *pr;
  struct ipmp_pathrecord6 *pr6;
  struct timeval           tv;
  struct timezone          tz;
  struct sockaddr_in      *sin4;
  int                      i, pr_len;
  int                      len;

  if(er->dst == NULL) { printf("er->dst null\n"); return EINVAL; }

  if(er->dst->sa_family == AF_INET)
    {
      if(er->len < 52) { printf("er->len %d < 52\n", er->len); return EINVAL; }
      len = er->len + sizeof(struct ip);
      buf = (u_char *)malloc(len);
      if(buf == NULL) return ENOMEM;

      sa_len = sizeof(struct sockaddr_in);
      pp     = (sizeof(struct ipmp) + sizeof(struct ipmp_pathrecord));

      i = 1;
      if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) == -1)
	{
#ifndef NDEBUG
	  fprintf(stderr, "could not ip_hdrincl, errno %d\n", errno);
#endif
	  return errno;
	}

      ip   = (struct ip *)buf;
      ipmp = (struct ipmp *)(buf + sizeof(struct ip));
      ipmp_trailer = (struct ipmp_trailer *)(buf + len - 4);

      ip->ip_v   = 4;
      ip->ip_hl  = 5;
      ip->ip_tos = er->tos;
      ip->ip_len = len;
      ip->ip_id  = 0;
      ip->ip_off = IP_DF;
      ip->ip_ttl = er->ttl;
      ip->ip_p   = IPPROTO_IPMP;
      ip->ip_sum = 0;

      if(er->src != NULL)
	ip->ip_src = ((struct sockaddr_in *)er->src)->sin_addr;
      else
	ip->ip_src.s_addr = INADDR_ANY;

      ip->ip_dst = ((struct sockaddr_in *)er->dst)->sin_addr;

#if defined(__linux__)
      ip->ip_len = htons(ip->ip_len);
      ip->ip_off = htons(ip->ip_off);
#endif
    }
  else if(er->dst->sa_family == AF_INET6)
    {
      if(er->len < 88) return EINVAL;
      len = er->len;
      buf = (u_char *)malloc(len);
      if(buf == NULL) return ENOMEM;

      sa_len = sizeof(struct sockaddr_in6);
      pp     = (sizeof(struct ipmp) + sizeof(struct ipmp_pathrecord6));      

      i = er->ttl;
      if(setsockopt(sock,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&i,sizeof(i)) == -1)
	{
#ifndef NDEBUG
	  fprintf(stderr, "could not set ip6->hlim, errno %d\n", errno);
#endif
	  return errno;
	}

      ipmp = (struct ipmp *)buf;
      ipmp_trailer = (struct ipmp_trailer *)(buf + er->len - 4);
    }
  else return EINVAL;

  /* get the offsets into the packet to be constructed */
  bzero(ipmp, er->len);

  /* fill out the ipmp header */
  ipmp->faux_srcport = 0;
  ipmp->faux_dstport = 0;
  ipmp->version      = 1;
  ipmp->faux_proto   = IPPROTO_TCP;
  ipmp->options      = IPMP_ECHO | IPMP_REQUEST;
  ipmp->reserved     = 0;
  ipmp->id           = er->id;
  ipmp->seq          = er->seq;
  ipmp_trailer->path_pointer = htons(pp);
  ipmp_trailer->checksum     = 0;

  /* fill out the first path record */
  gettimeofday(&tv, &tz);
  if(er->dst->sa_family == AF_INET)
    {
      pr = (struct ipmp_pathrecord *)(buf
				      + sizeof(struct ipmp) 
				      + sizeof(struct ip));

      if(er->src != NULL)
	{
	  sin4 = (struct sockaddr_in *)er->src;
	  pr->ip.s_addr = sin4->sin_addr.s_addr;
	}
      else pr->ip.s_addr = htonl(0x7f000001);

      pr->ttl   = er->ttl;
      pr->flowc = 0x80;
      pr->sec   = htons(tv.tv_sec & 0xffff);
      pr->nsec  = htonl(tv.tv_usec * 1000);

      pr++;
      pr_len = 12;
      i = ((int)((u_int8_t *)ipmp_trailer - (u_int8_t *)pr) / 12);

      while(i-- > 0)
	{
	  pr->ttl = er->ttl;
	  pr++;
	}
    }
  else
    {
      pr6 = (struct ipmp_pathrecord6 *)(buf + sizeof(struct ipmp));
      pr6->hlim             = er->ttl;
      pr6->flowc            = 0x80;
      pr6->ip.s6_addr32[0]  = htonl(0x00000000);
      pr6->ip.s6_addr32[1]  = htonl(0x00000000);
      pr6->ip.s6_addr32[2]  = htonl(0x00000000);
      pr6->ip.s6_addr32[3]  = htonl(0x00000001);
      pr6->sec              = htons(tv.tv_sec & 0xffff);
      pr6->nsec             = htonl(tv.tv_usec * 1000);

      pr6++;
      while((void*)pr6 < (void*)(ipmp_trailer-sizeof(struct ipmp_pathrecord6)))
	{
	  pr6->hlim = er->ttl;
	  pr6++;
	}
    }

  /* compute the checksum over the completed echo request packet */
  ipmp_trailer->checksum = in_cksum((u_short *)ipmp, er->len);

  /* send the ipmp request */
  if(sendto(sock, buf, len, 0, er->dst, sa_len) == -1)
    {
#ifndef NDEBUG
      fprintf(stderr, "sendto returns %d\n", errno);
#endif
      return errno;
    }
  return 0;
}

char *gai_strerror_wrap(int ecode)
{
  return (char *)gai_strerror(ecode);
}

static mjl_array_t *dnsentry_array;

int dnsentry_cmp(const void **a, const void **b)
{
  struct dns_entry *da, *db;

  if(a == NULL || *a == NULL || b == NULL || *b == NULL) return 0;

  da = (struct dns_entry *)*a;
  db = (struct dns_entry *)*b;

  return sockaddr_cmp((const void **)&da->addr, (const void **)&db->addr);
}

struct dns_entry *dnsentry_lookup6(struct in6_addr *addr)
{
  struct dns_entry  findme;
  struct sockaddr  *sa;
  struct dns_entry *ret;
  char              name[NI_MAXHOST];
  socklen_t         sa_len;

  sa = sockaddr_create(AF_INET6, addr);
  findme.addr = sa;

  ret = array_find(dnsentry_array, &findme);
  if(ret == NULL)
    {
      ret = (struct dns_entry *)malloc(sizeof(struct dns_entry));
      if(ret == NULL) return NULL;

      sa_len = sizeof(struct sockaddr_in6);

      if(getnameinfo(sa, sa_len, name, sizeof(name), NULL, 0, 0) != 0)
	{
	  free(sa);
	  return NULL;
	}

      ret->addr = sa;
      ret->name = strdup(name);

      array_insert(dnsentry_array, ret);
      array_quicksort(dnsentry_array);
    }
  else
    {
      free(sa);
    }

  return ret;
}

struct dns_entry *dnsentry_lookup4(struct in_addr *addr)
{
  struct dns_entry  findme;
  struct sockaddr  *sa;
  struct dns_entry *ret;
  char              name[NI_MAXHOST];
  socklen_t         sa_len;

  sa = sockaddr_create(AF_INET, addr);
  findme.addr = sa;
  
  ret = array_find(dnsentry_array, &findme);
  if(ret == NULL)
    {
      ret = (struct dns_entry *)malloc(sizeof(struct dns_entry));
      if(ret == NULL) return NULL;

      sa_len = sizeof(struct sockaddr_in);

      if(getnameinfo(sa, sa_len, name, sizeof(name), NULL, 0, 0) != 0)
	{
	  free(sa);
	  return NULL;
	}

      ret->addr = sa;
      ret->name = strdup(name);

      array_insert(dnsentry_array, ret);
      array_quicksort(dnsentry_array);
    }
  else
    {
      free(sa);
    }

  return ret;
}

int dnsentry_init()
{
  dnsentry_array = array_create(10, dnsentry_cmp);
  if(dnsentry_array == NULL) return 0;
  return 1;
}

void dnsentry_free(void *ptr)
{
  struct dns_entry *dns;

  if(ptr == NULL) return;

  dns = (struct dns_entry *)ptr;
  free(dns->addr);
  free(dns->name);
  free(dns);

  return;
}

void dnsentry_close()
{
  if(dnsentry_cmp != NULL)
    {
      array_destroy(dnsentry_array, dnsentry_free);
      dnsentry_array = NULL;
    }
  return;
}
