#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>
#include <curses.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/uio.h>

#if defined(__FreeBSD__)
#include <sys/module.h>
#endif

#if defined(__NetBSD__)
#include <sys/lkm.h>
#endif

#if defined(__linux__)
#include <linux/unistd.h>
#include <linux/sysctl.h>
#include <time.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <netinet/ipmp.h>
#include <netinet/ipmp_var.h>
#endif

#if defined(__linux__)
#include "ipmp.h"
#endif

#include <assert.h>

#include "mjl_ipmp_util.h"
#include "mjl_array.h"

#define OPT_MAXSIZE   0x000001 /* -s (maximum sized packet to send) */
#define OPT_IPV4      0x000002 /* -4 (force IPv4) */
#define OPT_IPV6      0x000004 /* -6 (force IPv6) */
#define OPT_DUMP      0x000008 /* -d (dump the raw data to a file */
#define OPT_RAW       0x000010 /* -R (use a RAW socket to send the echo) */
#define OPT_RESOLV    0x000020 /* -N (resolve the IP addresses to a name) */
#define OPT_INBETWEEN 0x000040 /* -i (how long to wait between sending pair) */

struct probe
{
  int                     size;
  u_int16_t               seq;
  int                     records;
  struct ipmp_pathrecord *pr;
};

enum ips_state
{
  IPS_PMTU,
  IPS_PROBE,
  IPS_LAYER2
};

struct segment
{
  void        *from;
  void        *to;
  char        *name;
  int          hops;
  int32_t     *samples;
  int          sample_count;
  int32_t      kbps;
  int32_t      min, max, avg;
};

struct ipmp_path
{
  struct segment **segments;
  int              len;
};

static u_int32_t         options;
static char             *target;
static struct sockaddr  *addr;
static int               ipmp_sock  = -1, icmp_sock  = -1;
static int               ipmp_sock6 = -1, icmp_sock6 = -1;
static int               ipv4_ttl, ipv6_hlim;
static int               in, in_ref = 0, ipmp_ref = 0;
static u_int16_t         pid;
static WINDOW           *window = NULL;
static int               tx = 0, rx = 0;
static int               finish_up = 0;
static enum ips_state    ips  = IPS_PMTU;
static int               minsize = 0, maxsize = 0;
static struct ipmp_path *paths = NULL, *current_path = NULL;
static int               path_count = 0;
static mjl_array_t      *segment_array;
static struct probe     *probe_pair[2];
static int               in_between = 1000;

#if defined(__FreeBSD__)
static int syscall_num;
#endif

/*
 * print a diagnostic error message to stdout, unless the -n option is in use:
 * then we print ERR and leave it at that.  if a user wants more info than
 * ERR they should run ipmp_ping without the -n flag and see what is causing
 * the error to occur
 */
static void printerror(int ecode, char *(*error_itoa)(int), char *format, ...)
{
  char     message[512];
  char    *error_str = NULL;
  va_list  ap;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);
  
  if(error_itoa != NULL)
    {
      error_str = error_itoa(ecode);
    }

  if(error_str != NULL) fprintf(stderr, "%s: %s\n", message, error_str);
  else                  fprintf(stderr, "%s\n", message);

  return;
}

static void printerrorw(int ecode, char *(*error_itoa)(int), char *format, ...)
{
  int      row, col;
  char     buf[512];
  char     message[512];
  char    *error_str = NULL;
  va_list  ap;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);
  
  if(error_itoa != NULL)
    error_str = error_itoa(ecode);

  if(error_str != NULL)
    snprintf(buf, sizeof(buf), "%s: %s\n", message, error_str);
  else
    snprintf(buf, sizeof(buf), "%s\n", message);

  /* information wants to be wide */
  getmaxyx(stdscr, row, col);

  attron(A_REVERSE);
  mvprintw(row-1, 0, buf);
  hline(' ', col-strlen(buf));
  attroff(A_REVERSE);

  refresh();

  return;
}

/*
 * if we get alarm bells, we have been told to finish up as fast as we
 * can.  the main loop is looping while(finish_up == 0).  the alarm bells
 * can be rung either by an alarm() or a ctrl-c
 */
static void alarm_bells(int sig)
{
  finish_up = 1;
  return;
}

static int resolve_address()
{
  struct addrinfo    hints, *res, *res0;
  int                error;

  bzero(&hints, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_IPMP;

  if(options & OPT_IPV4)      hints.ai_family = PF_INET;
  else if(options & OPT_IPV6) hints.ai_family = PF_INET6;
  else                        hints.ai_family = PF_UNSPEC;

  error = getaddrinfo(target, NULL, &hints, &res0);
  if(error != 0)
    {
      hints.ai_flags = AI_CANONNAME;
      error = getaddrinfo(target, NULL, &hints, &res0);
    }

  if(error != 0 || res0 == NULL)
    {
      printerror(error, gai_strerror_wrap, "Could not resolve %s", target);
      return 0;
    }

  res = res0;

  /*
   * scan for the first usable address if PF_UNSPEC was used
   */
  if(hints.ai_family == PF_UNSPEC)
    {
      while(res != NULL)
	{
	  if(res->ai_family == PF_INET || res->ai_family == PF_INET6) break;
	  res = res->ai_next;
	}
      if(res == NULL)
	{
	  freeaddrinfo(res0);
	  return 0;
	}
    }

  addr = malloc(res->ai_addrlen);
  bcopy(res->ai_addr, addr, res->ai_addrlen);

  freeaddrinfo(res0);

  return 1;
}

static void cleanup()
{
  if(window != NULL)
    {
      curs_set(1);
      endwin();
      window = NULL;
    }

  if(ipmp_sock != -1)
    {
      shutdown(ipmp_sock, 2);
      ipmp_sock = -1;
    }

  if(ipmp_sock6 != -1)
    {
      shutdown(ipmp_sock6, 2);
      ipmp_sock6 = -1;
    }

  if(icmp_sock != -1)
    {
      shutdown(icmp_sock, 2);
      icmp_sock = -1;
    }

  if(icmp_sock6 != -1)
    {
      shutdown(icmp_sock6, 2);
      icmp_sock6 = -1;
    }

  dnsentry_close();

  return;
}

static void usage_str(char c, char *str)
{
  fprintf(stderr, "   -%c %s\n", c, str);
  return;
}

static void usage(u_int32_t option)
{
  fprintf(stderr,
	  "usage: ipmp_pathchar [-?46diNRs] [-i in between] [-s size] host\n");

  if(option == 0) return;

  fprintf(stderr, "\n");

  if(option & OPT_IPV4)
    usage_str('4', "force encapsulation in an IPv4 header");

  if(option & OPT_IPV6)
    usage_str('6', "force encapsulation in an IPv6 header");

  if(option & OPT_DUMP)
    usage_str('d', "dump the instantaneous bandwidths measured");

  if(option & OPT_INBETWEEN)
    usage_str('i', "how long to wait in between sending a 'pair'");

  if(option & OPT_RESOLV)
    usage_str('N', "resolve IP addresses to names");

  if(option & OPT_RAW)
    usage_str('R', "use raw socket to send echo request packets");

  if(option & OPT_RAW)
    usage_str('s', "size of the maximum sized packet to send");

  fprintf(stderr, "\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;

  if(argc == 1)
    {
      usage(0);
      return 0;
    }

  while((ch = getopt(argc,argv,"46di:NRs:?")) != -1)
    {
      switch(ch)
	{
	case '4':
	  options |= OPT_IPV4;
	  break;
	  
	case '6':
	  options |= OPT_IPV6;
	  break;

	case 'd':
	  options |= OPT_DUMP;
	  break;

	case 'i':
	  options |= OPT_INBETWEEN;
	  in_between = atoi(optarg);
	  break;

	case 'N':
	  options |= OPT_RESOLV;
	  break;

	case 'R':
	  options |= OPT_RAW;
	  break;

	case 's':
	  options |= OPT_MAXSIZE;
	  maxsize = atoi(optarg);
	  break;

	case '?':
          usage(0xffffffff);
          return 0;
	}
    }

  if(argc - optind != 1)
    {
      usage(0);
      return 0;
    }

  target = argv[optind];

  if(options & OPT_IPV4 && options & OPT_IPV6)
    {
      usage(OPT_IPV4 | OPT_IPV6);
      fprintf(stderr, "Cannot force only-IPv4 and only-IPv6\n");
      return 0;
    }

  //if(maxsize <= 52 || ((maxsize % 4) != 0))
  //  {
  //    usage(OPT_MAXSIZE);
  //    return 0;
  //  }

  if(in_between < 100)
    {
      usage(OPT_INBETWEEN);
      return 0;
    }

  return 1;
}

static int open_sockets4()
{
#if defined(__FreeBSD__)
  int    mib[]  = {CTL_NET, PF_INET, IPPROTO_IP, IPCTL_DEFTTL};
  u_int  miblen = 4;
  size_t len    = sizeof(ipv4_ttl);
#elif defined(__linux__)
  int    mib[]  = {CTL_NET, NET_IPV4, NET_IPV4_DEFAULT_TTL};
  u_int  miblen = 3;
  size_t len    = sizeof(ipv4_ttl);
#endif

  ipmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_IPMP);
  if(ipmp_sock == -1)
    {
      printerror(errno, strerror, "could not open IPMP IPv4 raw socket");
      return 0;
    }

/* This gives Flo an SIGBUS error. Hardcode the linux default instead. */
ipv4_ttl = 64;

// #if defined(__NetBSD__)
//   ipv4_ttl = 255;
// #else
//   if(sysctl(mib, miblen, &ipv4_ttl, &len, NULL, 0) == -1)
//     {
//       printerror(errno, strerror, "could not find out default ipv4 ttl");
//       return 0;
//     }
// #endif

  icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(icmp_sock == -1)
    {
      printerror(errno, strerror, "open_sockets4: could not open ICMP socket");
      return -1;
    }

  return 1;
}

static int open_sockets6()
{
  size_t len;
  int    error;
  int    i;

#if defined(__FreeBSD__) || defined(__NetBSD__)
  int    mib[]  = {CTL_NET, PF_INET6, IPPROTO_IPV6, IPV6CTL_DEFHLIM};
  u_int  miblen = 4;
#elif defined(__linux__)
  int    mib[]  = {CTL_NET, NET_IPV6, NET_IPV6_HOP_LIMIT};
  u_int  miblen = 3;
#endif

  ipmp_sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_IPMP);
  if(ipmp_sock6 == -1)
    {
      printerror(errno, strerror, "could not open IPMP IPv6 raw socket");
      return 0;
    }

  len = sizeof(ipv6_hlim);
  if(sysctl(mib, miblen, &ipv6_hlim, &len, NULL, 0) == -1)
    {
      printerror(errno, strerror, "could not find out default ipv6 hlim");
      return 0;
    }

  len   = sizeof(ipv6_hlim);
  error = setsockopt(ipmp_sock6,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&ipv6_hlim,len);
  if(error != 0)
    {
      printerror(error, strerror, "could not set hlim on ipmp socket");
      return 0;
    }

  /* turn on the ability to read the ttl of the packet */
  i = 1;
  setsockopt(ipmp_sock6, IPPROTO_IPV6, IPV6_HOPLIMIT, &i, sizeof(i));

  return 1;
}

/*
 * send_echo_request
 *
 * the size parameter is the size of the packet to send not including the
 * encapsulating IP header
 */
static int send_echo_request(int size)
{
  struct ipmp_sendechorequest er;
  int                         error;
  static u_int16_t            seq = 0;
  int                         sock;

  if(addr->sa_family == AF_INET6)
    {
      size -= sizeof(struct ip6_hdr);
      sock = ipmp_sock6;
    }
  else if(addr->sa_family == AF_INET)
    {
      size -= sizeof(struct ip);
      sock = ipmp_sock;
    }
  else return EINVAL;

  er.len = size;
  er.id  = pid;
  er.seq = seq;
  er.src = NULL;
  er.dst = addr;
  er.ttl = -1;
  er.tos = 0;

#if defined(__FreeBSD__)

  if((options & OPT_RAW) == 0)
    error = ipmp_sendechorequest_mod(syscall_num, &er);
  else
    error = ipmp_sendechorequest_raw(sock, &er);

#elif defined(__linux__)

  if((options & OPT_RAW) == 0)
    error = ipmp_sendechorequest_ioctl(ipmp_sock, &er);
  else
    error = ipmp_sendechorequest_raw(sock, &er);

#else  

  error = ipmp_sendechorequest_raw(sock, &er);

#endif

  /*if(error == 0) tx++;*/

  return error;
}

static struct probe *recv_echo_response4()
{
  struct probe           *probe;
  u_char                  buf[8192];
  size_t                  size;
  struct sockaddr_in      from;
  socklen_t               len;
  int                     iphdrlen;
  struct ip              *ip;
  struct ipmp            *ipmp;
  int                     records;
  int                     pp;
  int                     i;

  /* try and receive something */
  size = sizeof(buf);
  len  = sizeof(from);
  size = recvfrom(ipmp_sock, buf, size, 0, (struct sockaddr *)&from, &len);
  if(size == -1)
    {
      fprintf(stderr, "recvfrom returns %d\n", (int)size);
      return NULL;
    }
  
  ip = (struct ip*)buf;
  iphdrlen = (ip->ip_hl) << 2;
#if defined(__NetBSD__)
  ip->ip_len += iphdrlen;
#elif defined(__linux__)
  ip->ip_len = ntohs(ip->ip_len);
#endif

  /* check to see if the buffer is big enough to be a valid response */
  if(size < iphdrlen + sizeof(struct ipmp))
    {
      fprintf(stderr, "size %d < iphdrlen %d + sizeof(struct ipmp)\n",
	      size, iphdrlen);
      return NULL;
    }

  if(ip->ip_p != IPPROTO_IPMP || ip->ip_len > size)
    {
      fprintf(stderr, "proto %d != IPPROTO_IPMP || ip->ip_len %d > size %d\n",
	      ip->ip_p, ip->ip_len, size);
      return NULL;
    }

  ipmp = (struct ipmp *)(buf + iphdrlen);
  if((ipmp->options & IPMP_ECHO) == 0)
    {
      fprintf(stderr, "not echo packet\n");
      return NULL;
    }

  if(ipmp->options & IPMP_REQUEST)
    {
      fprintf(stderr, "a request packet, we don't want this one\n");
      return NULL;
    }

  /*
   * Flo: Seems like the old ipmp struct had the path pointer at the
   * beginning, where the new one has it at the end.
   */
  // old: pp = ntohs(ipmp->path_pointer);
  // from ipmp_ping:
  // ipmp_trailer = (struct ipmp_trailer *)(pktbuf + ip->ip_len - 4);
  pp = ntohs(*((unsigned short*)(buf + ip->ip_len - 4)));

  if(pp + iphdrlen > size)
    {
      fprintf(stderr, "pp %d + iphdrlen %d > size %d\n", pp, iphdrlen, size);
      return NULL;
    }

  if(ipmp->id != pid)
    {
      fprintf(stderr, "ipmp->id %d != pid %d\n", ipmp->id, pid);
      return NULL;
    }

  records = (pp - sizeof(struct ipmp)) / sizeof(struct ipmp_pathrecord);
  if(records < 2)
    {
      return NULL;
    }

  probe     = malloc(sizeof(struct probe));
  i         = sizeof(struct ipmp_pathrecord) * records;

  probe->records = records;
  probe->pr      = malloc(i);
  probe->seq     = ipmp->seq;
  probe->size    = ip->ip_len;

  bcopy(buf + iphdrlen + sizeof(struct ipmp), probe->pr, i);

  for(i=0; i<records; i++)
    {
      probe->pr[i].sec  = ntohs(probe->pr[i].sec);
      probe->pr[i].nsec = ntohl(probe->pr[i].nsec);
    }

  return probe;
}

static int probe_is_same_path(struct probe *a, struct probe *b)
{
  int i;

  if(a->records != b->records)
    {
      return 0;
    }

  for(i=0; i<a->records; i++)
    {
      if(a->pr[i].ip.s_addr != b->pr[i].ip.s_addr)
	{
	  return 0;
	}
    }

  return 1;
}

static int kbps_sample_cmp(const void *a, const void *b)
{
  int32_t *ua = (int32_t *)a;
  int32_t *ub = (int32_t *)b;
  if(*ua < *ub) return -1;
  if(*ua > *ub) return  1;
  return 0;
}

#ifndef s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif

static int addr_cmp(int af, void *a, void *b)
{
  struct in_addr  *in4_a, *in4_b;
  struct in6_addr *in6_a, *in6_b;
  int              i;

  if(af == AF_INET)
    {
      in4_a = (struct in_addr *)a;
      in4_b = (struct in_addr *)b;

      if(in4_a->s_addr < in4_b->s_addr) return -1;
      if(in4_a->s_addr > in4_b->s_addr) return  1;
    }
  else if(af == AF_INET6)
    {
      in6_a = (struct in6_addr *)a;
      in6_b = (struct in6_addr *)b;

      for(i=0; i<4; i++)
        {
          if(in6_a->s6_addr32 < in6_b->s6_addr32) return -1;
          if(in6_a->s6_addr32 > in6_b->s6_addr32) return  1;
        }
    }

  return 0;
}

static int is_same_path(struct ipmp_path *path, struct probe *probe)
{
  int i;

  if(path->len +1 != probe->records)
    {
      return 0;
    }

  for(i=0; i<path->len; i++)
    {
      if(addr_cmp(AF_INET, path->segments[i]->from, &probe->pr[i].ip) != 0)
        return 0;

      if(addr_cmp(AF_INET, path->segments[i]->to,   &probe->pr[i+1].ip) != 0)
        return 0;
    }

  return 1;
}

static void pathchar_screen_pair()
{
  char buf[256];
  char addr[128];
  int  i;

  for(i=0; i<probe_pair[0]->records; i++)
    {
      inet_ntop(AF_INET, &probe_pair[0]->pr[i].ip, addr, sizeof(addr));
      snprintf(buf, sizeof(buf), "%s [%d %d] [%d %d]", addr,
	       probe_pair[0]->pr[i].sec, probe_pair[0]->pr[i].nsec,
	       probe_pair[1]->pr[i].sec, probe_pair[1]->pr[i].nsec);
      mvprintw(i + 10, 0, buf);
      hline(' ', 5);
    }

  refresh();
}

/*
 *static void pathchar_screen_probe(struct probe *probe)
 *{
 *  char buf[256];
 *  char addr[128];
 *  int i;
 *
 *  for(i=0; i<probe->records; i++)
 *    {
 *      inet_ntop(AF_INET, &probe->pr[i].ip, addr, sizeof(addr));
 *      snprintf(buf, sizeof(buf), "%s %d %d", addr, probe->pr[i].sec,
 *	       probe->pr[i].nsec);
 *      mvprintw(i + 10, 0, buf);
 *    }
 *
 *  refresh();
 *
 *  return;
 *}
 */

static void pathchar_name_segments(struct ipmp_path *path)
{
  char            from[128], to[128];
  char            name[128], fsbuf[24];
  int             i, temp;
  int             max;
  struct segment *seg;

  inet_ntop(AF_INET, path->segments[0]->from, from, sizeof(from));
  max = strlen(from);

  for(i=0; i<path->len; i++)
    {
      seg = path->segments[i];
      inet_ntop(AF_INET, seg->to, to, sizeof(to));
      temp = strlen(to);
      if(temp > max) max = temp;
    }

  snprintf(fsbuf, sizeof(fsbuf), "%%%ds -> %%%ds", max, max);

  for(i=0; i<path->len; i++)
    {
      seg = path->segments[i];
      inet_ntop(AF_INET, seg->from, from, sizeof(from));
      inet_ntop(AF_INET, seg->to,   to,   sizeof(to));

      snprintf(name, sizeof(name), fsbuf, from, to);
      if(seg->name != NULL) free(seg->name);
      seg->name = strdup(name);
    }

  return;
}

static void pathchar_screen()
{
  char            buf[256];
  int             row, col;
  int             i;
  static int      loop = 0;
  struct segment *seg;

  /* clear the screen */
  //erase();

  loop++;

  /* information wants to be wide */
  getmaxyx(stdscr, row, col);

  /* the first row is supposed to look fancy */
  attron(A_REVERSE);
  snprintf(buf, sizeof(buf),
	   "ipmp_pathchar %s: minsize %d, maxsize %d, tx/rx %d/%d, paths %d",
	   target, minsize, maxsize, tx, rx, path_count);
  buf[sizeof(buf)-1] = '\0';
  mvprintw(0, 0, buf);
  hline(' ', col-strlen(buf));
  attroff(A_REVERSE);

  /* print out accumulated statistics for each segment we know of */
  if(current_path == NULL)
    {
      mvprintw(1, 0, "nothing to report yet....");
      return;
    }

  for(i=0; i<current_path->len; i++)
    {
      seg = current_path->segments[i];

      snprintf(buf, sizeof(buf), "%s : %d kbps [min %d max %d]",
	       seg->name, seg->kbps, seg->min, seg->max);
      buf[sizeof(buf)-1] = '\0';

      mvprintw(i + 1, 0, buf);
      hline(' ', col-strlen(buf));
    }

  refresh();

  return;
}

static int ncurses_init()
{
  window = initscr();
  if(window == NULL)
    {
      fprintf(stderr, "could not initscr\n");
      return -1;
    }

  cbreak();                 /* turn off line buffering for console input */
  noecho();                 /* do not echo characters to the console     */
  nonl();                   /* do not translate the return key on input  */
  intrflush(stdscr, FALSE); /* do not flush on interrupt key press       */
  keypad(stdscr, TRUE);     /* allow the use of arrow and function keys  */
  curs_set(0);              /* do not show the cursor on the screen      */

  return 0;
}

static int segment_cmp(const void **a, const void **b)
{
  struct segment *sa, *sb;
  int             i;

  sa = (struct segment *)*a;
  sb = (struct segment *)*b;

  i = addr_cmp(AF_INET, sa->from, sb->from);
  if(i != 0) return i;
  return addr_cmp(AF_INET, sa->to, sb->to);
}

static struct ipmp_path *new_path(struct probe *probe)
{
  size_t            size;
  struct segment    findme, *seg;
  struct ipmp_path *path;
  int               i;

  /* create a new path */
  if(path_count == 0)
    {
      size  = sizeof(struct ipmp_path);
      paths = (struct ipmp_path *)malloc(size);
      if(paths == NULL)
	{
	  printerror(errno, strerror, "could not malloc initial path");
	  return NULL;
	}
      path = &paths[0];
    }
  else
    {
      size = sizeof(struct ipmp_path) * (path_count + 1);
      path = (struct ipmp_path *)realloc(paths, size);
      if(path == NULL)
	{
	  printerror(errno, strerror, "could not realloc path");
	  return NULL;
	}
      paths = path; /* reset the pointer after the realloc */
      path = &paths[path_count];
    }
      
  size           = sizeof(struct segment *) * probe->records;
  path->len      = probe->records-1;
  path->segments = (struct segment **)malloc(size);
  if(path->segments == NULL)
    {
      printerror(errno, strerror, "could not malloc path->segments");
      return NULL;
    }
  
  bzero(&findme, sizeof(findme));
  
  for(i=0; i<probe->records-1; i++)
    {
      findme.from = &probe->pr[i].ip;
      findme.to   = &probe->pr[i+1].ip;

      seg = (struct segment *)array_find(segment_array, &findme);
      if(seg == NULL)
	{
	  seg = (struct segment *)malloc(sizeof(struct segment));
	  if(seg == NULL)
	    {
	      printerror(errno, strerror, "could not malloc segment");
	      return NULL;
	    }

	  seg->from         = malloc(sizeof(struct in_addr));
	  seg->to           = malloc(sizeof(struct in_addr));
	  seg->samples      = malloc(sizeof(int32_t) * 10);
	  seg->sample_count = 0;
	  seg->kbps         = 0;
	  seg->min          = 0;
	  seg->max          = 0;
	  seg->avg          = 0;
	  seg->name         = NULL;

	  bcopy(&probe->pr[i].ip, seg->from, sizeof(struct in_addr));
	  bcopy(&probe->pr[i+1].ip, seg->to, sizeof(struct in_addr));

	  array_insert(segment_array, seg);
	  array_quicksort(segment_array);
	}

      path->segments[i] = seg;
    }

  pathchar_name_segments(path);

  path_count++;

  return path;
}

/*
 * get_path
 *
 * return a path that matches the probe, creating a new one if we can't find
 * an existing path that matches
 */
static struct ipmp_path *get_path(struct probe *probe)
{
  struct ipmp_path *path;
  int               i;
  
  /* find the path that matches this probe */
  for(i=0; i<path_count; i++)
    {
      if(is_same_path(&paths[i], probe) == 1)
	{
	  current_path = &paths[i];
	  return &paths[i];
	}
    }

  /* we did not find a path, create a new path for this probe */
  path = new_path(probe);
  if(path != NULL) current_path = path;
  return path;
}

static int64_t pr_diff(struct ipmp_pathrecord *b, struct ipmp_pathrecord *a)
{
  int64_t diff;

  diff  = (int64_t)(b->sec - a->sec) * (int64_t)1000000000;
  diff += b->nsec;
  diff -= a->nsec;

  return diff;
}

/*
 * kbps
 *
 * given two echo probes of different sizes, figure out what the bandwidth
 * seen by them is.
 *
 * this function does not work well where there is a small nsec or a large
 * size difference.
 */
static int32_t kbps(struct probe *b, struct probe *a, int i)
{
  int64_t nsec;/*, kbps;*/
  int32_t kbps;
  nsec = pr_diff(&b->pr[i], &a->pr[i]) - pr_diff(&b->pr[i-1], &a->pr[i-1]);
  kbps = (((b->size - a->size) * (int64_t)8000000) / nsec);
  return kbps;
}

/*
 * handle_packet
 *
 * this function does hardly any sanity checking - it expects that it has
 * been passed the appropriate path.
 */
static int handle_packet(struct ipmp_path *path, struct probe *probe)
{
  int             i;
  u_int32_t      *ptr;
  int32_t         temp;
  struct segment *seg;

  if(probe->size == minsize)
    {
      if(probe_pair[0] != NULL) free(probe_pair[0]);

      probe_pair[0] = probe;

      if(probe_pair[1] != NULL)
	{
	  free(probe_pair[1]);
	  probe_pair[1] = NULL;
	}
    }
  else if(probe->size == maxsize)
    {
      if(probe_pair[0] == NULL) return 0;
      probe_pair[1] = probe;

      /* if they don't belong to the same path */
      if(probe_is_same_path(probe_pair[0], probe_pair[1]) == 0)
	{
	  free(probe_pair[0]);  free(probe_pair[1]);
	  probe_pair[0] = NULL; probe_pair[1] = NULL;
	  return 1;
	}

      path = get_path(probe);

      for(i=0; i<path->len; i++)
	{
	  seg = path->segments[i];
	  
	  if((seg->sample_count) % 10 == 0)
	    {
	      qsort(seg->samples, seg->sample_count, sizeof(u_int32_t),
		    kbps_sample_cmp);

	      temp = sizeof(int32_t) * (seg->sample_count + 10);
	      ptr = realloc(seg->samples, temp);
	      if(ptr == NULL) return 0;
	      seg->samples = ptr;
	    }

	  temp = kbps(probe_pair[1], probe_pair[0], i+1);
	  seg->samples[seg->sample_count++] = temp;

	  if((temp < seg->min || seg->min == 0) && temp > 0)
	    {
	      seg->min = temp;
	    }

	  if(temp > seg->max)
	    {
	      seg->max = temp;
	    }

	  if(temp > 300000 || temp < 0)
	    {
	      pathchar_screen_pair();
	    }

	  seg->kbps = temp;
	}

      free(probe_pair[0]);  free(probe_pair[1]);
      probe_pair[0] = NULL; probe_pair[1] = NULL;
    }
  else
    {
      /* why do we have this packet? */
      fprintf(stderr, "why do i have this packet? size %d\n", probe->size);
      return 0;
    }

  return 1;
}

static int handle_probe(struct probe *probe)
{
  struct ipmp_path *path;

  if(ips == IPS_PMTU)
    {
      /*
       * find out the length of the path in path records and set our minsize
       * appropriately.
       */
      if(addr->sa_family == AF_INET)
	{
	  minsize  = sizeof(struct ipmp_pathrecord) * probe->records;
	  minsize += sizeof(struct ip) + sizeof(struct ipmp)
			+ sizeof(struct ipmp_trailer);
	}
      else if(addr->sa_family == AF_INET6)
	{
	  minsize  = sizeof(struct ipmp_pathrecord6) * probe->records;
	  minsize += sizeof(struct ip6_hdr) + sizeof(struct ipmp)
			+ sizeof(struct ipmp_trailer);
	}
      else return 0;

      /*
       * we got a packet returned, we will use this as our PMTU
       * and change into the probing state
       */
      maxsize = probe->size;
      ips     = IPS_PROBE;

      /* 
       * calling get_path will make sure that we have a path setup for when
       * we receive packets on it
       */
      get_path(probe);

      return 1;
    }
  else if(ips == IPS_PROBE)
    {
      /* find the path that matches this probe */
      path = get_path(probe);
      if(path == NULL) return 0;

      /* the path needs to handle this packet */
      handle_packet(path, probe);
      rx++;
      return 1;
    }
  else if(ips == IPS_LAYER2)
    {
    }

  return 0;
}

static int handle_icmp4()
{
  struct sockaddr     *from;
  struct sockaddr_in   from4;
  struct sockaddr_in  *sin4;
  socklen_t            fromlen;
  u_char               pktbuf[256];
  size_t               pktbuflen;
  struct icmp         *icmp;
  struct ip           *ip;
  int                  iphdrlen;

  from      = (struct sockaddr *)&from4;
  fromlen   = sizeof(from4);
  pktbuflen = recvfrom(icmp_sock, pktbuf, sizeof(pktbuf), 0, from, &fromlen);
  if(pktbuflen == -1)
    {
      return -1;
    }

  ip       = (struct ip *)pktbuf;
  iphdrlen = ip->ip_hl << 2;
  if(pktbuflen < iphdrlen + sizeof(struct icmp))
    {
      return -1;
    }

  icmp = (struct icmp *)(pktbuf + iphdrlen);
  if(icmp->icmp_type!=ICMP_UNREACH || icmp->icmp_code!=ICMP_UNREACH_NEEDFRAG)
    {
      return -1;
    }

  ip   = &icmp->icmp_ip;
  sin4 = (struct sockaddr_in *)addr;

  /* check if the packet sent was an IPMP packet to our destination */
  if(ip->ip_p != IPPROTO_IPMP || ip->ip_dst.s_addr != sin4->sin_addr.s_addr)
    {
      return -1;
    }

  /* check the validity of the MTU */
  icmp->icmp_nextmtu = ntohs(icmp->icmp_nextmtu);

  if(maxsize != 0 && icmp->icmp_nextmtu > maxsize)
    {
      return -1;
    }

  if(icmp->icmp_nextmtu < minsize)
    {
      return -1;
    }

  maxsize = icmp->icmp_nextmtu;

  return 0;
}

static void path_left()
{
  return;
}

static void path_right()
{
  return;
}

static void toggle_names()
{
  if(options & OPT_RESOLV) options |=   OPT_RESOLV;
  else                     options &= (~OPT_RESOLV);
  return;
}

static void setup_select(fd_set *rfds, int *nfds, struct timeval *tv)
{
  *nfds = 0;

  if(ipmp_sock != -1)
    {
      FD_SET(ipmp_sock, rfds);
      if(*nfds < ipmp_sock) *nfds = ipmp_sock;
    }

  if(icmp_sock != -1)
    {
      FD_SET(icmp_sock, rfds);
      if(*nfds < icmp_sock) *nfds = icmp_sock;
    }

  if(ipmp_sock6 != -1)
    {
      FD_SET(ipmp_sock6, rfds);
      if(*nfds < ipmp_sock6) *nfds = ipmp_sock6;
    }

  if(icmp_sock6 != -1)
    {
      FD_SET(icmp_sock6, rfds);
      if(*nfds < icmp_sock6) *nfds = icmp_sock6;
    }

  FD_SET(in, rfds);
  if(*nfds < in) *nfds = in;

  /* wait for half a second */
  bzero(tv, sizeof(struct timeval));
  timeval_add(tv, in_between);

  return;
}

static int dump()
{
  FILE             *file;
  char              buf[256], a[128], b[128];
  struct timeval    tv;
  struct timezone   tz;
  struct tm         tm;
  int               i, j, k;
  struct ipmp_path *path;
  struct segment   *seg;
  char             *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			 	 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

  gettimeofday(&tv, &tz);
  localtime_r(&tv.tv_sec, &tm);
  snprintf(buf, sizeof(buf), "ipmp_pathchar.%d%s%02d.%02d%02d.txt",
	   tm.tm_mday, months[tm.tm_mon], tm.tm_year % 100,
	   tm.tm_hour, tm.tm_min);
  
  file = fopen(buf, "w");
  if(file == NULL)
    {
      printerrorw(errno, strerror, "could not open %s", buf);
      return 0;
    }

  for(i=0; i<path_count; i++)
    {
      path = &paths[i];
      for(j=0; j<path->len; j++)
	{
	  seg = path->segments[j];
	  inet_ntop(AF_INET, seg->from, a, sizeof(a));
	  inet_ntop(AF_INET, seg->to,   b, sizeof(b));
	  fprintf(file, "%s -> %s\n", a, b);

	  qsort(seg->samples, seg->sample_count, sizeof(int32_t),
		kbps_sample_cmp);

	  for(k=0; k<seg->sample_count; k++)
	    {
	      fprintf(file, "%d\n", seg->samples[k]);
	    }
	}
    }

  fclose(file);

  return 1;
}

int main(int argc, char *argv[])
{
  int                   euid, ruid;
  int                   i;
  fd_set                rfds;
  int                   nfds;
  struct timeval        timeout;
  struct sigaction      si_sa;
  char                  c;
  struct probe         *probe;
  struct timeval        tv;
  struct timeval        tv_wait;
  struct timezone       tz;

  atexit(cleanup);

  euid = geteuid();
  ruid = getuid();

  /* see what options were passed to ipmp_pathchar */
  if(check_options(argc,argv) == 0)
    {
      return -1;
    }

  /* figure out where i am probing to */
  if(resolve_address() == 0)
    {
      return -1;
    }

  /* catch ctrl-c */
  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags = 0;
  si_sa.sa_handler = alarm_bells;
  if(sigaction(SIGINT, &si_sa, 0) == -1)
    {
      printerror(errno, strerror, "could not set sigaction for SIGINT");
      return -1;
    }

  /* get a file handle we can use with select() */
  in = fileno(stdin);
  if(in == -1)
    {
      printerror(0, NULL, "could not get stdin's file handle");
      return -1;
    }

  /* open the relevant sockets */
  switch(addr->sa_family)
    {
    case AF_INET:
      if(open_sockets4() == 0) return -1;
      break;

    case AF_INET6:
      if(open_sockets6() == 0) return -1;
      break;

    default:
      fprintf(stderr, "what do I do with an %08x address?", addr->sa_family);
      return -1;
    }

  /* relinquish the root priveledges, if we're not root */
  if(ruid != euid)
    {
      setreuid(ruid, ruid);
    }

  /* need to know what packets are destined for us */
  pid = getpid();

  /* need to know the addresses of the interfaces on this host */
  learn_localaddresses();

#if defined(__FreeBSD__)
  if((options & OPT_RAW) == 0)
    {
      i = get_syscall("ipmp_ping", &syscall_num);
      if(i != 0)
        {
          printerror(i, strerror, "could not get the syscall for ipmp_ping");
          return -1;
        }
    }
#endif

  /* we keep a cache of name lookups */
  if(dnsentry_init() == 0)
    {
      return -1;
    }

  /* we keep an array of network segments that are common across all paths */
  segment_array = array_create(10, segment_cmp);
  if(segment_array == NULL)
    {
      return -1;
    }

  /* init the fancy output routines */
  if(ncurses_init() == -1)
    {
      return -1;
    }

  probe_pair[0] = NULL;
  probe_pair[1] = NULL;

  pathchar_screen();

  gettimeofday(&tv_wait, &tz);

  /* probe till heart is content */
  while(finish_up == 0)
    {
      gettimeofday(&tv, &tz);

      if(timeval_diff_msec(&tv_wait, &tv) <= 0)
	{
	  /*
	   * if we are in the path MTU discovery phase then we want to keep
	   * going until we find a maximum packet size that will work
	   */
	  if(ips == IPS_PROBE)
	    {
	      i = send_echo_request(minsize);
	      if(i != 0)
		{
		  printerror(i, strerror, "send_echo_request probe");
		  return -1;
		}
	      tx++;
	    }
	  else if(ips == IPS_LAYER2)
	    {
	      i = send_echo_request(minsize);
	      if(i != 0)
		{
		  printerror(i, strerror, "send_echo_request train");
		  return -1;
		}
	    }
	  else if(ips == IPS_PMTU)
	    {
	      i = send_echo_request(maxsize);
	      if(i != 0)
		{
		  printerror(i, strerror, "send_echo_request(%d)\n", maxsize);
		  return -1;
		}
	    }

	  gettimeofday(&tv_wait, &tz);
	  timeval_add(&tv_wait, in_between);
	}

      setup_select(&rfds, &nfds, &timeout);

      if(select(nfds+1, &rfds, NULL, NULL, &timeout) > 0)
	{
	  if(in != -1 && FD_ISSET(in, &rfds))
	    {
	      read(in, &c, 1);
	      if(c == 'q' || c == 'Q') finish_up = 1;
	      else if(c == '<' || c == ',') path_left();
	      else if(c == '>' || c == '.') path_right();
	      else if(c == 'n' || c == 'N') toggle_names();
	      in_ref++;
	    }
	  
	  if(ipmp_sock != -1 && FD_ISSET(ipmp_sock, &rfds))
	    {
	      probe = recv_echo_response4();
	      if(probe != NULL)
		{
		  handle_probe(probe);
		  if(probe->size == minsize && ips == IPS_PROBE)
		    {
		      send_echo_request(maxsize);
		      tx++;
		    }
		}
	      ipmp_ref++;
	    }

	  if(icmp_sock != -1 && FD_ISSET(icmp_sock, &rfds))
	    {
	      handle_icmp4();
	    }
	}

      pathchar_screen();
    }

  if(options & OPT_DUMP) dump();

  return 0;
}
