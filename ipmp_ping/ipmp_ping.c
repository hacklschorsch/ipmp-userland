/*
 * IP Measurement Protocol (IPMP)
 * http://watt.nlanr.net/AMP/IPMP/ipmp.html
 *
 * Protocol       by Tony McGregor
 * Implementation by Matthew Luckie 2000, 2001, 2002
 *
 * Acknowledgements:
 * ping.c code by Mike Muss
 * freebsd header files for some of the definitions in ipmp_ping.h
 * fping.c code by Stanford University http://www.fping.org
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdarg.h>

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

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include "ipmp.h"
#include "ipmp_var.h"
#endif

#if defined(__linux__)
#include "ipmp.h"
#endif

#include "mjl_ipmp_util.h"

/* ipmp options from the command line */
u_int32_t options = 0;
#define OPT_AUDIBLE     0x000001 /* -a (beep the pc speaker) */
#define OPT_COUNT       0x000002 /* -c (count of packets to send) */
#define OPT_HOPS        0x000004 /* -h (print route symmetry) */
#define OPT_SIZE        0x000008 /* -s (send IPMP packets of specified size) */
#define OPT_TIMEOUT     0x000010 /* -t (only run for t sec) */
#define OPT_RTT         0x000020 /* -r (print rtt of the trip) */
#define OPT_NLANR       0x000040 /* -n (print stuff for amp purposes) */
#define OPT_IPV4        0x000080 /* -4 (force IPv4) */
#define OPT_IPV6        0x000100 /* -6 (force IPv6) */
#define OPT_RAW         0x000200 /* -R (use a RAW socket to send the echo) */
#define OPT_SRCADDR     0x000400 /* -S (use the specified source address) */
#define OPT_WAITBETWEEN 0x000800 /* -w (time to wait between packets) */
#define OPT_RESOLV      0x001000 /* -N (resolve the IP addresses to a name) */
#define OPT_DEBUG       0x002000 /* -d (debug options) */
#define OPT_PRECISION   0x004000 /* -p (precision to print the rtt with) */
#define OPT_TONY        0x008000 /* -A (tony's option) */
#define OPT_PROBE       0x010000 /* -P (probe one way) */
#define OPT_TOS         0x020000 /* -T (type of service bits) */

#define IPMP_ECHOOFFSET (sizeof(struct ipmp))

#define IPMP_PATHOFFSET (sizeof(struct ipmp) + sizeof(struct ipmp_echo))

/*
 * the host_entry struct stores per-host information regarding the packets
 * sent.  it is a doubly-linked list arrangement, so that as packets are
 * received, it can advance to the necessary host_entry
 */
struct host_entry
{
  struct host_entry      *next;               /* linked list */
  int                     i;                  /* index into array */
  char                   *name;               /* name as given by user */
  char                   *dns_name;           /* resolved name */
  char                   *printed;            /* the name to print out */
  struct sockaddr        *addr;
  int                     timeout;            /* time to wait for response   */
  int                     tx;                 /* how many tx'd packets       */
  int                     rx;                 /* how many rx'd packets       */
  int32_t                 ttl;                /* the ttl returned by recvmsg */
};

/*
 * the socket(s) used to send request(s) and receive response(s) from the
 * network;
 */
static int ipmp_sock  = -1;
static int ipmp_sock6 = -1;
static int icmp_sock  = -1;
static int icmp_sock6 = -1;


/*
 * the 16bit process idenification number.  this number is stored so that
 * packets received can be matched with this instance of the ping program
 */
static u_int16_t pid;

/*
 * head points to the first host entry and is useful when you have to scan
 * the whole list
 * cursor points to the last referenced host entry and is useful for randomly
 * navigating the list
 */
static struct host_entry *head;

#if defined(__FreeBSD__)
/*
 * syscall_num is used in the BSD version to remember the syscall to call,
 * which is particularly useful if we are sending more than just one ipmp
 * echo request packet
 */
static int syscall_num;
#endif

/*
 * filename points to a file that is specified on the command line.  filename
 * is either the host-list-file (specified with the -n option) or the
 * packet-file (specified with the -p option)
 */
static char *filename;

/*
 * timeout is how long we should keep this program running.  it is used when
 * a SIG alarm is set and is specified with the -t option
 */
static u_int32_t timeout = 0;

/*
 * finish up is a global variable used to tell the program to stop running as
 * soon as possible.  finish up is set either in response to an alarm or a
 * SIGINT
 */
static int finish_up;

/*
 * The size value must be a multiple of four bytes.
 * by default, packetsize is the IPv4 size (52 bytes)
 */
static int packetsize = 0;

/*
 * number of ipmp measurements to send to each host
 */
static int count = 1;

/*
 * amount of time to wait between sending any two ipmp packets (in msec)
 * the default is 25 msec
 */
static int            wait_between    = 25;
static struct timeval wait_between_tv;

/*
 * this is here because gettimeofday insists i provide a timezone pointer
 * even though i don't care what the timezone is
 */
static struct timezone tz;  

/*
 * sent_all_requests
 * flag to say if all the echo requests have been sent
 */
static int sent_all_requests;  

/*
 * source
 * if set, we should use the specified address as the packet's source
 * address
 */
static struct sockaddr *source     = NULL;
static char            *source_str = NULL;

/*
 * an array of pointers that point to the end-host a sequence number was
 * used for
 */
static struct host_entry *sequences[65535];

/*
 * precision
 */
static int precision = 0;

/*
 * the relevant ttl values for v4 and v6 sockets
 */
static int ipv4_ttl;
static int ipv6_hlim;

/*
 * the type of service bits
 * note that we check that 0 <= tos <= 255
 */
static long tos;

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

/*
 * if we get alarm bells, we have been told to finish up as fast as we
 * can.  the main loop is looping while(finish_up == 0).  the alarm bells
 * can be rung either by an alarm() or a ctrl-c
 */
static void alarm_bells(int sig)
{
  finish_up = 1;
}

/*
 * get_timeout
 * returns the amount of time that select should block for before returning
 * whether some packets have arrived or not
 */
static int get_timeout(struct timeval *tv)
{
  struct timeval  temp;
  int64_t         min_diff = 1000, temp_diff;

  if(tv == NULL)
    {
      return 0;
    }

  bzero(&temp, sizeof(temp));
  bzero(&tz,   sizeof(tz));
  if(gettimeofday(&temp, &tz) != 0)
    {
      printerror(errno, strerror, "could not gettimeofday");
      return 0;
    }

  if(wait_between > 0)
    {
      temp_diff = timeval_diff_msec(&wait_between_tv, &temp);
      if(temp_diff >= 0 && temp_diff < min_diff) min_diff = temp_diff;
    }

  tv->tv_sec  = 0;
  tv->tv_usec = 0;
  timeval_add(tv, min_diff);

  return 1;
}

/*
 * got_all_responses
 * returns true if all packets sent have responses associated with them
 */
static int got_all_responses()
{
  struct host_entry *current;

  /*
   * if there are no host_entrys, tell the caller we have got all responses
   * because there are no more to expect (because we didnt send anything)
   */
  if(head == NULL) return 1;

  /*
   * loop through all the host_entrys, checking to see if any of them do not
   * have response packets associated with 
   */
  current = head;
  while(current != NULL)
    {
      if(current->tx < count || current->rx < current->tx) return 0;
      /*if(current->packet == NULL) return 0;*/
      current = current->next;
    }

  /* if we get here, we must have recevied a response for every request sent */
  return 1;
}

/*
 * show_loss goes through all of the hosts and prints out the host names that
 * do not have a response packet associated with them
 */
static void show_loss()
{
  struct host_entry *current;
  int                i;

  if(head == NULL) return;

  current = head;
  while(current != NULL)
    {
      if(current->rx < current->tx)
	{
	  for(i=current->rx; i<current->tx; i++)
	    {
	      printf("%s loss\n", current->name);
	    }
	}

      current = current->next;
    }

  return; 
}

/*
 * copy_buffer is the same as copy_string, except that because it's binary
 * data the length of the buffer must be known first
 */
static u_char *copy_buffer(u_char *buf, int buf_size)
{
  u_char *copy;
  if(buf == NULL || buf_size < 1) return NULL;
  copy = malloc(buf_size);
  bcopy(buf,copy,buf_size);
  return copy;
}

/*
 * rtt()
 * this is the fixed? version of rtt that does all its work in nanoseconds
 * because of this, it is necessary to work with int64's so that we have
 * adequate space to store trillions of nanoseconds
 */
static char *rtt_reliable(struct ipmptime *start, struct ipmptime *finish)
{
  int64_t nano;
  int32_t milli, remainder;
  static char rtt[128];

  /*
   * work out how much the seconds have changed by, and convert that to a 
   * nanosecond representation
   */
  nano  = (finish->sec  - start->sec) * (int64_t)1000000000;
  nano += finish->nsec;
  nano -= start->nsec;

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

static char *rtt(struct ipmptime *start, struct ipmptime *finish)
{
  u_int64_t   nano;
  u_int32_t   milli, remainder;
  static char rtt[128];

  /*
   * work out how much the seconds have changed by, and convert that to a 
   * nanosecond representation
   */
  nano  = (finish->sec  - start->sec) * (int64_t)1000000000;
  nano += finish->nsec;
  nano -= start->nsec;

  milli     = (int32_t)(nano / 1000000);
  remainder = (int32_t)(nano % 1000000);

  if(precision == 0)
    {
      if(remainder > 500000) milli++;
      sprintf(rtt, "%d", milli);
    }
  else
    {
      char      fs_buf[16];
      u_int32_t digits = 0;
      int       pc[5][2] = {{100000,     9},
                            { 10000,    99},
                            {  1000,   999},
                            {   100,  9999},
                            {    10, 99999}};

      if(precision <= 5)
        {
	  digits = remainder / pc[precision-1][0];
	  if(remainder % pc[precision-1][0] > pc[precision-1][0]/2)
	    {
	      digits++;
	      if(digits > pc[precision-1][1])
		{
		  milli++;
		  digits = 0;
		}
	    }
        }
      else
        {
          digits = remainder;
        }

      sprintf(fs_buf, "%%d.%%0%dd", precision);
      sprintf(rtt, fs_buf, milli, digits);
    }

  return rtt;
}

/*
 * this is the freebsd version of send_echo_request
 * it uses the syscall that is loaded into the kernel so that a kernel
 * timestamp can be applied on the way out.
 */
static int send_echo_request(struct host_entry *he)
{
  struct ipmp_sendechorequest er;
  char                        addr[256];
  int                         error;
  static u_int16_t            seq = 0;
  int                         sock;

  if(he->addr->sa_family == AF_INET6)
    {
      sock = ipmp_sock6;

      inet_ntop(AF_INET6,
		&((struct sockaddr_in6 *)he->addr)->sin6_addr,
		addr, sizeof(addr));

      er.ttl = ipv6_hlim;

      if(packetsize > 88) er.len = packetsize;
      else                er.len = 88;
    }
  else if(he->addr->sa_family == AF_INET)
    {
      sock = ipmp_sock;

      inet_ntop(AF_INET,
		&((struct sockaddr_in *)he->addr)->sin_addr,
		addr, sizeof(addr));

      er.ttl = ipv4_ttl;

      if(packetsize > 52) er.len = packetsize;
      else                er.len = 52;
    }
  else return EINVAL;

  if(he->tx == 0 && (options & OPT_NLANR) == 0)
    {
      printf("ipmp_ping %s (%s)...\n", he->printed, addr);
    }

  /*
   * form the packet id, and call the syscall that sends the echo request
   * packet.  if we fail, print out a diagnostic message
   *
   * note that there is a field in the args that records the timestamp that
   * is inserted into the echo request packet as the 'out' timestamp
   */
  er.id  = pid;
  er.seq = seq;
  er.src = source;
  er.dst = he->addr;
  er.tos = tos;

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

  /*
   * if we couldn't actually send a packet due to not having a route
   * we need to still pretend we had rather than stop the program.
   */
  if((error == EHOSTUNREACH) && (options & OPT_NLANR))
    {
      seq++;
      return 0;
    }

  if(error != 0)
    {
      printerror(error, strerror, "Could not ipmp_ping(%s,%d)", addr, er.len);
      return error;
    }

  sequences[seq++] = he;

  return 0;
}

static struct host_entry *recv_echo_response4(char **packet, int *len)
{
  u_char               pktbuf[2048];
  size_t               pktbuflen;
  struct sockaddr_in   from;
  socklen_t            l;
  struct host_entry   *host_entry;
  int                  iphdrlen;
  struct ip           *ip;
  struct ipmp         *ipmp;
  struct ipmp_trailer *ipmp_trailer;
  int                  pp;
  u_short              cksum;

  /* try and receive something */
  pktbuflen = sizeof(pktbuf);
  l         = sizeof(from);

  pktbuflen=recvfrom(ipmp_sock,pktbuf,pktbuflen,0,(struct sockaddr *)&from,&l);
  if(pktbuflen == -1)
    {
      printf("recvfrom returns -1\n");
      return NULL;
    }

  /* convert no of 32bit words into no of bytes */
  ip       = (struct ip *)(pktbuf);
  iphdrlen = ip->ip_hl << 2;
 
  /* check to see if the buffer is big enough to be a valid response */
  if(pktbuflen < iphdrlen + sizeof(struct ipmp))
    {
      printf("pktbuflen %u < needed size\n", (unsigned int)pktbuflen);
      return NULL;
    }

#if defined(__NetBSD__)
  ip->ip_len += iphdrlen;
#elif defined(__linux__)
  ip->ip_len = ntohs(ip->ip_len);
#endif

  /* check that the IPMP packet is one that we want */
  ipmp = (struct ipmp *)(pktbuf + iphdrlen);
  if(ipmp->id != pid)
    {
      printf("not for us, %d != %d\n", ipmp->id, pid);
      return NULL;
    }

  if(ipmp->options & IPMP_ECHO)
    {
      if(ipmp->options & IPMP_REQUEST)
        {
          printf("not echo response, %x\n", ipmp->options);
          return NULL;
        }
    }

  ipmp_trailer = (struct ipmp_trailer *)(pktbuf + ip->ip_len - 4);

  if((cksum = in_cksum((u_short*)ipmp, pktbuflen - iphdrlen)) != 0)
    {
      cksum = ipmp_trailer->checksum;
      ipmp_trailer->checksum = 0;
      ipmp_trailer->checksum = in_cksum((u_short*)ipmp, pktbuflen - iphdrlen);
      printf("received 0x%04x expected 0x%04x\n",cksum,ipmp_trailer->checksum);
    }

  pp = ntohs(ipmp_trailer->path_pointer);
  if(pp > pktbuflen - iphdrlen) 
    {
      printf("pp %d > size %d\n", (unsigned int)pp,
		(unsigned int)(pktbuflen - iphdrlen));
      return 0;
    }

  /* if we can't find an entry, it is bogus */
  host_entry = sequences[ipmp->seq];
  if(host_entry == NULL)
    {
      printf("could not find host entry for this sequence\n");
      return NULL;
    }

  /* if there is already a packet for this one, it is a dupe */
  if(host_entry->rx == host_entry->tx)
    {
      printf("already have response\n");
      return NULL;
    }

  host_entry->rx++;
  host_entry->ttl = ip->ip_ttl;
  sequences[ipmp->seq] = NULL;

  *len = pktbuflen - iphdrlen;
  *packet = copy_buffer(pktbuf+iphdrlen, *len);

  return host_entry;
}

static struct host_entry *recv_echo_response6(char **packet, int *len)
{
  u_char               buf[1024];
  u_char               pktbuf[2048];
  size_t               pktbuflen;
  struct sockaddr_in6  from;
  struct host_entry   *host_entry;
  struct msghdr        msg;
  struct cmsghdr      *cmsg;
  struct iovec         iov[2];
  struct ipmp         *ipmp;
  struct ipmp_trailer *ipmp_trailer;
  int                  pp;

  bzero(&iov, sizeof(iov));
  iov[0].iov_base = (caddr_t)pktbuf;
  iov[0].iov_len  = sizeof(pktbuf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)buf;
  msg.msg_controllen = sizeof(buf);

  pktbuflen = recvmsg(ipmp_sock6, &msg, 0);
  if(pktbuflen == -1)
    {
      return NULL;
    }

  if(pktbuflen < sizeof(struct ipmp))
    {
      return 0;
    }

  /* check that the IPMP packet is one that we want */
  ipmp = (struct ipmp *)(pktbuf);
  if((ipmp->options & IPMP_ECHO) && (ipmp->options & IPMP_REQUEST) == 1)
    {
      return 0;
    }

  ipmp_trailer = (struct ipmp_trailer *)(pktbuf + pktbuflen - 4);

  pp = ntohs(ipmp_trailer->path_pointer);
  if(pp > pktbuflen) 
    {
#ifndef NDEBUG
      fprintf(stderr,"pp %d > pktbuflen %d\n", (unsigned int)pp, (unsigned int)pktbuflen);
#endif
      return 0;
    }

  if(ipmp->id != pid)
    {
      return NULL;
    }

  /* if we can't find an entry, it is bogus */
  host_entry = sequences[ipmp->seq];
  if(host_entry == NULL) return NULL;

  if(host_entry->rx == host_entry->tx)
    {
      return NULL;
    }

  /* associate the packet received with the appropriate host */
  *len    = pktbuflen;
  *packet = copy_buffer(pktbuf, pktbuflen);
  host_entry->rx++;

  sequences[ipmp->seq] = NULL;

  cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
  while(cmsg != NULL)
    {
      if(cmsg->cmsg_level == IPPROTO_IPV6)
	{
	  if(cmsg->cmsg_type == IPV6_HOPLIMIT)
	    {
	      bcopy(CMSG_DATA(cmsg),&host_entry->ttl,sizeof(host_entry->ttl));
	    }
	}
      cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
    }

  return host_entry;
}

static int parse_echo_response6(struct host_entry *host_entry, char *packet, int len)
{
  int                      records, i;
  struct ipmp             *ipmp;
  struct ipmp_trailer     *ipmp_trailer;
  struct ipmp_pathrecord6 *pr;
  char                     ctime_buf[26];
  char                     addr_buf[INET6_ADDRSTRLEN];
  char                     fs_buf[25];
  struct ipmp_pathrecord6 *out = NULL, *there = NULL, *back = NULL;
  int                      temp, max;
  struct dns_entry        *dns;
  struct ipmptime          t, t2; 
  long                     base_sec = tv_sec() & 0xffff0000;  
  time_t                   tt;
  char                    *name;
  char                     c;
  struct in6_addr         *in6;

  /* get the offsets into the packet received */
  ipmp = (struct ipmp *)packet;
  pr   = (struct ipmp_pathrecord6 *)(packet + sizeof(struct ipmp)); 

  ipmp_trailer = (struct ipmp_trailer *)(packet + len - 4);
  ipmp_trailer->path_pointer = ntohs(ipmp_trailer->path_pointer);

  /* get the number of path records */
  records = (ipmp_trailer->path_pointer - sizeof(struct ipmp))
	     / sizeof(struct ipmp_pathrecord6);

  /* get a pointer to the first timestamp so we can do a rtt calculation */
  if(is_localaddress6(&pr->ip)) out = pr;

  /* find out how many chars it is to represent the longest address */
  if(!(options & OPT_NLANR))
    {
      if(records <= 0) return 1;

      max = 0;
      for(i=0; i<records; i++)
	{
	  if(options & OPT_RESOLV && (dns=dnsentry_lookup6(&pr->ip)) != NULL)
	    {
	      temp = strlen(dns->name);
	    }
	  else
	    {
	      inet_ntop(AF_INET6, &pr->ip, addr_buf, sizeof(addr_buf));
	      temp = strlen(addr_buf);
	    }

	  if(temp > max) max = temp;
	  pr++;
	}

      pr--;
      temp = ipv6_hlim - pr->hlim; 
      if(temp < 9)       i = 1;
      else if(temp < 99) i = 2;
      else               i = 3;

      snprintf(fs_buf, sizeof(fs_buf), "%%c %%%dd  %%%ds  %%s %%9u\n", i, max);

      pr  = (struct ipmp_pathrecord6 *)(packet + sizeof(struct ipmp));
      in6 = &((struct sockaddr_in6 *)host_entry->addr)->sin6_addr;

      /* print the path records out */ 
      for(i=0; i<records; i++)
        {
          t.sec  = base_sec + ntohs(pr->sec);
          t.nsec = ntohl(pr->nsec);

          /* format the timestamp and remove the \n char from the end */
          tt = (time_t)t.sec;
	  strncpy(ctime_buf, ctime(&tt), 24); ctime_buf[24] = '\0';

          /* sort out the name we are going to show to the user */
	  if(options & OPT_RESOLV && (dns=dnsentry_lookup6(&pr->ip)) != NULL)
	    {
              name = dns->name;
	    }
	  else
	    {
	      inet_ntop(AF_INET6, &pr->ip, addr_buf, sizeof(addr_buf));
              name = addr_buf;
	    }

          /*
           * check to see if the address in this path record is either a
           * local address or a target address.  if it is, we want to show
           * the user
           */
          if(is_localaddress6(&pr->ip))
            {
              c = '*';
            }
          else if(in6addr_cmp(&pr->ip, in6) == 0)
            {
              c = '*';
              there = pr;
            }
          else c = ' ';

          printf(fs_buf, c, ipv6_hlim - pr->hlim, name, ctime_buf+4, t.nsec);
          pr++;
        }

      pr--;
      if(is_localaddress6(&pr->ip)) back = pr;

      if(options & OPT_HOPS && there != NULL)
        {
	  printf("forward path = ");
	  if(out != NULL)  printf("%d", out->hlim - there->hlim);
	  else             printf("?");
	  printf(" hops, reverse path = ");
	  if(back != NULL) printf("%d", there->hlim - back->hlim);
	  else             printf("%d", there->hlim - host_entry->ttl);
	  printf(" hops\n");
        }

      /* calculate the RTT if we have been asked to */
      if((options & OPT_RTT) && out != NULL && back != NULL)
        {
	  t.sec  = ntohs(out->sec);  t.nsec  = ntohl(out->nsec);
	  t2.sec = ntohs(back->sec); t2.nsec = ntohl(back->nsec);
	  if(t.sec > t2.sec) t2.sec += 0xffff;
	  
          printf("rtt: %sms\n", rtt(&t, &t2));
        }
      
      /* beep the pc speaker if we have been asked to */
      if(options & OPT_AUDIBLE) printf("\a");
    }
  else
    {
      /*
       * this output is the only stuff that the NLANR side (should) output to
       * stdio, thus making the perl scripts that much simpler to write
       */
      for(i=0; i<records-1; i++)
	{
	  pr++;
	}

      if(is_localaddress6(&pr->ip))
	{
	  back = pr;
	  t.sec  = out->sec;  t.nsec  = out->nsec;
	  t2.sec = back->sec; t2.nsec = back->nsec;
	  if(t.sec > t2.sec) t2.sec += 0xffff;

	  printf("%s %s\n", host_entry->name, rtt(&t, &t2));
	}
    }

  fflush(stdout);

  return 1;
}

/*
 * Function: parse_echo_response4
 * Purpose:  parses an echo response and prints out what we got back
 * Comments: we pass the host entry with the packet and associated data
 *           rather than all the 
 */
static int parse_echo_response4(struct host_entry *host_entry, char *packet, int len)
{
  int                     records, i;
  struct ipmp            *ipmp;
  struct ipmp_trailer    *ipmp_trailer;
  struct ipmp_pathrecord *pr;
  char                    ctime_buf[26];
  char                    addr_buf[17];
  char                    fs_buf[25];
  struct ipmp_pathrecord *out = NULL, *there = NULL, *back = NULL;
  int                     temp, max;
  struct dns_entry       *dns;
  struct ipmptime         t, t2; 
  long                    base_sec = tv_sec() & 0xffff0000;  
  time_t                  tt;
  char                   *name;
  char                    c;
  struct in_addr         *in;

  /* get the offsets into the packet received */
  ipmp = (struct ipmp *)(packet);
  pr   = (struct ipmp_pathrecord *)(packet + sizeof(struct ipmp));

  /* convert the echo module into host byte ordering */
  ipmp_trailer = (struct ipmp_trailer *)(packet + len - 4);
  ipmp_trailer->path_pointer = ntohs(ipmp_trailer->path_pointer);

  /* get the number of path records */
  records = (ipmp_trailer->path_pointer - sizeof(struct ipmp))
             / sizeof(struct ipmp_pathrecord);

  /* get a pointer to the first timestamp so we can do a rtt calculation */
  if(is_localaddress4(&pr->ip)) out = pr;

  /* find out how many chars it is to represent the longest address */
  if(!(options & OPT_NLANR))
    {
      max = 0;
      for(i=0; i<records; i++)
	{
	  if(options & OPT_RESOLV && (dns=dnsentry_lookup4(&pr->ip)) != NULL)
	    {
	      temp = strlen(dns->name);
	    }
	  else
	    {
	      inet_ntop(AF_INET, &pr->ip, addr_buf, sizeof(addr_buf));
	      temp = strlen(addr_buf);
	    }

	  if(temp > max) max = temp;
	  pr++;
	}

      pr--;
      temp = ipv4_ttl - pr->ttl;
      if(temp < 9)       i = 1;
      else if(temp < 99) i = 2;
      else               i = 3;

      snprintf(fs_buf, sizeof(fs_buf),
	       "%%c %%%dd  %%%ds  %%s %%9u %%x\n", i, max);

      pr = (struct ipmp_pathrecord *)(packet + sizeof(struct ipmp));
      in = &((struct sockaddr_in *)host_entry->addr)->sin_addr;

      /* print the path records out */
      for(i=0; i<records; i++)
	{
	  t.sec  = base_sec + ntohs(pr->sec);
	  t.nsec = ntohl(pr->nsec);

	  /* format the timestamp and remove the \n char from the end */
	  tt = (time_t)t.sec;
	  strncpy(ctime_buf, ctime(&tt), 24); ctime_buf[24] = '\0';

          /* sort out the name we are going to show to the user */
	  if(options & OPT_RESOLV && (dns=dnsentry_lookup4(&pr->ip)) != NULL)
	    {
              name = dns->name;
	    }
	  else
	    {
	      inet_ntop(AF_INET, &pr->ip, addr_buf, sizeof(addr_buf));
              name = addr_buf;
	    }

          /*
           * check to see if the address in this path record is either a
           * local address or a target address.  if it is, we want to show
           * the user
           */
          if(is_localaddress4(&pr->ip)) 
            {
              c = '*';
            }
	  else if(pr->ip.s_addr == in->s_addr)
	    {
	      c = '*';
	      there = pr;
	    }
          else c = ' ';

          /* actually print the path record now */
          printf(fs_buf, c, ipv4_ttl - pr->ttl, name, ctime_buf+4, t.nsec,
		 pr->flowc & 0xf);
	  pr++;
	}

      /*
       * get the corresponding last timestamp so we can work out the
       * timestamp this will only work, of course, if we are on freebsd which
       * timestamps the IPMP packets leaving and coming up the stack
       */
      pr--;
      if(is_localaddress4(&pr->ip)) back = pr;

      /* if we have been asked to calculate hops there and back, do it */
      if(options & OPT_HOPS && there != NULL)
	{
	  printf("forward path = ");
	  if(out != NULL)  printf("%d", out->ttl - there->ttl);
	  else             printf("?");
	  printf(" hops, reverse path = ");
	  if(back != NULL) printf("%d", there->ttl - back->ttl);
	  else             printf("%d", there->ttl - host_entry->ttl);
	  printf(" hops\n");
        }
      
      /* calculate the RTT if we have been asked to */
      if((options & OPT_RTT) && out != NULL && back != NULL)
	{
	  t.sec  = ntohs(out->sec);  t.nsec  = ntohl(out->nsec);
	  t2.sec = ntohs(back->sec); t2.nsec = ntohl(back->nsec);
	  if(t.sec > t2.sec) t2.sec += 0xffff;
	  
          printf("rtt: %sms\n", rtt(&t, &t2));
	}

      /* beep the pc speaker if we have been asked to */
      if(options & OPT_AUDIBLE) printf("\a");
    }
  else
    {
      /*
       * this output is the only stuff that the NLANR side (should) output to
       * stdio, thus making the perl scripts that much simpler to write
       */
      for(i=0; i<records-1; i++)
	{
	  pr++;
	}

      if(is_localaddress4(&pr->ip))
	{
	  back = pr;
	  t.sec  = out->sec;  t.nsec  = out->nsec;
	  t2.sec = back->sec; t2.nsec = back->nsec;
	  if(t.sec > t2.sec) t2.sec += 0xffff;

	  if(options & OPT_TONY)
	  {
	    printf("%s %s %d\n",host_entry->name, rtt(&t, &t2), ipmp->seq);
	  }
	  else
	  {
	    printf("%s %s\n", host_entry->name, rtt(&t, &t2));
	  }
	}
    }

  fflush(stdout);

  return 1;
}

/*
 * recv_echo_response
 * receives an echo response from somewhere
 *
 * once upon a time this was a simple function, but it became quite a bit
 * larger when the ability to ping multiple hosts in parallel was added
 */
static int recv_echo_responses()
{
  struct host_entry      *host_entry;
  fd_set                  rfds;
  int                     nfds;
  struct timeval          timeout;
  int                     responses = 0;
  char                   *packet;
  int                     len;

  /*
   * tell the socket that we want to timeout if there is nothing to receive
   * in the next second
   * i'd like to know why it's s+1
   */

  nfds = -1;
  FD_ZERO(&rfds);

  if(ipmp_sock != -1)
    {
      FD_SET(ipmp_sock, &rfds);
      if(nfds < ipmp_sock) nfds = ipmp_sock;
    }

  if(icmp_sock != -1)
    {
      FD_SET(icmp_sock, &rfds);
      if(nfds < icmp_sock) nfds = icmp_sock;
    }

  if(ipmp_sock6 != -1)
    {
      FD_SET(ipmp_sock6, &rfds);
      if(nfds < ipmp_sock6) nfds = ipmp_sock6;
    }

  get_timeout(&timeout);
  if(select(nfds+1, &rfds, NULL, NULL, &timeout) < 1)
    {
      return 0;
    }

  if(ipmp_sock != -1 && FD_ISSET(ipmp_sock, &rfds))
    {
      host_entry = recv_echo_response4(&packet, &len);
      if(host_entry != NULL)
	{
	  parse_echo_response4(host_entry, packet, len);
	  free(packet);
	  responses++;
	}
    }

  if(ipmp_sock6 != -1 && FD_ISSET(ipmp_sock6, &rfds))
    {
      host_entry = recv_echo_response6(&packet, &len);
      if(host_entry != NULL)
	{
	  parse_echo_response6(host_entry, packet, len);
	  free(packet);
	  responses++;
	}
    }

  return responses;
}

/*
 * cleanup()
 * this is used to free any resources that are allocated at the present time
 * things like mallocs and sockets
 */
static void cleanup()
{
  struct host_entry *current;

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

  while(head != NULL)
    {
      current = head->next;
      if(head->name   != NULL)   free(head->name);
      if(head->dns_name != NULL) free(head->dns_name);
      free(head);
      head = current;
    }

  if(options & OPT_RESOLV)
    {
      dnsentry_close();
    }

  return;
}

int resolve_address(char *target, struct sockaddr **addr, char **cname)
{
  struct addrinfo    hints, *res, *res0;
  int                error;

  if(target == NULL || addr == NULL) return 0;

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

  if(cname != NULL && res->ai_canonname != NULL)
    {
      *cname = strdup(res->ai_canonname);
    }
  else
    {
      *cname = NULL;
    }

  *addr = malloc(res->ai_addrlen);
  bcopy(res->ai_addr, *addr, res->ai_addrlen);

  freeaddrinfo(res0);

  return 1;
}

static struct host_entry *add_host_entry(char *target, struct host_entry *cur)
{
  struct host_entry *host_entry;
  static int         number = 0;
  struct sockaddr   *addr;
  char              *canonname;

  if(target == NULL)
    {
      return NULL;
    }

  if(resolve_address(target, &addr, &canonname) == 0)
    {
      return NULL;
    }

  host_entry = malloc(sizeof(struct host_entry));
  if(host_entry == NULL)
    {
      return NULL;
    }

  host_entry->name     = strdup(target);
  host_entry->i        = number; number++;
  host_entry->dns_name = canonname;
  host_entry->addr     = addr;
  host_entry->rx       = 0;
  host_entry->tx       = 0;
  host_entry->next     = NULL;

  /*
   * if we have resolved a DNS name associated with the IP address we print
   * that.  otherwise, we identify this host entry (to the user) with the
   * ip address supplied
   */
  if(host_entry->dns_name != NULL) host_entry->printed = host_entry->dns_name;
  else                             host_entry->printed = host_entry->name;

  /* merge this item into the linked list ... */
  if(cur != NULL) cur->next = host_entry;
  else            head      = host_entry;

  return host_entry;
}

/*
 * read_hosts_file
 * read the hosts file, resolve addresses, and put items into the main list
 * if it cannot resolve a name it fails
 */
static int read_hosts_file()
{
  FILE              *file;
  char               line[132], host[132];
  struct host_entry *cur = NULL;

  file = fopen(filename, "r");
  if(file == NULL)
    {
      printerror(errno, strerror, "could not open %s", filename);
      return 0;
    }

  /*
   * read all the items in the file and add an entry for each of them
   * in the list of hosts to be pinged
   */
  while(fgets(line,sizeof(line),file) != NULL)
    {
      line[sizeof(line)-1] = '\0';
      /* extract out the first word in the line */
      if(sscanf(line, "%s", host) != -1)
	{
	  /* see if the line is either blank or a comment */
	  if(!(host[0] == '\0' || host[0] == '#'))
	    {
	      /* if we get here, add a host entry for this name */
	      cur = add_host_entry(host, cur);
	      if(cur == NULL)
		{
		  fclose(file);
		  return 0;
		}
	    }
	}
    }

  fclose(file);
  return 1;
}

/*
 * is_valid_packetsize
 *
 * check that the size of the packet (supplied by -s packetsize) is valid
 */
static int is_valid_packetsize()
{
  if((packetsize % 4) != 0)
    {
      fprintf(stderr, "packetsize must be a multiple of 4\n");
      return 0;
    }

  if(options & OPT_IPV6)
    {
      if(packetsize < 88)
	{
	  fprintf(stderr, "packetsize must be at least 88 for IPMP/IPv6\n");
	  return 0;
	}
    }
  else if(options & OPT_IPV4)
    {
      if(packetsize < 52)
	{
	  fprintf(stderr, "packetsize must be at least 52 for IPMP/IPv4\n");
	  return 0;
	}
    }

  return 1;
}

static int source_address()
{
  if(resolve_address(source_str, &source, NULL) == 0)
    {
      return 0;
    }

  return 1;
}

static void usage_str(char c, char *str)
{
  fprintf(stderr, "              -%c %s\n", c, str);
  return;
}

static void usage(u_int32_t option)
{
  fprintf(stderr, "%s\n%s\n%s\n",
	    "usage: ipmp_ping [-?46aAhNPrRT] [-c count] [-w waitbetween]",
	    "                 [-s packetsize] [-S src_addr] [-p precision]",
	    "                 [-t timeout] [-n listfile] [host]");

  if(option == 0) return;

  fprintf(stderr, "\n");

  if(option & OPT_IPV4)
    usage_str('4',"force encapsulation in an IPv4 header");

  if(option & OPT_IPV6)
    usage_str('6',"force encapsulation in an IPv6 header");

  if(option & OPT_AUDIBLE)
    usage_str('a', "audible bell when a response arrives");

  if(option & OPT_HOPS)
    usage_str('h', "print the hop count there and back");

  if(option & OPT_RESOLV)
    usage_str('N', "resolve the IP addresses in path records");

  if(option & OPT_RTT)
    usage_str('r', "print the round-trip-time of responses");

  if(option & OPT_RAW)
    usage_str('R', "send the echo request using a raw socket");

  if(option & OPT_COUNT)
    usage_str('c', "send this number of packets to the host");

  if(option & OPT_WAITBETWEEN)
    usage_str('w', "wait this long between sending request packets (msec)");

  if(option & OPT_SIZE)
    usage_str('s', "the IPMP packet should be this size (bytes)");

  if(option & OPT_SRCADDR)
    usage_str('S', "send packets with the specified source address");

  if(option & OPT_TIMEOUT)
    usage_str('t', "wait this long for the last response packet");

  if(option & OPT_NLANR)
    usage_str('N', "ping this list of hosts");

  if(option & OPT_PRECISION)
    usage_str('p', "print the RTT with this number of decimal places");

  if(option & OPT_TONY)
    usage_str('A', "used with the -N option to print sequence numbers");

  if(option & OPT_PROBE)
    usage_str('P', "send a probe one-way");

  if(option & OPT_TOS)
    usage_str('T', "8 bits of (Type of Service) TOS to set in IPv[46] header");

  fprintf(stderr, "\n");  

  return;
}

/*
 * check_options()
 * 
 * parse the command line, looking for the options that have been entered.
 * we also check that the user has not entered in an invalid combination of
 * options
 */
static int check_options(int argc, char *argv[])
{
  int ch;

  if(argc == 1)
    {
      usage(0);
      return 0;
    }

  while((ch = getopt(argc,argv,"46Aac:hn:Np:rRs:S:t:T:w:?")) != -1)
    {
      switch(ch)
	{
        case '4':
	  options |= OPT_IPV4;
	  break;

        case '6':
	  options |= OPT_IPV6;
          break;

	case 'a':
	  options |= OPT_AUDIBLE;
	  break;

	case 'A':
	  options |= OPT_TONY;
	  break;

	case 'c':
	  options |= OPT_COUNT;
	  count = atoi(optarg);
	  break;

	case 'h':
	  options |= OPT_HOPS;
	  break;

	case 'n': /* the file is a list of hosts to ping */
	  options |= OPT_NLANR;
	  filename = optarg;
	  break;

        case 'N':
          options |= OPT_RESOLV;
          break;

	case 'p':
	  options |= OPT_PRECISION;
	  precision = atoi(optarg);
	  break;

	case 'P':
	  options |= OPT_PROBE;
	  break;

	case 'r':
	  options |= OPT_RTT;
	  break;

        case 'R':
          options |= OPT_RAW;
          break;

	case 's':
	  options |= OPT_SIZE;
	  packetsize = atoi(optarg);
	  break;

	case 'S':
	  options |= OPT_SRCADDR;
          source_str = optarg;
	  break;

	case 't': /* timeout is specified in seconds */
	  options |= OPT_TIMEOUT;
	  timeout = atoi(optarg);
	  break;

	case 'T':
	  options |= OPT_TOS;
	  tos = strtol(optarg, NULL, 0);
	  break;

	case 'w':
          options |= OPT_WAITBETWEEN;
	  wait_between = atoi(optarg);
	  break;

	case '?':
          usage(0xffffffff);
          return 0;

	default:
	  usage(0);
          return 0;
	}
    }

  if(options & OPT_IPV4 && options & OPT_IPV6)
    {
      usage(OPT_IPV4 | OPT_IPV6);
      fprintf(stderr, "Cannot force only-IPv4 and only-IPv6\n");
      return 0;
    }

  if(options & OPT_COUNT && count < 1)
    {
      usage(OPT_COUNT);
      return 0;
    }

  if(options & OPT_PRECISION && (precision < 0 || precision > 6))
    {
      usage(OPT_PRECISION);
      return 0;
    }

  if(options & OPT_TIMEOUT && timeout < 1)
    {
      usage(OPT_TIMEOUT);
      return 0;
    }

  if(options & OPT_WAITBETWEEN && wait_between < 0)
    {
      usage(OPT_WAITBETWEEN);
      return 0;
    }

  if(options & OPT_SRCADDR)
    {
      if(source_address() == 0)
        {
          usage(OPT_SRCADDR);
          return 0;
        }
    }

  if((options & OPT_SIZE) == 0)
    {
      if(options & OPT_IPV4) packetsize = 52;
      if(options & OPT_IPV6) packetsize = 88;
    }
  
  if((options & OPT_TOS) && (tos < 0 || tos > 255))
    {
      usage(OPT_TOS);
      return 0;
    }

  if(is_valid_packetsize() == 0)
    {
      usage(OPT_SIZE);
      return 0;
    }

  /*
   * if the nlanr option is specified, the user should not be specifying any
   * output modifiers in addition to this one
   * (only packet modifiers are allowed)
   */
  if(options & OPT_NLANR)
    {
      if(options & OPT_AUDIBLE || options & OPT_HOPS || options & OPT_RTT ||
	 options & OPT_PROBE)
	{
	  fprintf(stderr, "Error: Cannot use -n with ahrP\n");
	  usage(OPT_NLANR);
          return 0;
	}
    }

  if(options & OPT_RESOLV)
    {
      if(dnsentry_init() == 0) return 0;
    }

  return 1;
}

static int time_to_send_request()
{
  struct timeval tv;
  gettimeofday(&tv, &tz);

  if(sent_all_requests == 1)
    {
      return 0;
    }

  if(wait_between == 0)
    {
      return 1;
    }

  if(timeval_diff_msec(&wait_between_tv, &tv) > 0)
    {
      return 0;
    }

  return 1;
}

static int open_ipmp_sockets4()
{
  char      addr[128];
  struct    sockaddr_in *sin;

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

  if((options & OPT_SRCADDR) && source->sa_family == AF_INET)
    {
      if(bind(ipmp_sock, source, sizeof(struct sockaddr_in)) == -1)
	{
	  sin = (struct sockaddr_in *)source;
	  inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr));

	  printerror(errno, strerror, "could not bind to %s", addr);
	  return 0;
	}
    }

#if defined(__NetBSD__)
  ipv4_ttl = 255;
#else
  if(sysctl(mib, miblen, &ipv4_ttl, &len, NULL, 0) == -1)
    {
      printerror(errno, strerror, "could not find out default ipv4 ttl");
      return 0;
    }
#endif

  return 1;
}

static int open_ipmp_sockets6()
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
 * Function: main
 * Purpose:  
 * Comments: 
 */
int main(int argc, char *argv[])
{
  int                i;
  struct sigaction   si_sa;
  int                euid, ruid;
  struct host_entry *cursor;

  /*
   * first things first
   * if anything goes wrong anywhere, we want to be super careful to release
   * any file descriptor we have on /dev/lkm, and it probably makes sense to
   * shutdown the raw socket we have too.
   */
  atexit(cleanup);

  /*
   * get the effective and the real user id's so we know if we are running
   * with elevated permissions or not
   */
  euid = geteuid();
  ruid = getuid();

  /* check for the command line arguments */
  if(check_options(argc,argv) == 0)
    {
      return -1;
    }

  /*
   * open the raw socket now.  i used to have this further down closer to
   * where it was needed, but because you can't change the euid/uid to and
   * from root (unless you're the superuser) i can only do this once
   */
  if(options & OPT_IPV4)
    {
      if(open_ipmp_sockets4() == 0) return -1; 
    }
  else if(options & OPT_IPV6)
    {
      if(open_ipmp_sockets6() == 0) return -1; 
    }
  else
    {
      if(open_ipmp_sockets4() == 0) return -1;
      if(open_ipmp_sockets6() == 0) return -1;
    }

  /*
   * revoke the permissions we requested as we only need them to open a raw
   * socket.  this is to reduce the impact of any buffer overflow exploits
   * that may be present
   */
  if(ruid != euid)
    {
      setreuid(ruid, ruid);
    }

  /*
   * we get the pid so we can identify incoming ipmp packets destined for
   * this instance of ipmp_ping
   */
  pid = getpid();

  /*
   * need to know about the addresses this host has
   */
  learn_localaddresses();

  /*
   * in FreeBSD, the actual ping is done by a kernel module that has a syscall
   * in it.  the kernel module allows the protocol to get a timestamp as close
   * to when the mbuf is actually sent to ip_output as possible
   */
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

  /*
   * the -n option means that the user has supplied a list of hosts to
   * ping, so we read those entries and put them in an list of hosts with
   * details regarding each host.  the task of putting hosts into the list
   * is handled by read_hosts_file
   *
   * if the -n option isnt specified, we create a list containing just the 
   * one host to ping.  this way, all the program logic can be used in a
   * multitude of situations.
   */
  if(options & OPT_NLANR)
    {
      /*
       * if something went wrong parsing the file, we quit.
       */
      if(read_hosts_file() == 0)
	{
	  return -1;
	}
    }
  else
    {
      /*
       * if the user didnt specify a host to ping, we bail, telling them
       * why first...
       */
      if(argc - optind != 1)
	{
	  usage(0);
          return -1;
	}

      /*
       * if we can't add a host entry for the host supplied on the command line
       * tell the user that it couldnt be parse and cleanup
       */
      if(add_host_entry(argv[optind], NULL) == 0)
	{
	  return -1;
	}
    }

  /*
   * we now put some handlers into action so if the user ctrl-c's us we have
   * the opportunity to tell them what we found out first
   * also, if the user specified a timeout, put an alarm in for that so we
   * can bail when they tell us to...
   */
  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags = 0;
  si_sa.sa_handler = alarm_bells;
  if(sigaction(SIGINT, &si_sa, 0) == -1)
    {
      printerror(errno, strerror, "could not set sigaction for SIGINT");
      return -1;
    }
  if(options & OPT_TIMEOUT)
    {
      if(sigaction(SIGALRM, &si_sa, 0) == -1)
	{
	  printerror(errno, strerror, "could not set sigaction for SIGALRM");
	  return -1;
	}
    }

  /*
   * we loop for as long as we have not been told to finish up.
   * the finish_up loop will exit when
   *  - there has been an alarm set that goes off
   *  - a SIGINT is received (from e.g. Ctrl-C)
   *  - we have got_all_response()'s
   *
   * this is not an expensive loop in terms of cpu cycles, as the
   * recv_echo_response will sleep if there is nothing to recv until we have
   * told it to stop blocking - typically one second or whatever the between
   * timeout is.
   *
   * the loop does two things:
   *  - sends echo requests
   *  - receives echo responses
   *
   * the loop sends packets, pausing for however long the timeout is set for
   * between packets.  this pause is implemented in the recv_echo_response
   * function in a call to select(2).  if we cannot send a request to one of
   * them, we bail, as this probably means the syscall could not be called.
   *
   * the loop recv's the response and associates the packet with a host_entry
   * we then parse that response for the host entry, and then check if we have
   * now got all the responses we are looking for.  if we have, we exit the
   * loop by setting the finish_up flag
   */

  sent_all_requests = 0;
  i = 0;

  cursor = head;

  while(finish_up == 0)
    {
      while(sent_all_requests == 0)
	{
	  if(send_echo_request(cursor) != 0)
	    {
	      return -1;
	    }
	  cursor->tx++;

	  if(cursor->tx == count)
	    {
	      cursor = cursor->next;
	      if(cursor == NULL)
		{
		  sent_all_requests = 1;
		  alarm(timeout);
		  break;
		}
	    }

	  if(wait_between > 0)
	    {
	      gettimeofday(&wait_between_tv, &tz);
	      timeval_add(&wait_between_tv, wait_between);
	      break;
	    }
	}

      while(time_to_send_request() == 0 && finish_up == 0)
	{
	  if(recv_echo_responses() > 0)
	    {
	      if(got_all_responses() == 1)
		{
		  finish_up = 1;
		}
	    }
	}
    }

  /*
   * if we have been given a list of hosts to ping, we have to print out which
   * hosts did not give us a reply
   */
  if(options & OPT_NLANR)
    {
      show_loss();
    }

  return 0;
}
