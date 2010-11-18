/*
 * IP Measurement Protocol (IPMP)
 * http://moat.nlanr.net/AMP/AMP/IPMP/
 *
 * Implementation By Matthew Luckie 2000, 2001, 2002
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety,
 * (2) distributions including binary code include the above copyright
 * notice and this paragraph in its entirety in the documentation or other
 * materials provided with the distribution, and (3) derivative work or other
 * resulting materials based on this software product display the following
 * acknowledgement: ``This work utilizes software developed in whole or in
 * part by the National Laboratory for Applied Network Research (NLANR) at
 * the University of California San Diego's San Diego Supercomputer Center,
 * under a National Science Foundation Cooperative Agreement No. ANI-9807479,
 * and its contributors.''
 * 
 * Neither the NLANR name, the name of the University, funding organizations,
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _NETINET_IPMP_H
#define _NETINET_IPMP_H

#if defined(__linux__)
# include <linux/sockios.h>
# define SIOCSENDECHOREQUEST (SIOCPROTOPRIVATE+169)
#endif

#define IPPROTO_IPMP 169

/*
 * Set the following flag if you want to enable printing to the console
 * for IPMP protocol
 */
#define IPMP_PRINTFS

#define IPMP_ECHO    0x80
#define IPMP_PROBE   0x04
#define IPMP_INFO    0x02
#define IPMP_REQUEST 0x01

struct ipmp
{
  u_int8_t  version;
  u_int8_t  options;
  u_int8_t  faux_proto;
  u_int8_t  reserved;

  u_int16_t id;
  u_int16_t seq;

  u_int16_t faux_srcport;
  u_int16_t faux_dstport;
};

struct ipmp_trailer
{
  u_int16_t path_pointer;
  u_int16_t checksum;
};

/*
 * IPMP Time format
 * this is like timespec except it ensures 32bits are used for sec and
 * nsec on 64 bit platforms such as the alpha
 */
struct ipmptime
{
  u_int32_t sec;
  u_int32_t nsec;
};

/*
 * The IPMP path record
 * This is carried inside the ipmp_echo packet
 */
struct ipmp_pathrecord
{
  u_int8_t        ttl;
  u_int8_t        flowc;
  u_int16_t       sec;
  u_int32_t       nsec;
  struct in_addr  ip;
};
struct ipmp_pathrecord6
{
  u_int8_t        hlim;
  u_int8_t        flowc;
  u_int16_t       sec;
  u_int32_t       nsec;
  struct in6_addr ip;
};

/*
 * The IPMP real time reference point structure
 * This structure is carried in an ipmp_reply packet
 */
struct ipmp_rtrp
{
  struct ipmptime real_time;
  struct ipmptime reported_time;
};

/*
 * The IPMP inforeply packet format
 */
struct ipmp_inforeply
{
  u_int16_t       length;
  u_int16_t       pdp; /* performance data pointer */
  struct in_addr  forwarding_ip;
  struct ipmptime accuracy;
  struct ipmptime overhead;
};

typedef struct ipmp_ping_args
{
  u_int8_t         ip_v;      /* version of IP to encapsulate    */
  u_int8_t         ttl;       /* ttl of the echo request         */
  u_int16_t        len;       /* size of the ipmp packet to send */
  struct ipmptime  timestamp; /* time the packet was sent        */
  u_int16_t        id;        /* the id of the packet            */
  u_int16_t        seq;       /* the sequence number             */
  u_int8_t         tos;       /* the traffic class               */
  struct sockaddr *dst;       /* the destination address         */
  struct sockaddr *src;       /* the source address to spoof     */
} ipmp_ping_args_t;

/*
 * Only the kernel needs to see this!
 */

#if defined(__FreeBSD__) && defined(_KERNEL)
struct ipmp_flow_key
{
  struct in_addr src;
  struct in_addr dst;
  u_int16_t      id;
};

#if __FreeBSD_version > 501105
void ipmp_input __P((struct mbuf *, int));
#else
void ipmp_input  __P((struct mbuf *, int, int));
#endif

void ipmp_forward __P((struct mbuf *m));
void ipmp_init  __P((void));
u_int8_t ipmp_flowc_get __P((struct ipmp_flow_key *key));
void ipmp6_init __P((void));
int  ipmp6_input __P((struct mbuf **m, int *, int));
void ipmp6_forward __P((struct mbuf *m));
#endif

#if defined(__NetBSD__) && defined(_KERNEL)
struct ipmp_flow_key
{
  struct in_addr src;
  struct in_addr dst;
  u_int16_t      id;
};

void ipmp_input  __P((struct mbuf *, ...));
int  ipmp_sysctl __P((int *, u_int, void *, size_t *, void *, size_t));
void ipmp_forward __P((struct mbuf *m));
void ipmp_init __P((void));
#endif

#if defined(__linux__)
# if defined(__KERNEL__)
#  include <linux/version.h>
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,19) 
extern int ipmp_rcv(struct sk_buff *skb);
#  else
extern int ipmp_rcv(struct sk_buff *skb, unsigned short len);
#  endif
extern int  ipmp_ioctl(struct sock *sk, int cmd, unsigned long arg);
extern void ipmp_init(struct net_proto_family *ops);
extern int  ipmp_forward(struct sk_buff *skb);
# endif
#endif

#endif /* _NETINET_IPMP_H */
