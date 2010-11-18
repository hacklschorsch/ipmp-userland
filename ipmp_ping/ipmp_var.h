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

#ifndef _NETINET_IPMP_VAR_H_
#define _NETINET_IPMP_VAR_H_

struct	ipmpstat {
  u_long count;    /* number of packets */
  u_long tooshort; /* packet < IPMP_MINLEN */
  u_long checksum; /* bad checksum */
};

struct ipmp_kerntimeinfo
{
  int id;
  struct timespec timespec;
  long offset;
  int max_error;
  int est_error;
};

/*
 * Names for IPMP sysctl objects
 */
#define	IPMPCTL_PRINTFS  1
#define IPMPCTL_FLOWC    2
#define IPMPCTL_TSC      3
#define IPMPCTL_FORWARD  4 
#define IPMPCTL_STATS    5

#if defined(__FreeBSD__)
#define IPMPCTL_NAMES { \
 { 0,          0              }, \
 { "printfs",  CTLTYPE_INT    }, \
 { "flowc",    CTLTYPE_INT    }, \
 { "tsc",      CTLTYPE_INT    }, \
 { "forward",  CTLTYPE_INT    }, \
 { "stats",    CTLTYPE_STRUCT }, \
}
#elif defined(__NetBSD__)
#define IPMPCTL_NAMES { \
 { 0,          0              }, \
 { "printfs",  CTLTYPE_INT    }, \
 { "flowc",    CTLTYPE_INT    }, \
 { "tsc",      CTLTYPE_INT    }, \
 { "forward",  CTLTYPE_INT    }, \
}
#endif


#define ADJ_GET 0x0001
#define ADJ_SET 0x0002

struct ipmp_clockadj
{
  struct timespec time;
  long            offset;
  long            esterror;
};

struct ipmp_clockadjustment_args
{
  unsigned int          modes;
  struct ipmp_clockadj *adjs;
  int                   count;
};

#if __FreeBSD_version < 310000
# ifdef KERNEL
#  ifdef ACTUALLY_LKM_NOT_KERNEL
int ipmp_addclockadj __P((struct ipmp_clockadj *newadj));
#  endif
# endif
#else
# ifdef _KERNEL
#  ifndef KLD_MODULE
SYSCTL_DECL(_net_inet_ipmp);
#  else
int ipmp_addclockadj __P((struct ipmp_clockadj *newadj));
#  endif
# endif
#endif /* FreeBSD_version < 310000 */

#endif /* _NETINET_IPMP_VAR_H */
