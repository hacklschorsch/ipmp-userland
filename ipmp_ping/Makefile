CFLAGS+=		-Wall
OBJS=			mjl_ipmp_util.o mjl_array.o ipmp_ping.o

CFLAGS+=		-g

ipmp_ping:		${OBJS}	
			${CC} ${LDFLAGS} -o ipmp_ping ${OBJS} 

ipmp_ping.o:		ipmp_ping.c
			${CC} ${CFLAGS} -c ipmp_ping.c

mjl_ipmp_util.o:	mjl_ipmp_util.c
			${CC} ${CFLAGS} -c mjl_ipmp_util.c

mjl_array.o:		mjl_array.c
			${CC} ${CFLAGS} -c mjl_array.c

clean:
			rm -f ipmp_ping *~ ${OBJS} 

install:		ipmp_ping
			install -m 4555 -o root ipmp_ping /usr/local/bin
