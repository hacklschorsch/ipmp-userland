CFLAGS+=		-Wall
OBJS=			mjl_ipmp_util.o mjl_array.o ipmp_pathchar.o

CFLAGS+=		-O0 -g3 -ggdb -fno-inline
LDFLAGS+=		-lcurses

ipmp_pathchar:		${OBJS}	
			${CC} ${LDFLAGS} -o ipmp_pathchar ${OBJS} 

ipmp_pathchar.o:	ipmp_pathchar.c
			${CC} ${CFLAGS} -c ipmp_pathchar.c

mjl_ipmp_util.o:	mjl_ipmp_util.c
			${CC} ${CFLAGS} -c mjl_ipmp_util.c

mjl_array.o:		mjl_array.c
			${CC} ${CFLAGS} -c mjl_array.c

clean:
			rm -f ipmp_pathchar *~ ${OBJS} 

install:		ipmp_pathchar
			install -m 4555 -o root ipmp_pathchar /usr/local/bin
