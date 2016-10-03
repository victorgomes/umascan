PROG=	umascan
MAN=
.OBJDIR=${CANONICALOBJDIR}

IGNORE_PRAGMA=
WITH_DTRACE=

SRCS=		umascan.c ptrscan.c amd64_kstack.c main.c
CFLAGS=	-g -DDEBUG -I/usr/local/include/
LDFLAGS=-L/usr/local/lib/ 
LDADD=	-l:libelf.so.1 -lkvm -lyaml

.if defined(WITH_DTRACE)
FREEBSD_SRC=/usr/src
SRCS+=dtscan.c
CFLAGS+=-I ${FREEBSD_SRC}/cddl/compat/opensolaris/include \
	-I ${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libdtrace/common/ \
	-I ${FREEBSD_SRC}/sys/cddl/compat/opensolaris/ \
	-I ${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common/
LDADD+=-lrtld_db -lproc -lctf -lz -lpthread -ldtrace -lutil
.endif

.include <bsd.prog.mk>
