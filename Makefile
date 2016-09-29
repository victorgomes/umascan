PROG=	umascan
MAN=
.OBJDIR=${CANONICALOBJDIR}

IGNORE_PRAGMA=
WITH_DTRACE=

CFLAGS=-g -I/usr/local/include 
SRCS=umascan.c ptrscan.c amd64_kstack.c main.c
LDADD=	-lelf -lkvm -lyaml -L/usr/local/lib

.if defined(WITH_DTRACE)
FREEBSD_SRC=/usr/src
SRCS+=dtscan.c
CFLAGS+=-I ${FREEBSD_SRC}/cddl/compat/opensolaris/include \
	-I ${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libdtrace/common/ \
	-I ${FREEBSD_SRC}/sys/cddl/compat/opensolaris/ \
	-I ${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common/
LDADD+=-lrtld_db -lproc -lctf -lelf -lz -lpthread -ldtrace -lutil
.endif

.include <bsd.prog.mk>
