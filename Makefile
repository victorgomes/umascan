PROG=	umascan
MAN=
WARNS?=	3
.OBJDIR=${CANONICALOBJDIR}

IGNORE_PRAGMA=
WITH_DTRACE=

FREEBSD_SRC=/usr/src

CFLAGS=-g
SRCS=umascan.c mhdr.c ptrscan.c main.c
DlADD=	${LIBKVM}
LDADD=	-lkvm 

.if defined(WITH_DTRACE)
SRCS+=dtscan.c
CFLAGS+=-I ${FREEBSD_SRC}/cddl/compat/opensolaris/include \
	-I ${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libdtrace/common/ \
	-I ${FREEBSD_SRC}/sys/cddl/compat/opensolaris/ \
	-I ${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common/
LDADD+=-lrtld_db -lproc -lctf -lelf -lz -lpthread -ldtrace -lutil
.endif

.include <bsd.prog.mk>
