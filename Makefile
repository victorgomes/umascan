PROG=	umascan
MAN=
WARNS?=	3
.OBJDIR=${CANONICALOBJDIR}

CFLAGS=-g

SRCS= umascan.c mhdr.c scan_pointers.c main.c

DPADD=	${LIBKVM}
LDADD=	-lkvm

.include <bsd.prog.mk>
