PROG=	umascan
MAN=
WARNS?=	3

CFLAGS=-g

SRCS= umascan.c slabs.c main.c

DPADD=	${LIBKVM}
LDADD=	-lkvm

.include <bsd.prog.mk>
