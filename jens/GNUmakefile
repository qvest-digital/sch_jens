CC?=		cc
CFLAGS?=	-Og -g -fstack-protector-strong
CFLAGS+=	-Wformat -Werror=format-security -Wall -Wextra
CPPFLAGS?=	-Wdate-time
LDFLAGS?=	-Wl,-z,relro -Wl,-z,now -Wl,--as-needed

PROG=		jensdmp
SRCS?=		${PROG}.c
OBJS?=		${SRCS:.c=.o}

CLEANFILES+=	${PROG} ${OBJS}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS} ${LDADD}

.c.o:
	${CC} -c ${CPPFLAGS} ${CFLAGS} $<

clean:
	-rm -f ${CLEANFILES}
