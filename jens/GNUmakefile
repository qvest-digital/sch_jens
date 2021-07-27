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

CLEANFILES+=	*.class

javac: JensReaderLib.class JensReaderDemo.class

JensReaderLib.class: JensReaderLib.java
	javac $^

JensReaderDemo.class: JensReaderDemo.java
	javac $^

run: all javac
	sudo java JensReaderDemo /sys/kernel/debug/sch_jens/0002:0

install:
	install -m 0755 -d ${DESTDIR}/usr/sbin
	install -m 0755 jensdmp ${DESTDIR}/usr/sbin/
	@echo do install the *.java examples
