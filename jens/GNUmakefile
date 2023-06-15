CC?=		cc
CFLAGS?=	-Og -g -fstack-protector-strong
CFLAGS+=	-Wformat -Werror=format-security -Wall -Wextra
CFLAGS+=	-fno-fast-math -fexcess-precision=standard
CPPFLAGS?=	-Wdate-time
CPPFLAGS+=	-D_GNU_SOURCE
LDFLAGS?=	-Wl,-z,relro -Wl,-z,now -Wl,--as-needed

ifeq (,${JENS_MAKE_RECURSIVE})
ifeq (ok,$(shell ${MAKE} JENS_MAKE_RECURSIVE=1 have_sednp >/dev/null 2>&1 && \
    test -x have_sednp && echo ok))
CPPFLAGS+=	-DHAVE_STRERRORDESC_NP
endif
else
have_sednp: have_sednp.o
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} $^ ${LDADD}
endif
CLEANFILES+=	have_sednp.o have_sednp

show_invalid_records?=no
ifeq (yes,${show_invalid_records})
CPPFLAGS+=	-Dshow_invalid_records
endif

JNIDIR?=	/usr/lib/jvm/default-java
JNICFLAGS+=	${CFLAGS} -fPIC -fvisibility=hidden
JNICPPFLAGS+=	${CPPFLAGS} -I${JNIDIR}/include -I${JNIDIR}/include/linux
JNILDFLAGS+=	${LDFLAGS} -Wl,--no-undefined
JNILDFLAGS+=	-shared -Wl,-soname,libjensdmpJNI.so

PROG=		jensdmp
SRCS?=		${PROG}.c
OBJS?=		${SRCS:.c=.o}

CLEANFILES+=	${PROG} ${OBJS}

PROG2=		ratedemo
SRCS2?=		${PROG2}.c
OBJS2?=		${SRCS2:.c=.o}

CLEANFILES+=	${PROG2} ${OBJS2}

PROG3=		mratedemo
SRCS3?=		${PROG3}.c
OBJS3?=		${SRCS3:.c=.o}

CLEANFILES+=	${PROG3} ${OBJS3}

JLIB=		libjensdmpJNI.so
JSRC=		nativelib.c
JOBJ=		${JSRC:.c=.o}

CLEANFILES+=	${JLIB} ${JOBJ}

all: ${PROG} ${PROG2} ${PROG3}

${PROG}: ${OBJS}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS} ${LDADD}

${PROG2}: ${OBJS2}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS2} ${LDADD}

${PROG3}: ${OBJS3}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS3} ${LDADD}

.c.o:
	${CC} -c ${CPPFLAGS} ${CFLAGS} $<

all: ${JLIB}

${JLIB}: ${JOBJ}
	${CC} -o $@ ${JNICFLAGS} ${JNILDFLAGS} ${JOBJ}

${JOBJ}: ${JSRC}
	${CC} -c ${JNICPPFLAGS} ${JNICFLAGS} $<

clean:
	-rm -rf .built
	-rm -f ${CLEANFILES}

javac: .built/java
.built/java: JensReaderLib.java JensReaderDemo.java
	javac -d .built $^
	@:>$@

e:=env "LD_LIBRARY_PATH=$$PWD"
p=de.telekom.llcto.jens.reader
if=eth0
run: all .built/java
	sudo $e java -cp .built $p.JensReaderDemo ${if} /sys/kernel/debug/sch_janz/0001:0

rundemo: ratedemo
	sudo ./ratedemo /sys/kernel/debug/sch_janz/0001:v1

runmdemo: mratedemo
	sudo ./mratedemo /sys/kernel/debug/sch_multijens/0001:v1

jd= #-t
rundump: jensdmp
	sudo ./jensdmp ${jd} /sys/kernel/debug/sch_janz/0001:0

install:
	install -m 0755 -d ${DESTDIR}/usr/lib/jni
	install -m 0644 ${JLIB} ${DESTDIR}/usr/lib/jni/
	install -m 0755 -d ${DESTDIR}/usr/libexec
	install -m 0755 ${PROG} ${PROG2} ${PROG3} ${DESTDIR}/usr/libexec/
	@echo do install the *.java examples

.PHONY: all install javac run clean
