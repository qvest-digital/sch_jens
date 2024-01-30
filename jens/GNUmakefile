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

PROG4=		jensvqdmp
SRCS4?=		${PROG4}.c
OBJS4?=		${SRCS4:.c=.o}

CLEANFILES+=	${PROG4} ${OBJS4}

PROG5=		vqdemo
SRCS5?=		${PROG5}.c
OBJS5?=		${SRCS5:.c=.o}

CLEANFILES+=	${PROG5} ${OBJS5}

all: ${PROG} ${PROG2} ${PROG3} ${PROG4} ${PROG5}

${PROG}: ${OBJS}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS} ${LDADD}

${PROG2}: ${OBJS2}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS2} ${LDADD}

${PROG3}: ${OBJS3}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS3} ${LDADD}

${PROG4}: ${OBJS4}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS4} ${LDADD}

${PROG5}: ${OBJS5}
	${CC} -o $@ ${CFLAGS} ${LDFLAGS} ${LDSTATIC} ${OBJS5} ${LDADD}

.c.o:
	${CC} -c ${CPPFLAGS} ${CFLAGS} $<

clean:
	-rm -f ${CLEANFILES}

qtype=janz

rundemo: ratedemo
	sudo ./ratedemo /sys/kernel/debug/sch_${qtype}/0001:v1

runmdemo: mratedemo
	sudo ./mratedemo /sys/kernel/debug/sch_multijens/0001:v1 \
	    5000 15000 \
	    15000 5000 \
	    5000 15000 \
	    12000 3000 \
	    128 256 \
	    768 1536 \
	    10000 20000 \
	    10000 100000

jd= #-t
rundump: jensdmp
	sudo ./jensdmp ${jd} /sys/kernel/debug/sch_${qtype}/0001:0

runvqdump: jensvqdmp
	sudo ./jensvqdmp /sys/kernel/debug/sch_jensvq/0001:v2-0

runvqdemo: vqdemo
	sudo ./vqdemo /sys/kernel/debug/sch_jensvq/0001:v2-c

install:
	install -m 0755 -d ${DESTDIR}/usr/libexec
	install -m 0755 ${PROG} ${PROG2} ${PROG3} ${PROG4} ${PROG5} \
	    ${DESTDIR}/usr/libexec/

.PHONY: all install run clean
