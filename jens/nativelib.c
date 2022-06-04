/*-
 * Copyright © 2020, 2021, 2022
 *	mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom
 *
 * Provided that these terms and disclaimer and all copyright notices
 * are retained or reproduced in an accompanying document, permission
 * is granted to deal in this work without restriction, including un‐
 * limited rights to use, publicly perform, distribute, sell, modify,
 * merge, give away, or sublicence.
 *
 * This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to
 * the utmost extent permitted by applicable law, neither express nor
 * implied; without malicious intent or gross negligence. In no event
 * may a licensor, author or contributor be held liable for indirect,
 * direct, other damage, loss, or other issues arising in any way out
 * of dealing in the work, even if advised of the possibility of such
 * damage or existence of a defect, except proven that it results out
 * of said person’s immediate fault when using the work as intended.
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include <jni.h>

/* prerequisite kernel headers */
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include "../sch_jens/jens_uapi.h"

#ifndef INFTIM
#define INFTIM		(-1)
#endif

#define RBUF_TARGETSIZE (65536U)
#define RBUF_SUBBUFSIZE (RBUF_TARGETSIZE / (TC_JENS_RELAY_NRECORDS * sizeof(struct tc_jens_relay)))
#define RBUF_ELEMENTLEN (RBUF_SUBBUFSIZE * TC_JENS_RELAY_NRECORDS)
#define RBUF_BYTELENGTH (RBUF_ELEMENTLEN * sizeof(struct tc_jens_relay))

#define BIT(n)		(1U << (n))
#define NELEM(a)	(sizeof(a) / sizeof((a)[0]))
#define __unused	__attribute__((__unused__))
#define ZCS(x)		(x), sizeof(x)

#define tagnl(level,msg)	#level ": jensdmpJNI: " msg "\n"
#define log_err(msg, ...)	fprintf(stderr, tagnl(E, msg), ## __VA_ARGS__)
#define log_warn(msg, ...)	fprintf(stderr, tagnl(W, msg), ## __VA_ARGS__)
#define log_info(msg, ...)	fprintf(stderr, tagnl(I, msg), ## __VA_ARGS__)

static jboolean jniVerbose = JNI_TRUE;

static JNICALL jstring nativeOpen(JNIEnv *, jobject, jstring);
static JNICALL jstring nativeRead(JNIEnv *, jobject);
static JNICALL void nativeClose(JNIEnv *, jobject);

#define METH(name,signature) \
	{ #name, signature, (void *)(name) }
static const JNINativeMethod methods[] = {
	METH(nativeOpen, "(Ljava/lang/String;)Ljava/lang/String;"),
	METH(nativeRead, "()Ljava/lang/String;"),
	METH(nativeClose, "()V"),
};
#undef METH

static jstring e_GetStringUTFChars;
static jstring e_RecordFail;
static jstring e_UnalignedRead;

/* de.telekom.llcto.jens.reader.JensReaderLib$JNI */
static jclass cls_JNI;
/* de.telekom.llcto.jens.reader.JensReaderLib$AbstractJensActor$Record */
static jclass cls_REC;
/* java.lang.Thread */
static jclass cls_THR;

static jmethodID M_THR_interrupted;	// bool()

static jfieldID o_JNI_fd;		// int
static jfieldID o_JNI_rQueueSize;	// AbstractJensActor.Record[1024]
static jfieldID o_JNI_rPacket;		// AbstractJensActor.Record[1024]
static jfieldID o_JNI_rUnknown;		// AbstractJensActor.Record[1024]
static jfieldID o_JNI_nQueueSize;	// int
static jfieldID o_JNI_nPacket;		// int
static jfieldID o_JNI_nUnknown;		// int
static jfieldID o_JNI_buf;		// ByteBuffer

static jfieldID o_REC_timestamp;	// @Unsigned long
// queue-size
static jfieldID o_REC_len;		// int (u16)
static jfieldID o_REC_mem;		// long (u32)
// packet
static jfieldID o_REC_sojournTime;	// long (s64)
static jfieldID o_REC_chance;		// double
static jfieldID o_REC_ecnIn;		// int
static jfieldID o_REC_ecnOut;		// int
static jfieldID o_REC_ecnValid;		// bool
static jfieldID o_REC_markCoDel;	// bool
static jfieldID o_REC_markJENS;		// bool
static jfieldID o_REC_dropped;		// bool
static jfieldID o_REC_pktSize;		// long (u32)
static jfieldID o_REC_ipVer;		// int
static jfieldID o_REC_nextHeader;	// int
static jfieldID o_REC_srcIP;		// byte[16]
static jfieldID o_REC_dstIP;		// byte[16]
static jfieldID o_REC_srcPort;		// int
static jfieldID o_REC_dstPort;		// int
// unknown
static jfieldID o_REC_type;		// byte

#ifndef HAVE_STRERRORDESC_NP
#ifdef NEED_SYS_NERR_DECL
extern const int sys_nerr;
extern const char * const sys_errlist[];
#endif
#warning strerror is not thread-safe, glibc strerror_r unreliable, and your glibc lacks strerrordesc_np, using sys_errlist and sys_nerr
static const char *
Xstrerror(int eno)
{
	if (eno > 0 && eno < sys_nerr && sys_errlist[eno])
		return (sys_errlist[eno]);
	return (NULL);
}
#define strerrordesc_np Xstrerror
#endif

static jstring
jstrerror(JNIEnv *env, int eno)
{
	const char *ep;
	char buf[28];

	if (!(ep = strerrordesc_np(eno))) {
		if (snprintf(buf, sizeof(buf), "Unknown error: %d", eno) < 0) {
			if (!eno)
				memcpy(buf, ZCS("Undefined error: 0"));
			else
				memcpy(buf, ZCS("Unknown error"));
		}
		ep = buf;
	}
	return ((*env)->NewStringUTF(env, ep));
}

static void
free_grefs(JNIEnv *env)
{
#define f(x) do { if (x) {			\
	(*env)->DeleteGlobalRef(env, (x));	\
	(x) = NULL;				\
} } while (/* CONSTCOND */ 0)
	f(cls_THR);
	f(cls_REC);
	f(cls_JNI);
	f(e_GetStringUTFChars);
	f(e_RecordFail);
	f(e_UnalignedRead);
#undef f
}

JNIEXPORT JNICALL jint
JNI_OnLoad(JavaVM *vm, void *reserved __unused)
{
	JNIEnv *env;
	jint rc;
	const char *cp;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
		log_err("load: failed to get JNI environment");
		return (JNI_ERR);
	}

#define mkjstring(v,body) do {						\
	jstring tmpstr;							\
	if (!(tmpstr = (*env)->NewStringUTF(env, (body))) ||		\
	    !((v) = (*env)->NewGlobalRef(env, tmpstr))) {		\
		if (tmpstr)						\
			(*env)->DeleteLocalRef(env, tmpstr);		\
		log_err("failed to create %s jstring", #v);		\
		goto unwind;						\
	}								\
	(*env)->DeleteLocalRef(env, tmpstr);				\
} while (/* CONSTCOND */ 0)

#define getclass(dst,name) do {						\
	jclass tmpcls;							\
	if (!(tmpcls = (*env)->FindClass(env, (name))) ||		\
	    !((cls_ ## dst) = (*env)->NewGlobalRef(env, tmpcls))) {	\
		if (tmpcls)						\
			(*env)->DeleteLocalRef(env, tmpcls);		\
		log_err("failed to get class reference for %s",		\
		    (name));						\
		goto unwind;						\
	}								\
	(*env)->DeleteLocalRef(env, tmpcls);				\
} while (/* CONSTCOND */ 0)

#define _getid(what,pfx,cls,vn,jn,sig,sep,how) do {			\
	if (!((pfx ## _ ## cls ## _ ## vn) =				\
	    (*env)->how(env, cls_ ## cls, jn, sig))) {			\
		log_err("failed to get %s reference to %s%s%s",		\
		    what, #cls, sep, jn);				\
		goto unwind;						\
	}								\
} while (/* CONSTCOND */ 0)

#define getfield(cls,name,sig)	_getid("field",  o, cls, name, #name, sig, ".", GetFieldID)
#define getmeth(cls,name,sig)	_getid("method", m, cls, name, #name, sig, ".", GetMethodID)
#define getsfield(cls,name,sig)	_getid("field",  O, cls, name, #name, sig, "::", GetStaticFieldID)
#define getsmeth(cls,name,sig)	_getid("method", M, cls, name, #name, sig, "::", GetStaticMethodID)
#define getcons(cls,vn,sig)	_getid("constructor", i, cls, vn, "<init>", sig, "", GetMethodID)

	mkjstring(e_GetStringUTFChars, "GetStringUTFChars failed");
	mkjstring(e_RecordFail, "Failure accessing a Record array element");
	mkjstring(e_UnalignedRead, "relayfs read no multiple of record size");

	getclass(JNI, "de/telekom/llcto/jens/reader/JensReaderLib$JNI");
	getclass(REC, "de/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record");
	getclass(THR, "java/lang/Thread");

	getsmeth(THR, interrupted, "()Z");

	getfield(JNI, fd, "I");
	getfield(JNI, rQueueSize, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, rPacket, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, rUnknown, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, nQueueSize, "I");
	getfield(JNI, nPacket, "I");
	getfield(JNI, nUnknown, "I");
	getfield(JNI, buf, "Ljava/nio/ByteBuffer;");
	getfield(REC, timestamp, "J");
	getfield(REC, len, "I");
	getfield(REC, mem, "J");
	getfield(REC, sojournTime, "J");
	getfield(REC, chance, "D");
	getfield(REC, ecnIn, "I");
	getfield(REC, ecnOut, "I");
	getfield(REC, ecnValid, "Z");
	getfield(REC, markCoDel, "Z");
	getfield(REC, markJENS, "Z");
	getfield(REC, dropped, "Z");
	getfield(REC, pktSize, "J");
	getfield(REC, ipVer, "I");
	getfield(REC, nextHeader, "I");
	getfield(REC, srcIP, "[B");
	getfield(REC, dstIP, "[B");
	getfield(REC, srcPort, "I");
	getfield(REC, dstPort, "I");
	getfield(REC, type, "B");

	rc = (*env)->RegisterNatives(env, cls_JNI, methods, NELEM(methods));
	if (rc != JNI_OK) {
		log_err("failed to attach methods to class");
		goto unwind_rc_set;
	}

	if ((cp = getenv("JNI_VERBOSE")) && cp[0] == '0' && !cp[1])
		jniVerbose = JNI_FALSE;
	else
		log_info("load successful");
	return (JNI_VERSION_1_6);
 unwind:
	rc = JNI_ERR;
 unwind_rc_set:
	free_grefs(env);
	return (rc);
}

JNIEXPORT JNICALL void
JNI_OnUnload(JavaVM *vm, void *reserved __unused)
{
	JNIEnv *env;

	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
		log_err("unload: failed to get JNI environment");
		return;
	}

	free_grefs(env);
	if (jniVerbose)
		log_info("unload successful");
}

static JNICALL jstring
nativeOpen(JNIEnv *env, jobject obj, jstring name)
{
	jboolean sizeCheckFail = JNI_FALSE;
	const char *fn;
	int fd, eno;

	/* assert that the Java arrays are sized correctly */
#define sizeCheck(f) do {						\
	jobject o = (*env)->GetObjectField(env, obj, o_JNI_ ## f);	\
	jsize oz = o ? (*env)->GetArrayLength(env, (jarray)o) : -1;	\
	if ((size_t)oz != (size_t)RBUF_ELEMENTLEN) {			\
		log_err("wrong length %zd (expected %zu) for %s array",	\
		    (ssize_t)oz, (size_t)RBUF_ELEMENTLEN, #f);		\
		sizeCheckFail = JNI_TRUE;				\
	}								\
	(*env)->DeleteLocalRef(env, o);					\
} while (/* CONSTCOND */ 0)
	sizeCheck(rQueueSize);
	sizeCheck(rPacket);
	sizeCheck(rUnknown);
#undef sizeCheck
	do {
		jobject o = (*env)->GetObjectField(env, obj, o_JNI_buf);
		void *ob = o ? (*env)->GetDirectBufferAddress(env, o) : NULL;
		jlong n = o ? (*env)->GetDirectBufferCapacity(env, o) : -2L;
		if (ob == NULL || n != (jlong)RBUF_BYTELENGTH) {
			log_err("wrong length %ld for ByteBuffer", (long)n);
			sizeCheckFail = JNI_TRUE;
		}
		(*env)->DeleteLocalRef(env, o);
	} while (/* CONSTCOND */ 0);
	if (sizeCheckFail != JNI_FALSE) {
		eno = /*EBADRPC*/ EUCLEAN;
		goto err_out;
	}

	/* actually open the relayfs file */
	if (!(fn = (*env)->GetStringUTFChars(env, name, NULL)))
		return (e_GetStringUTFChars);
	fd = open(fn, O_RDONLY);
	eno = errno;
	(*env)->ReleaseStringUTFChars(env, name, fn);
	(*env)->SetIntField(env, obj, o_JNI_fd, (jint)fd);
	if (fd != -1)
		return (/* success */ NULL);
 err_out:
	return (jstrerror(env, eno));
}

static JNICALL void
nativeClose(JNIEnv *env, jobject obj)
{
	jint fd;

	fd = (*env)->GetIntField(env, obj, o_JNI_fd);
	if (close((int)fd)) {
		int eno = errno;
		const char *ep = strerrordesc_np(eno);

		if (ep)
			log_warn("close(%d) failed: %s", (int)fd, ep);
		else
			log_err("close(%d) failed: errno %d", (int)fd, eno);
	}
}

static int
notInterrupted(JNIEnv *env)
{
	jboolean is_interrupted = (*env)->CallStaticBooleanMethod(env,
	    cls_THR, M_THR_interrupted);
	jboolean has_exception = (*env)->ExceptionCheck(env);

	return (is_interrupted == JNI_FALSE && has_exception == JNI_FALSE);
}

static JNICALL jstring
nativeRead(JNIEnv *env, jobject obj)
{
	size_t n;
	int fd, eno, i;
	struct tc_jens_relay *buf, *hadPadding = NULL;
	jint nP = 0, nQ = 0, nU = 0;
	jobjectArray aP, aQ, aU;
	jobject to, toip;
	struct pollfd pfd;
	union {
		__u64 u;
		jlong s;
		char c[sizeof(__u64) == sizeof(jlong) ? 1 : -1];
	} U64;
	/*union {
		__u32 u;
		jint s;
		char c[sizeof(__u32) == sizeof(jint) ? 1 : -1];
	} U32;*/
	union {
		__u8 u;
		jbyte s;
		char c[sizeof(__u8) == sizeof(jbyte) ? 1 : -1];
	} U8;

	fd = (int)((*env)->GetIntField(env, obj, o_JNI_fd));
	aP = (jobjectArray)((*env)->GetObjectField(env, obj, o_JNI_rPacket));
	aQ = (jobjectArray)((*env)->GetObjectField(env, obj, o_JNI_rQueueSize));
	aU = (jobjectArray)((*env)->GetObjectField(env, obj, o_JNI_rUnknown));
	to = (*env)->GetObjectField(env, obj, o_JNI_buf);
	buf = (*env)->GetDirectBufferAddress(env, to);
	(*env)->DeleteLocalRef(env, to);

 poll_loop:
	pfd.fd = fd;
	pfd.events = POLLIN;
	eno = ECHRNG;
	i = poll(&pfd, 1, INFTIM);
	if (i == -1 && (eno = errno) == EINTR && notInterrupted(env))
		goto poll_loop;
	if (i != 1)
		goto err_out;
 read_loop:
	if ((n = read(fd, buf, RBUF_BYTELENGTH)) == (size_t)-1) {
		if ((eno = errno) == EINTR && notInterrupted(env))
			goto read_loop;
 err_out:
		return (jstrerror(env, eno));
	}
	if (n == 0)
		goto eof;
	if ((n % sizeof(struct tc_jens_relay)) != 0)
		return (e_UnalignedRead);
	n /= sizeof(struct tc_jens_relay);

	while (n--) {
		switch (buf->type) {
		case TC_JENS_RELAY_PADDING:
			hadPadding = buf;
			break;
		case TC_JENS_RELAY_INVALID:
		default:
			if (!(to = (*env)->GetObjectArrayElement(env, aU, nU)))
				return (e_RecordFail);
			U64.u = buf->ts;
			(*env)->SetLongField(env, to, o_REC_timestamp, U64.s);
			U8.u = buf->type;
			(*env)->SetByteField(env, to, o_REC_type, U8.s);
			(*env)->DeleteLocalRef(env, to);
			++nU;
			break;
		case TC_JENS_RELAY_QUEUESZ:
			if (!(to = (*env)->GetObjectArrayElement(env, aQ, nQ)))
				return (e_RecordFail);
			U64.u = buf->ts;
			(*env)->SetLongField(env, to, o_REC_timestamp, U64.s);
			(*env)->SetIntField(env, to, o_REC_len,
			    (jint)(unsigned int)buf->e16);
			(*env)->SetLongField(env, to, o_REC_mem,
			    (jlong)(unsigned long long)buf->d32);
			(*env)->DeleteLocalRef(env, to);
			++nQ;
			break;
		case TC_JENS_RELAY_SOJOURN:
			if (!(to = (*env)->GetObjectArrayElement(env, aP, nP)))
				return (e_RecordFail);
			U64.u = buf->ts;
			(*env)->SetLongField(env, to, o_REC_timestamp, U64.s);
			(*env)->SetLongField(env, to, o_REC_sojournTime,
			    (jlong)(1024ULL * (unsigned long long)buf->d32));
			(*env)->SetDoubleField(env, to, o_REC_chance,
			    (jdouble)((double)buf->e16 / TC_JENS_RELAY_SOJOURN_PCTDIV));
			(*env)->SetIntField(env, to, o_REC_ecnIn,
			    (jint)((0U + buf->f8) & 0x03U));
			(*env)->SetIntField(env, to, o_REC_ecnOut,
			    (jint)(((0U + buf->f8) >> 3) & 0x03U));
			(*env)->SetBooleanField(env, to, o_REC_ecnValid,
			    buf->f8 & BIT(2) ? JNI_TRUE : JNI_FALSE);
			(*env)->SetBooleanField(env, to, o_REC_markCoDel,
			    buf->f8 & TC_JENS_RELAY_SOJOURN_SLOW ? JNI_TRUE : JNI_FALSE);
			(*env)->SetBooleanField(env, to, o_REC_markJENS,
			    buf->f8 & TC_JENS_RELAY_SOJOURN_MARK ? JNI_TRUE : JNI_FALSE);
			(*env)->SetBooleanField(env, to, o_REC_dropped,
			    buf->f8 & TC_JENS_RELAY_SOJOURN_DROP ? JNI_TRUE : JNI_FALSE);
			(*env)->SetIntField(env, to, o_REC_ipVer,
			    (jint)(unsigned int)buf->z.zSOJOURN.ipver);
			(*env)->SetIntField(env, to, o_REC_nextHeader,
			    (jint)(unsigned int)buf->z.zSOJOURN.nexthdr);
			if (buf->z.zSOJOURN.ipver) {
				toip = (*env)->GetObjectField(env, to, o_REC_srcIP);
				(*env)->SetByteArrayRegion(env, toip, 0, 16,
				    (const void *)buf->x8);
				(*env)->DeleteLocalRef(env, toip);
				toip = (*env)->GetObjectField(env, to, o_REC_dstIP);
				(*env)->SetByteArrayRegion(env, toip, 0, 16,
				    (const void *)buf->y8);
				(*env)->DeleteLocalRef(env, toip);
			}
			(*env)->SetIntField(env, to, o_REC_srcPort,
			    (jint)(unsigned int)buf->z.zSOJOURN.sport);
			(*env)->SetIntField(env, to, o_REC_dstPort,
			    (jint)(unsigned int)buf->z.zSOJOURN.dport);
			(*env)->SetLongField(env, to, o_REC_pktSize,
			    (jlong)(unsigned long long)buf->z.zSOJOURN.psize);
			(*env)->DeleteLocalRef(env, to);
			++nP;
			break;
		}
		++buf;
	}
	/* add one padding element but only if there were no others */
	if (hadPadding && !(nP + nQ + nU)) {
		if (!(to = (*env)->GetObjectArrayElement(env, aU, nU)))
			return (e_RecordFail);
		U64.u = hadPadding->ts;
		(*env)->SetLongField(env, to, o_REC_timestamp, U64.s);
		U8.u = hadPadding->type;
		(*env)->SetByteField(env, to, o_REC_type, U8.s);
		(*env)->DeleteLocalRef(env, to);
		++nU;
	}
 eof:
	(*env)->SetIntField(env, obj, o_JNI_nPacket, nP);
	(*env)->SetIntField(env, obj, o_JNI_nQueueSize, nQ);
	(*env)->SetIntField(env, obj, o_JNI_nUnknown, nU);
	return (NULL);
}
