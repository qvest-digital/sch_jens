/*-
 * Copyright © 2020, 2021
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

#include <jni.h>

#include <linux/types.h>
#include "../sch_jens/jens_uapi.h"

#define NELEM(a)	(sizeof(a) / sizeof((a)[0]))
#define __unused	__attribute__((__unused__))
#define ZCS(x)		(x), sizeof(x)

#define tagnl(level,msg)	#level ": jensdmpJNI: " msg "\n"
#define log_err(msg, ...)	fprintf(stderr, tagnl(E, msg), ## __VA_ARGS__)
#define log_warn(msg, ...)	fprintf(stderr, tagnl(W, msg), ## __VA_ARGS__)
#define log_info(msg, ...)	fprintf(stderr, tagnl(I, msg), ## __VA_ARGS__)

static jboolean jniVerbose = JNI_TRUE;

static JNICALL jstring nativeOpen(JNIEnv *, jobject, jstring);
//…
static JNICALL void nativeClose(JNIEnv *, jobject);

#define METH(name,signature) \
	{ #name, signature, (void *)(name) }
static const JNINativeMethod methods[] = {
	METH(nativeOpen, "(Ljava/lang/String;)Ljava/lang/String;"),
	METH(nativeClose, "()V"),
};
#undef METH

static jstring e_GetStringUTFChars;

/* de.telekom.llcto.jens.reader.JensReaderLib$JNI */
static jclass cls_JNI;
/* de.telekom.llcto.jens.reader.JensReaderLib$AbstractJensActor$Record */
static jclass cls_REC;

static jfieldID o_JNI_fd;		// int
static jfieldID o_JNI_rQueueSize;	// AbstractJensActor.Record[256]
static jfieldID o_JNI_rPacket;		// AbstractJensActor.Record[256]
static jfieldID o_JNI_rUnknown;		// AbstractJensActor.Record[256]
static jfieldID o_JNI_nQueueSize;	// int
static jfieldID o_JNI_nPacket;		// int
static jfieldID o_JNI_nUnknown;		// int

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
// unknown
static jfieldID o_REC_type;		// byte

#undef HAVE_STRERRORDESC_NP	/* not on buster yet */

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
	f(cls_REC);
	f(cls_JNI);
	f(e_GetStringUTFChars);
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

	getclass(JNI, "de/telekom/llcto/jens/reader/JensReaderLib$JNI");
	getclass(REC, "de/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record");

	getfield(JNI, fd, "I");
	getfield(JNI, rQueueSize, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, rPacket, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, rUnknown, "[Lde/telekom/llcto/jens/reader/JensReaderLib$AbstractJensActor$Record;");
	getfield(JNI, nQueueSize, "I");
	getfield(JNI, nPacket, "I");
	getfield(JNI, nUnknown, "I");
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
	jsize oz = (*env)->GetArrayLength(env, (jarray)o);		\
	if ((size_t)oz != (size_t)TC_JENS_RELAY_NRECORDS) {		\
		log_err("wrong length %zu (expected %zu) for %s array",	\
		    (size_t)oz, (size_t)TC_JENS_RELAY_NRECORDS, #f);	\
		sizeCheckFail = JNI_TRUE;				\
	}								\
	(*env)->DeleteLocalRef(env, o);					\
} while (/* CONSTCOND */ 0)
	sizeCheck(rQueueSize);
	sizeCheck(rPacket);
	sizeCheck(rUnknown);
#undef sizeCheck
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
