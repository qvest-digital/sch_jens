# GNUmakefile for the sch_jens Linux kernel module
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

# from jupp packaging in Debian
shellescape='$(subst ','\'',$(1))'

gmf_kernelversion=	$(shell uname -r)
gmf_kernelbasedir=	/lib/modules/${gmf_kernelversion}
gmf_kernelmakedir=	${gmf_kernelbasedir}/build
gmf_module_srcdir=	$(shell pwd)
gmE_kernelmakedir=	$(call shellescape,${gmf_kernelmakedir})
gmE_module_srcdir=	$(call shellescape,${gmf_module_srcdir})
gmf_mk=			${MAKE} -C ${gmE_kernelmakedir} M=${gmE_module_srcdir}
gmf_wrap_mk=		${gmf_mk} -f ${gmE_module_srcdir}/Wrapper.mk
gmf_wrap=		${gmf_wrap_mk} gmf_wraptgt=$(call shellescape,$(1)) gmf_wrapped

export gmf_kernelversion gmf_kernelbasedir gmf_kernelmakedir gmf_module_srcdir

all:
	${gmf_mk} modules

clean:
	${gmf_mk} clean

install:
	${gmf_mk} modules_install

uninstall:
	$(call gmf_wrap,gmf_uninst)

unload:
	-rmmod sch_jens

load: unload
	insmod sch_jens.ko

.PHONY: all clean install mpost unload load
