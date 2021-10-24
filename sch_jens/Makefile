# GNUmakefile for the sch_jens/sch_jhtb Linux kernel modules
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
	-rm -f .show-hz

install:
	${gmf_mk} modules_install

uninstall:
	$(call gmf_wrap,gmf_uninst)

unload:
	-rmmod sch_jens
	-rmmod sch_jhtb

load: unload
	insmod sch_jens.ko
	insmod sch_jhtb.ko

show-hz:
	@-rm -f .show-hz
	@test ! -e .show-hz && test ! -h .show-hz
	env SHOW_HZ_HACK=1 ${gmf_mk} modules
	sed --posix -ne '/SHOW_HZ_before/,/SHOW_HZ_after/p' .tmp_SHOW_HZ.i | \
	    tr '\n' ' ' | (cat; echo) | \
	    sed --posix -e 's/^[^;]*;//' -e 's/ *;.*$$//' -e 's/^.*= *//' \
	    >.show-hz
	test -s .show-hz
	env SHOW_HZ_HACK=1 ${gmf_mk} clean
	@echo
	@echo HZ = $$(cat .show-hz)
	@rm -f .show-hz

.PHONY: all clean install mpost unload load
