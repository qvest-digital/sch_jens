# GNUmakefile for the JENS Linux kernel modules
# © 2021, 2022 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
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

versions:
	@b='[1m'; n='[0m'; ov=$(call shellescape,${gmf_kernelversion}); \
	 cd /lib/modules && for v in [4-9].*/build/; do \
		if test x"$${v%/build/}" = x"$$ov"; then \
			i=$$n$$b; \
		else \
			i=$$n; \
		fi; \
		echo "$${i}make gmf_kernelversion=$${v%/build/}$${n}"; \
	done

clean:
	${gmf_mk} clean
	-rm -rf .show-hz .tmp_versions

install:
	${gmf_mk} modules_install

uninstall:
	$(call gmf_wrap,gmf_uninst)

unload:
	-rmmod sch_janz

load: unload
	insmod sch_janz.ko

show-hz:
	@-rm -f .show-hz
	@test ! -e .show-hz && test ! -h .show-hz
	env SHOW_HZ_HACK=1 ${gmf_mk} modules
	test -s .tmp_SHOW_HZ.i || test -s SHOW_HZ.i
	sed --posix -ne '/SHOW_HZ_before/,/SHOW_HZ_after/p' $$(if \
	    test -s .tmp_SHOW_HZ.i; then echo .tmp_SHOW_HZ.i; \
	    else echo SHOW_HZ.i; fi) | \
	    tr '\n' ' ' | (cat; echo) | \
	    sed --posix -e 's/^[^;]*;//' -e 's/ *;.*$$//' -e 's/^.*= *//' \
	    >.show-hz
	test -s .show-hz
	env SHOW_HZ_HACK=1 ${gmf_mk} clean
	@echo
	@echo HZ = $$(cat .show-hz)
	@rm -f .show-hz

.PHONY: all versions clean install mpost unload load show-hz
