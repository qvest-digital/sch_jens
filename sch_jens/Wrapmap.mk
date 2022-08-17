# GNUmakefile for the JENS Linux kernel modules, out-of-tree wrapper
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

# from jupp packaging in Debian
shellescape='$(subst ','\'',$(1))'
shellexport=$(1)=$(call shellescape,${$(1)})

gmE_module_srcdir=$(call shellescape,${gmf_module_srcdir})
export gmE_module_srcdir

KBUILD_SRC:=$(shell pwd)
KBUILD_OUTPUT:=$O

gmf_wrapped:
	${MAKE} -C ${KBUILD_OUTPUT} -f ${gmE_module_srcdir}/Wrapped.mk \
	    -rR --include-dir=$(call shellescape,${KBUILD_SRC}) \
	    $(foreach i,KBUILD_SRC KBUILD_OUTPUT KBUILD_EXTMOD,$(call shellexport,$i)) \
	    ${gmf_wraptgt}

.PHONY: gmf_wrapped
