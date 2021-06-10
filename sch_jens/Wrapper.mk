# GNUmakefile for the sch_jens Linux kernel module, extmod wrapper
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

# from jupp packaging in Debian
shellescape='$(subst ','\'',$(1))'

KBUILD_EXTMOD:=${gmf_module_srcdir}
export KBUILD_EXTMOD

export gmf_wraptgt

include ./Makefile

MAKEARGS := -f $(call shellescape,${gmf_module_srcdir})/Wrapmap.mk ${MAKEARGS}
