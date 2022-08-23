# GNUmakefile for the JENS Linux kernel modules, Kbuild wrapper
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

include ${KBUILD_SRC}/Makefile

# same as _emodinst_post except for the dependency on _emodinst_
gmf_modpost:
	$(call cmd,depmod)

gmf_uninst: gmf_uninst_do gmf_modpost
gmf_uninst_do:
	${MAKE} -f ${gmE_module_srcdir}/Uninst.mk gmf_uninstall

.PHONY: gmf_modpost gmf_uninst gmf_uninst_do
