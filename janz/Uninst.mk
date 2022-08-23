# GNUmakefile for the JENS Linux kernel modules, uninstallation code
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

include $(srctree)/scripts/Makefile.modinst

gmf_uninstall: ${gmf_module_srcdir}/gmf_uninstall

${gmf_module_srcdir}/gmf_uninstall:
	rm -f $(MODLIB)/$(modinst_dir)/sch_janz.*

.PHONY: gmf_uninstall ${gmf_module_srcdir}/gmf_uninstall
