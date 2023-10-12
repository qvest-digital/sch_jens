# GNUmakefile for the JENS Linux kernel modules, uninstallation code
# © 2021 mirabilos <t.glaser@tarent.de>, for Deutsche Telekom
# Licence: GPLv2, same as the Linux kernel

include $(srctree)/scripts/Makefile.modinst

gmf_uninstall: ${gmf_module_srcdir}/gmf_uninstall

${gmf_module_srcdir}/gmf_uninstall:
	rm -f $(MODLIB)/$(modinst_dir)/sch_janz.*
	rm -f $(MODLIB)/$(modinst_dir)/sch_janzdbg.*
	rm -f $(MODLIB)/$(modinst_dir)/sch_multijens.*
	rm -f $(MODLIB)/$(modinst_dir)/sch_jensvq2proto.*
	rm -f $(MODLIB)/$(modinst_dir)/sch_jensvq3proto.*

.PHONY: gmf_uninstall ${gmf_module_srcdir}/gmf_uninstall
