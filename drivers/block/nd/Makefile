ifdef CONFIG_NFIT_TEST
# This obviously will cause symbol collisions if another
# driver/sub-system attempts a similar mocked io-memory implementation.
# When that happens we can either add a 'choice' kconfig option to
# select one mocked instance at a time, or push for the linker to
# include an option of the form "--wrap-prefix=<prefix>" to allow for
# separate namespaces of mocked functions.
ldflags-y += --wrap=ioremap_cache
ldflags-y += --wrap=ioremap_nocache
ldflags-y += --wrap=iounmap
ldflags-y += --wrap=__request_region
ldflags-y += --wrap=__release_region
endif

obj-$(CONFIG_LIBND) += libnd.o
obj-$(CONFIG_ND_ACPI) += nd_acpi.o
obj-$(CONFIG_ND_E820) += nd_e820.o
obj-$(CONFIG_NFIT_TEST) += test/
obj-$(CONFIG_BLK_DEV_PMEM) += nd_pmem.o

nd_acpi-y := acpi.o

nd_e820-y := e820.o

nd_pmem-y := pmem.o

libnd-y := core.o
libnd-y += bus.o
libnd-y += dimm_devs.o
libnd-y += dimm.o
libnd-y += region_devs.o
libnd-y += region.o
libnd-y += namespace_devs.o
