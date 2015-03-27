obj-$(CONFIG_NFIT_TEST) += test/

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

obj-$(CONFIG_ND_CORE) += nd.o
obj-$(CONFIG_NFIT_ACPI) += nd_acpi.o
obj-$(CONFIG_BLK_DEV_PMEM) += nd_pmem.o

nd_acpi-y := acpi.o

nd-y := core.o
nd-y += bus.o
nd-y += dimm_devs.o
nd-y += dimm.o
nd-y += region_devs.o
nd-y += region.o
nd-y += namespace_devs.o
nd-y += label.o

nd_pmem-y := pmem.o
