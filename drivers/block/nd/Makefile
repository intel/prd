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
obj-$(CONFIG_NFIT_TEST) += test/

nd_acpi-y := acpi.o

libnd-y := core.o
libnd-y += bus.o
