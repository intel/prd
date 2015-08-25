PMEM: The Persistent Memory Driver + ext4 Direct Access (DAX)
=========================================================

This tree contains the current version of the ND subsystem, the PMEM and ND BLK
drivers.  

Here are some links that might be of interest:

ACPI 6: http://www.uefi.org/sites/default/files/resources/ACPI_6.0.pdf

NVDIMM Namespace: http://pmem.io/documents/NVDIMM_Namespace_Spec.pdf

DSM Interface Example: http://pmem.io/documents/NVDIMM_DSM_Interface_Example.pdf

Driver Writer’s Guide: http://pmem.io/documents/NVDIMM_Driver_Writers_Guide.pdf

ND: https://git.kernel.org/cgit/linux/kernel/git/nvdimm/nvdimm.git

NDCTL: https://github.com/pmem/ndctl.git

PMEM: https://github.com/01org/prd

One interesting use of the PMEM driver is to allow users to begin developing
software using DAX, which was upstreamed in v4.0.  On a non-NFIT system this
can be done by using PMEM's memmap kernel command line to manually create a
type 12 memory region.

Here are the additions I made for my system with 32 GiB of RAM:

1) Reserve 16 GiB of memory via the "memmap" kernel parameter in grub's
menu.lst, using PMEM's new "!" specifier:

<pre>
memmap=16G!16G
</pre>

The documentation for this parameter can be found here:
https://www.kernel.org/doc/Documentation/kernel-parameters.txt

2) Set up the correct kernel configuration options for PMEM and DAX in .config.

<pre>
CONFIG_BLK_DEV_RAM_DAX=y
CONFIG_FS_DAX=y
CONFIG_X86_PMEM_LEGACY=y
CONFIG_LIBNVDIMM=y
CONFIG_BLK_DEV_PMEM=m
CONFIG_ARCH_HAS_PMEM_API=y
</pre>

This configuration gave me one pmem device with 16 GiB of space:

<pre>
# fdisk -l /dev/pmem0

Disk /dev/pmem0: 16 GiB, 17179869184 bytes, 33554432 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
</pre>

You can use DAX with PMEM by making an ext4 on your new /dev/pmem0 device
and then mounting it with the "dax" option:

<pre>
# mkdir /mnt/mem
# mkfs.ext4 /dev/pmem0
# mount -o dax /dev/pmem0 /mnt/mem
# mount | fgrep /mnt/mem
/dev/pmem0 on /mnt/mem type ext4 (rw,relatime,seclabel,dax,data=ordered)
# df -h | fgrep /mnt/mem
/dev/pmem0       16G   44M   15G   1% /mnt/mem
</pre>
