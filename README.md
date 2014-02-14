PRD: The Persistent RAM Driver + ext4 Direct Access (DAX)
=========================================================

Yet another Persistent RAM Driver.  This driver is not intended to go upstream
in its current state, and is instead meant as a development tool.

PRD is basically a modified version of the Block RAM Driver, BRD.  The major
difference is that BRD allocates its backing store pages from the page cache,
whereas PRD uses reserved memory that has been ioremapped.  The benefit of this
approach is that there is a direct mapping between filesystem block numbers and
virtual addresses.

In PRD, filesystem blocks N, N+1, N+2, etc. will all be adjacent in the virtual
memory space.  This property will hopefully allow us to set up PMD mappings (2
MiB) for DAX.

To use PRD, you need to set up some reserved memory for it.  Here are the
additions I made for my system with 64 GiB of RAM:

1) Reserve memory via the "memmap" kernel parameter in grub 1's menu.lst:

<pre>
title		Debian GNU/Linux, kernel 3.13.0+
root		(hd1,0)
kernel		/boot/vmlinuz-3.13.0+ root=UUID=fbb9c4ad-ca73-481d-affc-b0230f262333 ro memmap=32G$32G
initrd		/boot/initrd.img-3.13.0+
</pre>

2) Set up the correct kernel configuration options for PRD in .config.

<pre>
CONFIG_BLK_DEV_PMEM=m
CONFIG_BLK_DEV_PMEM_START=32
CONFIG_BLK_DEV_PMEM_COUNT=4
CONFIG_BLK_DEV_PMEM_SIZE=32
</pre>

If you intend to use DAX, you should also have this option enabled:

<pre>
CONFIG_FS_DAX=y
</pre>

This configuration gave me four pmem devices, each with 8 GiB of space:

<pre>
# fdisk -l /dev/pmem*

Disk /dev/pmem0: 8589 MB, 8589934592 bytes
255 heads, 63 sectors/track, 1044 cylinders, total 16777216 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk identifier: 0x00000000

Disk /dev/pmem0 doesn't contain a valid partition table

Disk /dev/pmem1: 8589 MB, 8589934592 bytes
255 heads, 63 sectors/track, 1044 cylinders, total 16777216 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk identifier: 0x00000000

Disk /dev/pmem1 doesn't contain a valid partition table

Disk /dev/pmem2: 8589 MB, 8589934592 bytes
255 heads, 63 sectors/track, 1044 cylinders, total 16777216 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk identifier: 0x52456575

Disk /dev/pmem2 doesn't contain a valid partition table

Disk /dev/pmem3: 8589 MB, 8589934592 bytes
255 heads, 63 sectors/track, 1044 cylinders, total 16777216 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk identifier: 0x00000000

Disk /dev/pmem3 doesn't contain a valid partition table
</pre>

This tree also includes v8 of Matthew Wilcox's patchset which adds DAX
functionality to ext4.

You can use DAX with PRD by making an ext4 on your new /dev/pmem<N> devices
and then mounting them with the "dax" option:

<pre>
# mkdir /mnt/mem
# mkfs.ext4 /dev/pmem0
# mount -o dax /dev/pmem0 /mnt/mem
# mount | fgrep /mnt/mem
/dev/pmem0 on /mnt/mem type ext4 (rw,dax)
# df -h | fgrep /mnt/mem
/dev/pmem0            7.8G   18M  7.4G   1% /mnt/mem
</pre>
