// SPDX-License-Identifier: GPL-2.0

#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/unistd.h>

#include <asm/syscalls.h>
#include <asm/syscall.h>

#define sys_clone	sys_clone_wrapper
#define sys_clone3	sys_clone3_wrapper

#ifdef CONFIG_64BIT
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, off_t, off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}
#else
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, off)
{
	return ksys_mmap_pgoff(addr, len, prot, flags, fd, off);
}
#endif

#undef __SYSCALL
#define __SYSCALL(nr, call) [nr] = (call),

void *sys_call_table[NR_syscalls] = {
	[0 ... NR_syscalls-1] = sys_ni_syscall,
#include <asm/unistd.h>
};
