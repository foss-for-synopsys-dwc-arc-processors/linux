// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <sys/types.h>

pid_t pid = 0;
__s64 ret = 0;
__u64 user_ptr = 0;
char buf[256] = {};

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int on_write(void *ctx)
{
	if (pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	ret = bpf_probe_read_user_str(buf, sizeof(buf), (void *) user_ptr);

	return 0;
}

char _license[] SEC("license") = "GPL";
