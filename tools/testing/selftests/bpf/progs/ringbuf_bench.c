// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

const volatile int batch_cnt = 0;
const volatile __s64 use_output = 0;

__s64 sample_val = 42;
__s64 dropped __attribute__((aligned(128))) = 0;

const volatile __s64 wakeup_data_size = 0;

static __always_inline __s64 get_flags()
{
	__s64 sz;

	if (!wakeup_data_size)
		return 0;

	sz = (__s64) bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA);
	return sz >= wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int bench_ringbuf(void *ctx)
{
	__s64 *sample, flags;
	int i;

	if (!use_output) {
		for (i = 0; i < batch_cnt; i++) {
			sample = bpf_ringbuf_reserve(&ringbuf,
					             sizeof(sample_val), 0);
			if (!sample) {
				__sync_add_and_fetch(&dropped, 1);
			} else {
				*sample = sample_val;
				flags = get_flags();
				bpf_ringbuf_submit(sample, flags);
			}
		}
	} else {
		for (i = 0; i < batch_cnt; i++) {
			flags = get_flags();
			if (bpf_ringbuf_output(&ringbuf, &sample_val,
					       sizeof(sample_val), flags))
				__sync_add_and_fetch(&dropped, 1);
		}
	}
	return 0;
}
