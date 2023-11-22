// SPDX-License-Identifier: GPL-2.0-only
/*
 * Function tracing support for ARC
 *
 * Copyright (C) 2023 Synopsys, Inc. (www.synopsys.com)
 */

#include <linux/ftrace.h>

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

/*
 * Setup return hook in traced routine
 * Function copied from riscv
 */
void prepare_ftrace_return(unsigned long *parent, unsigned long self_addr,
			   unsigned long frame_pointer)
{
	unsigned long return_hooker = (unsigned long)&return_to_handler;
	unsigned long old;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	old = *parent;

	if (!function_graph_enter(old, self_addr, frame_pointer, parent))
		*parent = return_hooker;
}

#endif	/* CONFIG_FUNCTION_GRAPH_TRACER */
