/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Abstraction for 64-bit load/store:
 *   - Emulate 64-bit access with two 32-bit load/stores.
 *   - In the non-emulated case, output register pair r<N>:r<N+1>
 *     so macro takes only 1 output arg and determines the 2nd.
 */

.macro ST64.ab d, s, incr
	st.ab	\d, [\s, \incr / 2]
	.ifeqs	"\d", "r4"
		st.ab	r5, [\s, \incr / 2]
	.endif
	.ifeqs	"\d", "r6"
		st.ab	r7, [\s, \incr / 2]
	.endif
.endm

.macro LD64.ab d, s, incr
	ld.ab	\d, [\s, \incr / 2]
	.ifeqs	"\d", "r4"
		ld.ab	r5, [\s, \incr / 2]
	.endif
	.ifeqs	"\d", "r6"
		ld.ab	r7, [\s, \incr / 2]
	.endif
.endm
