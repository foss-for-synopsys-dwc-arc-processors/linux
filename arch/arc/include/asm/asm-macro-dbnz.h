/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * Copyright (C) 2021 Synopsys, Inc. (www.synopsys.com)
 *
 * Author: Vineet Gupta <vgupta@synopsys.com>
 *
 * DBNZ pseudo-mnemonic: ARCv2
 */

.macro DBNZR r, lbl
	dbnz  \r, \lbl
.endm
