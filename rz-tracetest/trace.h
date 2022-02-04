// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _TRACE_H
#define _TRACE_H

#include <trace.container.hpp>

static inline size_t OperandSizeBits(const operand_info &o) {
	size_t r = o.value().size() * 8;
	if (o.bit_length() > 0 & o.bit_length() < r) {
		return o.bit_length();
	}
	return r;
}

static inline size_t RegOperandSizeBits(const operand_info &o) {
	assert(o.operand_info_specific().has_reg_operand());
	return OperandSizeBits(o);
}

static inline size_t MemOperandSizeBytes(const operand_info &o) {
	assert(o.operand_info_specific().has_mem_operand());
	size_t bits = OperandSizeBits(o);
	if (o.bit_length() % 8 != 0) {
		printf("Bit length of mem operand not byte-aligned\n");
	}
	return bits / 8;
}

#endif
