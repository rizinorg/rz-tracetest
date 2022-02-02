// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dump.h"

static void DumpStdFrame(const std_frame &frame, ut64 index);

void DumpTrace(SerializedTrace::TraceContainerReader &trace, ut64 offset, ut64 count, int verbose) {
	const meta_frame *meta = trace.get_meta();
	printf("META:\n%s\n======================================\n\n", meta->DebugString().c_str());

	ut64 index = 0;
	trace.seek(offset);
	while (!trace.end_of_trace() && count--) {
		auto frame = trace.get_frame();
		if (frame->has_std_frame()) {
			DumpStdFrame(frame->std_frame(), index);
		}
		if (!frame->has_std_frame() || verbose) {
			printf("%" PFMT64u " = %s\n", index, frame->DebugString().c_str());
		}
		index++;
	}
}

static void DumpStdFrame(const std_frame &frame, ut64 index) {
#if 0
	if (frame.address() & (1 << 31)) {
		return;
	}
#endif
	char *hex = rz_hex_bin2strdup((const ut8 *)frame.rawbytes().data(), frame.rawbytes().size());
	printf("-- %5" PFMT64u "    0x%" PFMT64x "    %s\n", index, (ut64)frame.address(), hex);
	DumpOperandList("  PRE  ", frame.operand_pre_list(), [](const operand_info &, size_t){});
	DumpOperandList("  POST ", frame.operand_post_list(), [](const operand_info &, size_t){});
	rz_mem_free(hex);
}

void DumpOperandList(const char *prefix, const operand_value_list &operands, std::function<void(const operand_info &, size_t)> print_detail) {
	for (const auto &o : operands.elem()) {
		size_t real_bits = o.bit_length();
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			real_bits = RZ_MIN(o.value().size() * 8, real_bits);
			RzBitVector *tbv = real_bits ? rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, real_bits) : NULL;
			char *ts = tbv ? rz_bv_as_hex_string(tbv, true) : NULL;
			rz_bv_free(tbv);
			printf("%s%s : %u = %s\n", prefix, ro.name().c_str(), (unsigned int)o.bit_length(), ts ? ts : "");
			rz_mem_free(ts);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			char *hex = rz_hex_bin2strdup((const ut8 *)o.value().data(), o.value().size());
			printf("%s[0x%04" PFMT64x "] = %s\n", prefix, (ut64)mo.address(), hex);
		}
		print_detail(o, real_bits);
	}
}
