// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dump.h"

#include <rz_asm.h>

static void DumpStdFrame(const std_frame &frame, ut64 index, RzAsm *rzasm);

void DumpTrace(SerializedTrace::TraceContainerReader &trace, ut64 offset, ut64 count, int verbose, TraceAdapter *adapter) {
	std::unique_ptr<RzAsm, decltype(&rz_asm_free)> rzasm(nullptr, rz_asm_free);
	if (adapter) {
		rzasm.reset(rz_asm_new());
		rz_asm_use(rzasm.get(), adapter->RizinArch().c_str());
		rz_asm_set_cpu(rzasm.get(), adapter->RizinCPU().c_str());
		int bits = adapter->RizinBits();
		if (bits) {
			rz_asm_set_bits(rzasm.get(), bits);
		}
	}

	const meta_frame *meta = trace.get_meta();
	printf("META:\n%s\n======================================\n\n", meta->DebugString().c_str());

	ut64 index = 0;
	trace.seek(offset);
	while (!trace.end_of_trace() && count--) {
		auto frame = trace.get_frame();
		if (frame->has_std_frame()) {
			DumpStdFrame(frame->std_frame(), index, rzasm.get());
		}
		if (!frame->has_std_frame() || verbose) {
			printf("%" PFMT64u " = %s\n", index, frame->DebugString().c_str());
		}
		index++;
	}
}

static void DumpStdFrame(const std_frame &frame, ut64 index, RzAsm *rzasm) {
#if 0
	if (frame.address() & (1 << 31)) {
		return;
	}
#endif
	char *hex = rz_hex_bin2strdup((const ut8 *)frame.rawbytes().data(), frame.rawbytes().size());
	printf(Color_BCYAN "-- %5" PFMT64u "    0x%" PFMT64x "    %s", index, (ut64)frame.address(), hex);
	if (rzasm) {
		char *disasm = rz_asm_to_string(rzasm, frame.address(), (const ut8 *)frame.rawbytes().data(), frame.rawbytes().size());
		printf("    %s", disasm ? rz_str_trim_tail(disasm) : "(null)");
		rz_mem_free(disasm);
	}
	printf(Color_RESET "\n");
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
