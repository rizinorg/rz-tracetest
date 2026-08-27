// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "adapter.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <rz_types.h>
#include <rz_util/rz_bitvector.h>
#include <rz_util/rz_hex.h>
#include <rz_util/rz_strbuf.h>
#include <vector>

static inline bool IsOneBitFlag(const std::string &tn) {
	// PPC
	if (tn == "ca" || tn == "ca32" || tn == "ov" || tn == "ov32" || tn == "so") {
		return true;
	}
	return false;
}

std::string TraceAdapter::RizinCPU() const {
	return isa;
}

int TraceAdapter::RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const {
	return 0;
}

bool TraceAdapter::IgnoreUnknownReg(const std::string &trace_reg_name) const {
	return false;
}

std::string TraceAdapter::TraceRegToRizin(const std::string &tracereg) const {
	return tracereg;
}

void TraceAdapter::AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const {}

void TraceAdapter::AdjustRegContentsFromRizin(const std::string &tracename, RzBitVector *rizin_val) const {}

void TraceAdapter::PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const {}

bool TraceAdapter::IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const {
	return false;
}

bool TraceAdapter::AllowNoOperandSameValueAssignment() const {
	return false;
}

class VICETraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override { return "6502"; }

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "sr") {
				return "flags";
			}
			return tracereg;
		}

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const override {
			if (tracename == "sr") {
				// mask out the unused and break bits, which rizin does not represent
				rz_bv_set(trace_val, 5, false);
				rz_bv_set(trace_val, 4, false);
			}
		}

		void AdjustRegContentsFromRizin(const std::string &tracename, RzBitVector *rizin_val) const override {
			if (tracename == "sr") {
				// mask out the unused and break bits, which rizin does not represent
				rz_bv_set(rizin_val, 5, false);
				rz_bv_set(rizin_val, 4, false);
			}
		}

		void PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const override {
			if (tracename == "sr") {
				if (bits_size != 8) {
					return;
				}
				ut8 sr = data[0];
				printf("    0  %#04x  C  = %d\n", 1 << 0, (sr & (1 << 0)) != 0);
				printf("    1  %#04x  Z  = %d\n", 1 << 1, (sr & (1 << 1)) != 0);
				printf("    2  %#04x  I  = %d\n", 1 << 2, (sr & (1 << 2)) != 0);
				printf("    3  %#04x  D  = %d\n", 1 << 3, (sr & (1 << 3)) != 0);
				printf("    4  %#04x (B) = %d\n", 1 << 4, (sr & (1 << 4)) != 0);
				printf("    5  %#04x     = %d\n", 1 << 5, (sr & (1 << 5)) != 0);
				printf("    6  %#04x  V  = %d\n", 1 << 6, (sr & (1 << 6)) != 0);
				printf("    7  %#04x  N  = %d\n", 1 << 7, (sr & (1 << 7)) != 0);
			}
		}

		bool AllowNoOperandSameValueAssignment() const override {
			return true;
		}
};

class Arm32TraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override { return "arm"; }

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return (mode && mode.value() == FRAME_MODE_ARM_T32) ? 16 : 32;
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "GE") {
				return std::string("gef");
			}
			std::string r = tracereg;
			std::transform(r.begin(), r.end(), r.begin(), ::tolower);
			return r;
		}

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const override {
			if (tracename == "NF" || tracename == "ZF" || tracename == "CF" || tracename == "VF" || tracename == "QF") {
				// flags in the trace have 32 bits, but they should just have 1
				bool set = !rz_bv_is_zero_vector(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 1);
				rz_bv_set_from_ut64(trace_val, set ? 1 : 0);
			}
			if (tracename == "GE") {
				ut32 val = rz_bv_to_ut32(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 4);
				rz_bv_set_from_ut64(trace_val, val);
			}
			if (op && rz_bv_len(trace_val) == 32 && op->mnemonic && !strncmp(op->mnemonic, "mrs ", 4)) {
				// mrs ops read cpsr and write a single register, but we don't support all bits from cpsr
				// so we need to mask some out in the result.
				rz_bv_set_from_ut64(trace_val, rz_bv_to_ut32(trace_val) & 0xf80f0000); // nzcvg is 0xf8000000, ge is 0xf0000
			}
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			if ((pc_actual & ~1) == (pc_expect & ~1)) {
				// interworking
				return true;
			}
			switch (pc_actual) {
			// Kernel-provided User Helpers
			// See https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt
			case 0xffff0ffc: // kuser_helper_version
			case 0xffff0fe0: // kuser_get_tls
			case 0xffff0fc0: // kuser_cmpxchg
			case 0xffff0fa0: // kuser_memory_barrier
			case 0xffff0f60: // kuser_cmpxchg64
				return true;
			default:
				return false;
			}
		}
};

class Arm64TraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override { return "arm"; }
		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override { return 64; }

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "R31") {
				return "sp";
			}
			if (tracereg.size() >= 1 && tracereg[0] == 'R') {
				return "x" + tracereg.substr(1);
			}
			std::string r = tracereg;
			std::transform(r.begin(), r.end(), r.begin(), ::tolower);
			return r;
		}

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const override {
			if (tracename == "NF" || tracename == "ZF" || tracename == "CF" || tracename == "VF") {
				// flags in the trace have 32 bits, but they should just have 1
				bool set = !rz_bv_is_zero_vector(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 1);
				rz_bv_set_from_ut64(trace_val, set ? 1 : 0);
			}
		}
};

class Sparc32TraceAdapter : public TraceAdapter {
	private:
		std::vector<const char *> event_ignore_regs = {
			"cwp",
			"ccr",
			"pstate",
			"asi",
			"fprs"
		};

	public:
		std::string RizinArch() const override { return "sparc"; }
		std::string RizinCPU() const override { return "v8"; }

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override { return 32; }

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			return tracereg;
		}

		bool AllowNoOperandSameValueAssignment() const override {
			return true;
		}

		bool AssumeEventIsJustified(const RzILEvent *event) const override {
			// Ignore all writes which didn't change anything.
			switch (event->type) {
			default:
				return false;
			case RZ_IL_EVENT_VAR_READ: {
				// These registers don't exist in the QEMU.
				const char *var_name = event->data.var_read.variable;
				return std::any_of(event_ignore_regs.begin(), event_ignore_regs.end(), [&](const char *elem) { return RZ_STR_EQ(var_name, elem); });
			}
			case RZ_IL_EVENT_VAR_WRITE: {
				// These registers don't exist in the QEMU.
				const char *var_name = event->data.var_write.variable;
				return std::any_of(event_ignore_regs.begin(), event_ignore_regs.end(), [&](const char *elem) { return RZ_STR_EQ(var_name, elem); });
			}
			case RZ_IL_EVENT_MEM_READ:
			case RZ_IL_EVENT_MEM_WRITE:
				// The memory region 1 is Rizin's region to backup register content for read and write.
				return event->data.mem_write.index == 1; // = SPARC_ASI_INDEX_RW
			}
			return false;
		};

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op = nullptr) const override {
			if (tracename == "fsr") {
				size_t len = rz_bv_len(trace_val);
				uint64_t fsr = rz_bv_to_ut64(trace_val);
				// Remove the exception related fields until we have exception hooks.
				rz_bv_set_from_ut64(trace_val, fsr & ~0x3ffull);
				return;
			}
		}

		void AdjustRegContentsFromRizin(const std::string &tracename, RzBitVector *rizin_val) const override {
			if (tracename != "fsr") {
				return;
			}
			size_t len = rz_bv_len(rizin_val);
			uint64_t fsr = rz_bv_to_ut64(rizin_val);
			// Remove the exception related fields until we have exception hooks.
			rz_bv_set_from_ut64(rizin_val, fsr & ~0x3ffull);
		}

		bool RegNeedsCustomHandling(const std::string &trace_reg_name) const override {
			return trace_reg_name == "psr";
		}

		void CompareSubreg(RzReg *rz_reg_instance, const char *rz_subreg_name, ut64 rexpected, RzStrBuf *miss_name, RzStrBuf *miss_val) override {
			RzRegItem *rz_reg_item = rz_reg_get(rz_reg_instance, rz_subreg_name, RZ_REG_TYPE_ANY);
			RzBitVector *actual_val = rz_reg_get_bv(rz_reg_instance, rz_reg_item);
			if (RZ_STR_EQ(rz_subreg_name, "ccr")) {
				// Only compare the icc bits.
				ut64 v = rz_bv_to_ut64(actual_val);
				rz_bv_fini(actual_val);
				rz_bv_init(actual_val, 8);
				rz_bv_set_from_ut64(actual_val, v & 0xf);
			}
			RzBitVector *expected_val = rz_bv_new_from_ut64(rz_reg_item->size, rexpected);
			if (!rz_bv_eq(actual_val, expected_val) && !IgnorePostMismatchReg(rz_subreg_name)) {
				if (rz_strbuf_length(miss_name) > 0) {
					rz_strbuf_append(miss_name, " | ");
				}
				rz_strbuf_append(miss_name, rz_subreg_name);
				char *tmp = rz_bv_as_hex_string(actual_val, true);
				if (rz_strbuf_length(miss_val) > 0) {
					rz_strbuf_append(miss_val, " | ");
				}
				rz_strbuf_append(miss_val, tmp);
				free(tmp);
				failed_custom_compare = true;
			}
			rz_bv_free(actual_val);
			rz_bv_free(expected_val);
		}

		void CustomRegSetup(RzReg *rz_reg, const std::string &trace_reg_name, const RzBitVector *trace_bv) const override {
			if (trace_reg_name != "psr") {
				return;
			}
			// QEMU encodes icc, xcc, asi, ppsr and cwp in psr.
			uint64_t psr = rz_bv_to_ut64(trace_bv);
			uint64_t cwp = psr & 0x1f;
			uint64_t ccr = (psr >> 20) & 0xf;

			RzRegItem *reg_cwp = rz_reg_get(rz_reg, "cwp", RZ_REG_TYPE_ANY);
			RzRegItem *reg_ccr = rz_reg_get(rz_reg, "ccr", RZ_REG_TYPE_ANY);
			assert(reg_cwp && reg_ccr);

			rz_reg_set_bv(rz_reg, reg_cwp, rz_bv_new_from_ut64(reg_cwp->size, cwp));
			rz_reg_set_bv(rz_reg, reg_ccr, rz_bv_new_from_ut64(reg_ccr->size, ccr));
		}

		bool CustomRegCompare(RzReg *rz_reg,
			const std::string &trace_reg_name,
			const RzBitVector *trace_bv,
			RZ_OUT char **mismatch_name,
			RZ_OUT char **mismatch_val) override {
			assert(trace_reg_name == "psr");
			uint64_t psr = rz_bv_to_ut64(trace_bv);
			uint64_t cwp_expected = psr & 0x1f;
			uint64_t ccr_expected = (psr >> 20) & 0xf;

			RzStrBuf *miss_name = rz_strbuf_new("");
			RzStrBuf *miss_val = rz_strbuf_new("");

			failed_custom_compare = false;
			CompareSubreg(rz_reg, "cwp", cwp_expected, miss_name, miss_val);
			CompareSubreg(rz_reg, "ccr", ccr_expected, miss_name, miss_val);

			*mismatch_name = rz_strbuf_drain(miss_name);
			*mismatch_val = rz_strbuf_drain(miss_val);
			return failed_custom_compare == false;
		}

		// We ignore all writes and reads to PC or NPC.
		// Due to the inability of the QEMU trace to properly
		// log delayed branches, we need to test them separatly.
		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return true;
		}

		virtual bool IgnorePostMismatchReg(const std::string &rz_reg_name) const override {
			return rz_reg_name == "pc" || rz_reg_name == "npc" ||
				// Doesn't exist in Sparc32, but is present in gdb.
				rz_reg_name == "fprs";
		}
};

class Sparc64TraceAdapter : public TraceAdapter {
	private:
		std::vector<const char *> event_ignore_regs = {
			"cwp",
			"ccr",
			"pstate",
			"asi"
		};

	public:
		std::string RizinArch() const override { return "sparc"; }
		std::string RizinCPU() const override { return "v9"; }

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override { return 64; }

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			return tracereg;
		}

		bool AllowNoOperandSameValueAssignment() const override {
			return true;
		}

		bool AssumeEventIsJustified(const RzILEvent *event) const override {
			// Ignore all writes which didn't change anything.
			switch (event->type) {
			default:
				return false;
			case RZ_IL_EVENT_VAR_READ: {
				// These registers don't exist in the QEMU.
				const char *var_name = event->data.var_read.variable;
				return std::any_of(event_ignore_regs.begin(), event_ignore_regs.end(), [&](const char *elem) { return RZ_STR_EQ(var_name, elem); });
			}
			case RZ_IL_EVENT_VAR_WRITE: {
				// These registers don't exist in the QEMU.
				const char *var_name = event->data.var_write.variable;
				return std::any_of(event_ignore_regs.begin(), event_ignore_regs.end(), [&](const char *elem) { return RZ_STR_EQ(var_name, elem); });
			}
			case RZ_IL_EVENT_MEM_READ:
			case RZ_IL_EVENT_MEM_WRITE:
				// The memory region 1 is Rizin's region to backup register content for read and write.
				return event->data.mem_write.index == 1; // = SPARC_ASI_INDEX_RW
			}
			return false;
		};

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op = nullptr) const override {
			if (tracename == "fprs") {
				ut8 v = rz_bv_to_ut8(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 3);
				rz_bv_set_from_ut64(trace_val, v);
				return;
			} else if (tracename == "fsr") {
				size_t len = rz_bv_len(trace_val);
				uint64_t fsr = rz_bv_to_ut64(trace_val);
				// Remove the exception related fields until we have exception hooks.
				rz_bv_set_from_ut64(trace_val, fsr & ~0x3ffull);
				return;
			}
		}

		void AdjustRegContentsFromRizin(const std::string &tracename, RzBitVector *rizin_val) const override {
			if (tracename != "fsr") {
				return;
			}
			size_t len = rz_bv_len(rizin_val);
			uint64_t fsr = rz_bv_to_ut64(rizin_val);
			// Remove the exception related fields until we have exception hooks.
			rz_bv_set_from_ut64(rizin_val, fsr & ~0x3ffull);
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override {
			return false;
		}

		bool RegNeedsCustomHandling(const std::string &trace_reg_name) const override {
			return trace_reg_name == "state";
		}

		void CompareSubreg(RzReg *rz_reg_instance, const char *rz_subreg_name, ut64 rexpected, RzStrBuf *miss_name, RzStrBuf *miss_val) override {
			RzRegItem *rz_reg_item = rz_reg_get(rz_reg_instance, rz_subreg_name, RZ_REG_TYPE_ANY);
			RzBitVector *actual_val = rz_reg_get_bv(rz_reg_instance, rz_reg_item);
			RzBitVector *expected_val = rz_bv_new_from_ut64(rz_reg_item->size, rexpected);
			if (!rz_bv_eq(actual_val, expected_val) && !IgnorePostMismatchReg(rz_subreg_name)) {
				if (rz_strbuf_length(miss_name) > 0) {
					rz_strbuf_append(miss_name, " | ");
				}
				rz_strbuf_append(miss_name, rz_subreg_name);
				char *tmp = rz_bv_as_hex_string(actual_val, true);
				if (rz_strbuf_length(miss_val) > 0) {
					rz_strbuf_append(miss_val, " | ");
				}
				rz_strbuf_append(miss_val, tmp);
				free(tmp);
				failed_custom_compare = true;
			}
			rz_bv_free(actual_val);
			rz_bv_free(expected_val);
		}

		void CustomRegSetup(RzReg *rz_reg, const std::string &trace_reg_name, const RzBitVector *trace_bv) const override {
			if (trace_reg_name != "state") {
				return;
			}
			// QEMU encodes icc, xcc, asi, pstate and cwp in state.
			uint64_t state = rz_bv_to_ut64(trace_bv);
			uint64_t cwp = state & 0xff;
			uint64_t pstate = (state >> 8) & 0xfff;
			uint64_t asi = (state >> 24) & 0xff;
			uint64_t ccr = (state >> 32) & 0xff;

			RzRegItem *reg_cwp = rz_reg_get(rz_reg, "cwp", RZ_REG_TYPE_ANY);
			RzRegItem *reg_asi = rz_reg_get(rz_reg, "asi", RZ_REG_TYPE_ANY);
			RzRegItem *reg_pstate = rz_reg_get(rz_reg, "pstate", RZ_REG_TYPE_ANY);
			RzRegItem *reg_ccr = rz_reg_get(rz_reg, "ccr", RZ_REG_TYPE_ANY);
			assert(reg_cwp && reg_asi && reg_pstate && reg_ccr);

			rz_reg_set_bv(rz_reg, reg_cwp, rz_bv_new_from_ut64(reg_cwp->size, cwp));
			rz_reg_set_bv(rz_reg, reg_asi, rz_bv_new_from_ut64(reg_asi->size, asi));
			rz_reg_set_bv(rz_reg, reg_pstate, rz_bv_new_from_ut64(reg_pstate->size, pstate));
			rz_reg_set_bv(rz_reg, reg_ccr, rz_bv_new_from_ut64(reg_ccr->size, ccr));
		}

		bool CustomRegCompare(RzReg *rz_reg,
			const std::string &trace_reg_name,
			const RzBitVector *trace_bv,
			RZ_OUT char **mismatch_name,
			RZ_OUT char **mismatch_val) override {
			assert(trace_reg_name == "state");
			uint64_t state = rz_bv_to_ut64(trace_bv);
			uint64_t cwp_expected = state & 0xff;
			uint64_t pstate_expected = (state >> 8) & 0xfff;
			uint64_t asi_expected = (state >> 24) & 0xff;
			uint64_t ccr_expected = (state >> 32) & 0xff;

			RzStrBuf *miss_name = rz_strbuf_new("");
			RzStrBuf *miss_val = rz_strbuf_new("");

			failed_custom_compare = false;
			CompareSubreg(rz_reg, "cwp", cwp_expected, miss_name, miss_val);
			CompareSubreg(rz_reg, "asi", asi_expected, miss_name, miss_val);
			CompareSubreg(rz_reg, "pstate", pstate_expected, miss_name, miss_val);
			CompareSubreg(rz_reg, "ccr", ccr_expected, miss_name, miss_val);

			*mismatch_name = rz_strbuf_drain(miss_name);
			*mismatch_val = rz_strbuf_drain(miss_val);
			return failed_custom_compare == false;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return true;
		}

		virtual bool IgnorePostMismatchReg(const std::string &rz_reg_name) const override {
			return rz_reg_name == "pc" || rz_reg_name == "npc";
		}
};

class PPCTraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override { return "ppc"; }

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			if (mode) {
				return (mode.value() == FRAME_MODE_PPC64) ? 64 : 32;
			}
			return machine.value();
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override {
			return trace_reg_name == "ca32" || trace_reg_name == "ov32";
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg.substr(0, 3) == "crf") {
				// crf0 -> cr0
				return std::string()
					.append(tracereg.substr(0, 2))
					.append(tracereg.substr(3, 1));
			}
			std::string r = tracereg;
			std::transform(r.begin(), r.end(), r.begin(), ::tolower);
			return r;
		}

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const override {
			if (tracename.substr(0, 3) == "crf") {
				ut8 v = rz_bv_to_ut8(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 4);
				rz_bv_set_from_ut64(trace_val, v);
			} else if (IsOneBitFlag(tracename)) {
				bool set = !rz_bv_is_zero_vector(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 1);
				rz_bv_set_from_ut64(trace_val, set ? 1 : 0);
			} else if (tracename == "VRSAVE") {
				ut64 v = rz_bv_to_ut64(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 32);
				rz_bv_set_from_ut64(trace_val, v);
			} else if (tracename == "XER") {
				// Remove ca32 and ov32 bits
				ut64 v = rz_bv_to_ut64(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 64);
				ut64 r = v & PPC_XER_ISA2_BITS_MASK;
				rz_bv_set_from_ut64(trace_val, r);
			}
		}

		void AdjustRegContentsFromRizin(
			const std::string &tracename,
			RzBitVector *rizin_val) const override {
			if (tracename == "XER") {
				// Remove ca32 and ov32 bits
				ut64 v = rz_bv_to_ut64(rizin_val);
				rz_bv_fini(rizin_val);
				rz_bv_init(rizin_val, 64);
				ut64 r = v & PPC_XER_ISA2_BITS_MASK;
				rz_bv_set_from_ut64(rizin_val, r);
			}
		}
};

class I8051TraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override { return "8051"; }

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return 16;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override {
			return true;
		}
};

class MipsTraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override {
			return "mips";
		}

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return machine.value();
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override {
			return true;
		}
};

class GBTraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override {
			return "gb";
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "pc") {
				// Rizin extends pc to 32bit mpc
				return "mpc";
			}
			return tracereg;
		}

		void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op) const override {
			if (tracename == "pc") {
				// Rizin extends pc to 32bit mpc
				ut16 v = rz_bv_to_ut16(trace_val);
				rz_bv_fini(trace_val);
				rz_bv_init(trace_val, 32);
				rz_bv_set_from_ut64(trace_val, v);
			}
		}

		void PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const override {
			if (tracename == "f") {
				if (bits_size != 8) {
					return;
				}
				ut8 f = data[0];
				printf("    0  %#04x     = %d\n", 1 << 0, (f & (1 << 0)) != 0);
				printf("    1  %#04x     = %d\n", 1 << 1, (f & (1 << 1)) != 0);
				printf("    2  %#04x     = %d\n", 1 << 2, (f & (1 << 2)) != 0);
				printf("    3  %#04x     = %d\n", 1 << 3, (f & (1 << 3)) != 0);
				printf("    4  %#04x  C  = %d\n", 1 << 4, (f & (1 << 4)) != 0);
				printf("    5  %#04x  H  = %d\n", 1 << 5, (f & (1 << 5)) != 0);
				printf("    6  %#04x  N  = %d\n", 1 << 6, (f & (1 << 6)) != 0);
				printf("    7  %#04x  Z  = %d\n", 1 << 7, (f & (1 << 7)) != 0);
			}
		}

		bool AllowNoOperandSameValueAssignment() const override {
			return true;
		}
};

class HexagonTraceAdapter : public TraceAdapter {
	public:
		std::string RizinArch() const override {
			return "hexagon";
		}

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return 32;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override {
			return false;
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			std::string r = tracereg;
			for (size_t i = 0; i < RZ_ARRAY_SIZE(hexagon_reg_mapping); ++i) {
				if (hexagon_reg_mapping[i].qemu == tracereg) {
					r = hexagon_reg_mapping[i].rz;
				}
			}
			std::transform(r.begin(), r.end(), r.begin(), ::toupper);
			return r;
		}

		bool IgnoreCompareMemMismatch() const override {
			// Dual stores won't get recognized because every memop gets compared.
			// Although we would need to combine both.
			return true;
		}

		bool AssumeEventIsJustified(const RzILEvent *event) const override {
			// We ignore all writes and reads to .new register for now, because they
			// get optimized away by QEMU for some instrucions.
			switch (event->type) {
			default:
				return false;
			case RZ_IL_EVENT_VAR_READ:
				if (strstr(event->data.var_read.variable, "_tmp")) {
					return true;
				}
				return false;
			case RZ_IL_EVENT_VAR_WRITE:
				if (strstr(event->data.var_write.variable, "_tmp")) {
					return true;
				}
				if (strstr(event->data.var_write.variable, "C4")) {
					// Ignore writes to C4 P3:0 since QEMU only writes
					// to each predicate reg separately and never to C4.
					// Because it is onlt an alias.
					return true;
				}
				if (strstr(event->data.var_write.variable, "C1")) {
					// Ignore writes to LC0 where old == new value.
					// The tcg code chains blocks together and the LC0 value
					// we cannot trace the C1 writes in this case.
					// So these are ignored.
					return rz_il_value_eq(event->data.var_write.old_value, event->data.var_write.new_value);
				}
				return false;
			}
			return false;
		};
};

class X86TraceAdapter : public TraceAdapter {
		std::string RizinArch() const override {
			return "x86";
		}

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return (machine && machine.value() == frame_mach_x86_64) ? 64 : 32;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		virtual std::string TraceRegToRizin(const std::string &tracereg) const override {
			std::string r = tracereg;
			std::transform(r.begin(), r.end(), r.begin(), ::tolower);
			return r;
		}
};

class TriCoreTraceAdapter : public TraceAdapter {
		std::string RizinArch() const override {
			return "tricore";
		}

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return 32;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			std::string r = tracereg;
			if (r.size() > 1 && (r[0] == 'a' || r[0] == 'd')) {
				bool alldigits = std::all_of(r.begin() + 1, r.end(), [](unsigned char c) { return std::isdigit(c); });
				if (alldigits) {
					return r;
				}
			}
			std::transform(r.begin(), r.end(), r.begin(), ::toupper);
			return r;
		}

		bool IgnorePostMismatchReg(const std::string &rz_reg_name) const override {
			static const std::vector<std::string> ignore_regs = {
				"cpu_id", "syscon"
			};
			static const auto cmp_icase = [&](const std::string &x) {
				return std::equal(x.begin(), x.end(),
					rz_reg_name.begin(), rz_reg_name.end(),
					[](char a, char b) {
						return tolower(a) == tolower(b);
					});
			};
			return std::find_if(ignore_regs.begin(), ignore_regs.end(), cmp_icase) != ignore_regs.end();
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override { return true; }

		bool AssumeEventIsJustified(const RzILEvent *event) const override {
			if (event->type != RZ_IL_EVENT_VAR_WRITE) {
				return false;
			}
			auto oldv = event->data.var_write.old_value;
			auto newv = event->data.var_write.new_value;
			return rz_il_value_eq(oldv, newv);
		};
};

class RiscVTraceAdapter : public TraceAdapter {
		std::string RizinArch() const override {
			return "riscv";
		}

		int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const override {
			return machine && machine.value() == frame_mach_riscv64 ? 64 : 32;
		}

		bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const override {
			return false;
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "frm") {
				return std::string();
			}
			// TODO: width mismatch between QEMU traces and Rizin (128 vs. 512), and V-extension instructions unhandled in lifter still
			if (tracereg.size() >= 2 && tracereg[0] == 'v' && std::isdigit(tracereg[1])) {
				return std::string();
			}
			if (tracereg == "fp") {
				return "s0";
			}
			std::string r = tracereg;
			std::transform(r.begin(), r.end(), r.begin(), ::tolower);
			return r;
		}

		bool IgnoreUnknownReg(const std::string &trace_reg_name) const override { return true; }

		bool AllowNoOperandSameValueAssignment() const override { return true; }
};

std::unique_ptr<TraceAdapter>
SelectTraceAdapter(frame_architecture arch, size_t mach) {
	switch (arch) {
	case frame_arch_6502:
		return std::unique_ptr<TraceAdapter>(new VICETraceAdapter());
	case frame_arch_arm:
		return std::unique_ptr<TraceAdapter>(new Arm32TraceAdapter());
	case frame_arch_aarch64:
		return std::unique_ptr<TraceAdapter>(new Arm64TraceAdapter());
	case frame_arch_powerpc:
		return std::unique_ptr<TraceAdapter>(new PPCTraceAdapter());
	case frame_arch_8051:
		return std::unique_ptr<TraceAdapter>(new I8051TraceAdapter());
	case frame_arch_mips:
		return std::unique_ptr<TraceAdapter>(new MipsTraceAdapter());
	case frame_arch_sm83:
		return std::unique_ptr<TraceAdapter>(new GBTraceAdapter());
	case frame_arch_hexagon:
		return std::unique_ptr<TraceAdapter>(new HexagonTraceAdapter());
	case frame_arch_i386:
		return std::unique_ptr<TraceAdapter>(new X86TraceAdapter());
	case frame_arch_tricore:
		return std::unique_ptr<TraceAdapter>(new TriCoreTraceAdapter());
	case frame_arch_sparc: {
		std::unique_ptr<TraceAdapter> adapter;
		if (frame_mach_sparc_64bit_p(mach) != 0) {
			adapter = std::unique_ptr<TraceAdapter>(new Sparc64TraceAdapter());
		} else {
			adapter = std::unique_ptr<TraceAdapter>(new Sparc32TraceAdapter());
		}
		adapter->SetIsBigEndian(mach == frame_mach_sparc_sparclite_le ? false : true);
		return adapter;
	}
	case frame_arch_riscv:
		return std::unique_ptr<TraceAdapter>(new RiscVTraceAdapter());
	default:
		return nullptr;
	}
}
