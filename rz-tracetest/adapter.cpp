// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "adapter.h"

#include <memory>

static inline bool IsOneBitFlag(const std::string &tn) {
	// PPC
	if (tn == "ca" || tn == "ca32" || tn == "ov" || tn == "ov32" || tn == "so") {
		return true;
	}
	return false;
}

std::string TraceAdapter::RizinCPU() const {
	return std::string();
}

int TraceAdapter::RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const {
	return 0;
}

bool TraceAdapter::IgnoreUnknownReg(const std::string &rz_reg_name) const {
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

		bool IgnoreUnknownReg(const std::string &rz_reg_name) const override {
			return rz_reg_name == "ca32" || rz_reg_name == "ov32";
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

		bool IgnoreUnknownReg(const std::string &rz_reg_name) const override {
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

		bool IgnoreUnknownReg(const std::string &rz_reg_name) const override {
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

		bool IgnoreUnknownReg(const std::string &rz_reg_name) const override {
			return false;
		}

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			std::string r = tracereg.substr(0, tracereg.find("_tmp"));
			std::transform(r.begin(), r.end(), r.begin(), ::toupper);
			if (tracereg.find_first_of("_tmp") != std::string::npos) {
				return r += "_tmp";
			}
			return r;
		}
};

std::unique_ptr<TraceAdapter> SelectTraceAdapter(frame_architecture arch) {
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
	default:
		return nullptr;
	}
}
