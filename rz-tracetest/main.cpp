
#include <rz_core.h>

#include <trace.container.hpp>

#include <memory>

class RizinException: public std::exception
{
public:
	RizinException(const char *fmt, ...) {
		va_list ap, ap2;
		va_start(ap, fmt);
		va_copy(ap2, ap);
		int ret = vsnprintf(NULL, 0, fmt, ap2);
		ret++;
		msg = new char[ret];
		vsnprintf(msg, ret, fmt, ap);
		va_end(ap2);
		va_end(ap);
	}
	~RizinException() {
		delete msg;
	}
	const char* what() const noexcept override { return msg; }
private:
	char *msg;
};

enum class FrameCheckResult {
	Success,
	InvalidOp,
	InvalidIL,
	VMRuntimeError,
	PostStateMismatch,
	Unimplemented
};
#define FRAME_CHECK_RESULT_COUNT 6

class RizinEmulator {
	private:
		std::unique_ptr<RzCore, decltype(&rz_core_free)> core;
		std::unique_ptr<RzReg, decltype(&rz_reg_free)> reg;
		std::unique_ptr<RzAnalysisILVM, decltype(&rz_analysis_il_vm_free)> vm;
		std::unique_ptr<RzILValidateGlobalContext, decltype(&rz_il_validate_global_context_free)> validate_ctx;

	public:
		RizinEmulator(const char *arch, const char *cpu, int bits);
		FrameCheckResult RunFrame(frame *f);
		const char *RegTraceToRizin(const char *tracereg);
};

static const char *MatchRizinArch(frame_architecture arch) {
	switch (arch) {
	case frame_arch_arm:
		return "arm";
	case frame_arch_6502:
		return "6502";
	default:
		return nullptr;
	}
}

int main(int argc, const char *argv[]) {
	if (argc < 2 || argc > 4 || !strcmp(argv[1], "-h")) {
		eprintf("Usage: rz-tracetest <filename>.frames [count] [offset]\n");
		eprintf(" [count]    number of frames to check, default: all\n");
		eprintf(" [offset]   index of the first frame to check, default: 0\n");
		return 1;
	}
	ut64 count = UT64_MAX;
	ut64 offset = 0;
	if (argc > 2) {
		count = strtoull(argv[2], NULL, 0);
	}
	if (argc > 3) {
		offset = strtoull(argv[3], NULL, 0);
	}

	SerializedTrace::TraceContainerReader trace(argv[1]);
	auto arch = trace.get_arch();
	auto rarch = MatchRizinArch(arch);
	if (!rarch) {
		throw RizinException("Failed to match frame_architecture %d to Rizin architecture.\n", (int)arch);
	}
	RizinEmulator r(rarch, nullptr, 0);
	trace.seek(offset);
	ut64 stats[FRAME_CHECK_RESULT_COUNT] = {};
	while (!trace.end_of_trace() && !rz_cons_is_breaked() && count) {
		auto res = r.RunFrame(trace.get_frame().get());
		stats[static_cast<int>(res)]++;
		count--;
	}

	eprintf("\n\n---------------------------------\n");
	for (int i = 0; i < FRAME_CHECK_RESULT_COUNT; i++) {
		switch (static_cast<FrameCheckResult>(i)) {
		case FrameCheckResult::Success:
			eprintf("            success: ");
			break;
		case FrameCheckResult::InvalidOp:
			eprintf("         invalid op: ");
			break;
		case FrameCheckResult::InvalidIL:
			eprintf("         invalid il: ");
			break;
		case FrameCheckResult::VMRuntimeError:
			eprintf("   vm runtime error: ");
			break;
		case FrameCheckResult::PostStateMismatch:
			eprintf("post state mismatch: ");
			break;
		case FrameCheckResult::Unimplemented:
			eprintf("      unimplemented: ");
			break;
		}
		eprintf("%" PFMT64u "\n", stats[i]);
	}

	return 0;
}

RizinEmulator::RizinEmulator(const char *arch, const char *cpu, int bits) :
		core(rz_core_new(), rz_core_free),
		reg(rz_reg_new(), rz_reg_free),
		vm(nullptr, rz_analysis_il_vm_free),
		validate_ctx(nullptr, rz_il_validate_global_context_free) {
	if (!core) {
		throw RizinException("Failed to create RzCore.");
	}
	if (!reg) {
		throw RizinException("Failed to create RzReg.");
	}
	rz_config_set(core->config, "asm.arch", arch);
	if (cpu) {
		rz_config_set(core->config, "asm.cpu", cpu);
	}
	if (bits) {
		rz_config_set_i(core->config, "asm.bits", bits);
	}
	char *reg_profile = rz_analysis_get_reg_profile(core->analysis);
	if (!reg_profile) {
		throw RizinException("Failed to get reg profile.");
	}
	bool succ = rz_reg_set_profile_string(reg.get(), reg_profile);
	rz_mem_free(reg_profile);
	if (!succ) {
		throw RizinException("Failed to apply reg profile.");
	}
	vm.reset(rz_analysis_il_vm_new(core->analysis, reg.get()));
	if (!vm) {
		throw RizinException("Failed to create IL vm.");
	}
	validate_ctx.reset(rz_il_validate_global_context_new_from_vm(vm->vm));
	if (!validate_ctx) {
		throw RizinException("Failed to derive validation context from IL VM.");
	}
}

FrameCheckResult RizinEmulator::RunFrame(frame *f) {
	if (!f->has_std_frame()) {
		eprintf("Non-std frame, can't deal with this (yet)\n");
		return FrameCheckResult::Unimplemented;
	}

	RzIO *io = core->io;

	const std_frame &sf = f->std_frame();
	const std::string &code = sf.rawbytes();

	eprintf(Color_BCYAN "-- 0x%08" PFMT64x "    ", (ut64)sf.address());
	RzAsmOp asmop = {};
	core->rasm->pc = sf.address();
	if (rz_asm_disassemble(core->rasm, &asmop, (const ut8 *)code.data(), code.size()) > 0) {
		char *hex = rz_hex_bin2strdup((const ut8 *)code.data(), asmop.size);
		eprintf("%-16s    %s", hex, rz_strbuf_get(&asmop.buf_asm));
		free(hex);
	} else {
		eprintf("?");
	}
	eprintf(Color_RESET "\n");
	rz_asm_op_fini(&asmop);

	//////////////////////////////////////////
	// Set up pre-state

	// effects of ops should only depend on the operands given explicitly in the frame, so reset everything.
	rz_io_cache_reset(io, RZ_PERM_R | RZ_PERM_W);
	rz_reg_arena_zero(reg.get(), RZ_REG_TYPE_ANY);

	rz_io_write_at(io, sf.address(), (const ut8 *)code.data(), code.size());
	rz_reg_set_value_by_role(reg.get(), RZ_REG_NAME_PC, sf.address());

	for (const auto &o : sf.operand_pre_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			RzRegItem *ri = rz_reg_get(reg.get(), RegTraceToRizin(ro.name().c_str()), RZ_REG_TYPE_ANY);
			if (!ri) {
				eprintf("Unknown reg: %s\n", ro.name().c_str());
				continue;
			}
			RzBitVector *bv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
			rz_reg_set_bv(reg.get(), ri, bv);
			rz_bv_free(bv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			if (o.bit_length() % 8 != 0) {
				eprintf("Bit length of mem operand not byte-aligned\n");
			}
			rz_io_write_at(io, mo.address(), (const ut8 *)o.value().data(), RZ_MIN(o.value().size(), o.bit_length() / 8));
		} else {
			eprintf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	//////////////////////////////////////////
	// Check manually disassembled op

	std::unique_ptr<RzAnalysisOp, std::function<void (RzAnalysisOp *)>> aop(rz_analysis_op_new(), [](RzAnalysisOp *op) {
		rz_analysis_op_free(op);
	});
	if (rz_analysis_op(core->analysis, aop.get(), sf.address(), (const ut8 *)code.data(), code.size(), RZ_ANALYSIS_OP_MASK_ALL) <= 0) {
		eprintf("rz_analysis_op() failed\n");
		return FrameCheckResult::InvalidOp;
	}
	if (!aop->il_op) {
		eprintf("analysis plugin did not lift to IL\n");
		return FrameCheckResult::InvalidOp;
	}
	RzILValidateReport validate_report = nullptr;
	if (!rz_il_validate_effect(aop->il_op, validate_ctx.get(), NULL, NULL, &validate_report)) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb);
		eprintf("%s\n", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
		eprintf("Validation failed: %s\n", validate_report);
		rz_mem_free(validate_report);
		return FrameCheckResult::InvalidOp;
	}

	//////////////////////////////////////////
	// Execute op

	RzAnalysisILStepResult sr = rz_analysis_il_vm_step(core->analysis, vm.get(), reg.get());
	if (sr != RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS) {
		eprintf("Step failed: ");
		switch (sr) {
		case RZ_ANALYSIS_IL_STEP_IL_RUNTIME_ERROR:
			eprintf("runtime error\n");
			return FrameCheckResult::VMRuntimeError;
		case RZ_ANALYSIS_IL_STEP_INVALID_OP:
			eprintf("invalid op\n");
			return FrameCheckResult::InvalidOp;
		case RZ_ANALYSIS_IL_STEP_RESULT_NOT_SET_UP:
			eprintf("not set up\n");
			return FrameCheckResult::Unimplemented;
		default:
			eprintf("unknown\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	//////////////////////////////////////////
	// Compare results

	bool mismatch = false;
	auto mismatched = [&]() {
		if (mismatch) {
			return;
		}
		mismatch = true;
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb);
		eprintf("%s\n\n", rz_strbuf_get(&sb));

		auto print_operands = [](const operand_value_list &operands) {
			for (const auto &o : operands.elem()) {
				if (o.operand_info_specific().has_reg_operand()) {
					const auto &ro = o.operand_info_specific().reg_operand();
					RzBitVector *tbv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
					char *ts = rz_bv_as_hex_string(tbv, true);
					eprintf("  %s : %u = %s\n", ro.name().c_str(), (unsigned int)o.bit_length(), ts);
					rz_mem_free(ts);
				} else if (o.operand_info_specific().has_mem_operand()) {
					const auto &mo = o.operand_info_specific().mem_operand();
					char *hex = rz_hex_bin2strdup((const ut8 *)o.value().data(), o.value().size());
					eprintf("  [0x%04" PFMT64x "] = %s\n", (ut64)mo.address(), hex);
				}
			}
		};
		eprintf(Color_GREEN "PRE-OPERANDS:" Color_RESET "\n");
		print_operands(sf.operand_pre_list());
		eprintf(Color_GREEN "POST-OPERANDS EXPECTED:" Color_RESET "\n");
		print_operands(sf.operand_post_list());
		eprintf("\n");

		rz_strbuf_fini(&sb);
	};

	// trace -> vm: check that every post-operand is correctly represented in the vm
	for (const auto &o : sf.operand_post_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			RzRegItem *ri = rz_reg_get(reg.get(), RegTraceToRizin(ro.name().c_str()), RZ_REG_TYPE_ANY);
			if (!ri) {
				eprintf("Unknown reg: %s\n", ro.name().c_str());
				continue;
			}
			RzBitVector *tbv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
			RzBitVector *rbv = rz_reg_get_bv(reg.get(), ri);
			if (!rz_bv_eq(tbv, rbv)) {
				mismatched();
				char *ts = rz_bv_as_hex_string(tbv, true);
				char *rs = rz_bv_as_hex_string(rbv, true);
				eprintf(Color_RED "MISMATCH" Color_RESET " post-register:\n");
				eprintf("  expected %8s = %s\n", ro.name().c_str(), ts);
				eprintf("  got      %8s = %s\n", ri->name, rs);
				rz_mem_free(ts);
				rz_mem_free(rs);
			}
			rz_bv_free(tbv);
			rz_bv_free(rbv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			// TODO
		} else {
			eprintf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	// vm -> trace: try to find a valid explanation in the trace for every part of the vm state
	// TODO

	if (mismatch) {
		eprintf("\n");
	}
	return mismatch ? FrameCheckResult::PostStateMismatch : FrameCheckResult::Success;
}

const char *RizinEmulator::RegTraceToRizin(const char *tracereg) {
	// This can be done nicer with some declarative tables when more mapping is needed
	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strcmp(arch, "6502") && !strcmp(tracereg, "sr")) {
		return "flags";
	}
	return tracereg;
}
