
#include "rzemu.h"

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

FrameCheckResult RizinEmulator::RunFrame(ut64 index, frame *f) {
	if (!f->has_std_frame()) {
		printf("Non-std frame, can't deal with this (yet)\n");
		return FrameCheckResult::Unimplemented;
	}

	RzIO *io = core->io;

	const std_frame &sf = f->std_frame();
	const std::string &code = sf.rawbytes();

	auto print_disasm = [&]() {
		printf(Color_BCYAN "-- %5" PFMT64u "     0x%08" PFMT64x "    ", index, (ut64)sf.address());
		RzAsmOp asmop = {};
		core->rasm->pc = sf.address();
		if (rz_asm_disassemble(core->rasm, &asmop, (const ut8 *)code.data(), code.size()) > 0) {
			char *hex = rz_hex_bin2strdup((const ut8 *)code.data(), asmop.size);
			printf("%-16s    %s", hex, rz_strbuf_get(&asmop.buf_asm));
			free(hex);
		} else {
			printf("?");
		}
		printf(Color_RESET "\n");
		rz_asm_op_fini(&asmop);
	};

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
				printf("Unknown reg: %s\n", ro.name().c_str());
				continue;
			}
			RzBitVector *bv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
			rz_reg_set_bv(reg.get(), ri, bv);
			rz_bv_free(bv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			if (o.bit_length() % 8 != 0) {
				printf("Bit length of mem operand not byte-aligned\n");
			}
			rz_io_write_at(io, mo.address(), (const ut8 *)o.value().data(), RZ_MIN(o.value().size(), o.bit_length() / 8));
		} else {
			printf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	//////////////////////////////////////////
	// Check manually disassembled op

	std::unique_ptr<RzAnalysisOp, std::function<void (RzAnalysisOp *)>> aop(rz_analysis_op_new(), [](RzAnalysisOp *op) {
		rz_analysis_op_free(op);
	});
	if (rz_analysis_op(core->analysis, aop.get(), sf.address(), (const ut8 *)code.data(), code.size(), RZ_ANALYSIS_OP_MASK_ALL) <= 0) {
		printf("rz_analysis_op() failed\n");
		return FrameCheckResult::InvalidOp;
	}
	if (!aop->il_op) {
		printf("analysis plugin did not lift to IL\n");
		return FrameCheckResult::InvalidOp;
	}
	RzILValidateReport validate_report = nullptr;
	if (!rz_il_validate_effect(aop->il_op, validate_ctx.get(), NULL, NULL, &validate_report)) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb);
		printf("%s\n", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
		printf("Validation failed: %s\n", validate_report);
		rz_mem_free(validate_report);
		return FrameCheckResult::InvalidOp;
	}

	//////////////////////////////////////////
	// Execute op

	RzAnalysisILStepResult sr = rz_analysis_il_vm_step(core->analysis, vm.get(), reg.get());
	if (sr != RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS) {
		printf("Step failed: ");
		switch (sr) {
		case RZ_ANALYSIS_IL_STEP_IL_RUNTIME_ERROR:
			printf("runtime error\n");
			return FrameCheckResult::VMRuntimeError;
		case RZ_ANALYSIS_IL_STEP_INVALID_OP:
			printf("invalid op\n");
			return FrameCheckResult::InvalidOp;
		case RZ_ANALYSIS_IL_STEP_RESULT_NOT_SET_UP:
			printf("not set up\n");
			return FrameCheckResult::Unimplemented;
		default:
			printf("unknown\n");
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
		print_disasm();
		mismatch = true;
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb);
		printf("%s\n\n", rz_strbuf_get(&sb));

		auto print_operands = [](const operand_value_list &operands) {
			for (const auto &o : operands.elem()) {
				if (o.operand_info_specific().has_reg_operand()) {
					const auto &ro = o.operand_info_specific().reg_operand();
					RzBitVector *tbv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
					char *ts = rz_bv_as_hex_string(tbv, true);
					printf("  %s : %u = %s\n", ro.name().c_str(), (unsigned int)o.bit_length(), ts);
					rz_mem_free(ts);
					if (!strcmp(ro.name().c_str(), "sr") && o.value().size()) {
						// TODO: generalize this for other archs too
						ut8 sr = o.value().data()[0];
						printf("    0  %#04x  C  = %d\n", 1 << 0, (sr & (1 << 0)) != 0);
						printf("    1  %#04x  Z  = %d\n", 1 << 1, (sr & (1 << 1)) != 0);
						printf("    2  %#04x  I  = %d\n", 1 << 2, (sr & (1 << 2)) != 0);
						printf("    3  %#04x  D  = %d\n", 1 << 3, (sr & (1 << 3)) != 0);
						printf("    4  %#04x (B) = %d\n", 1 << 4, (sr & (1 << 4)) != 0);
						printf("    5  %#04x     = %d\n", 1 << 5, (sr & (1 << 5)) != 0);
						printf("    6  %#04x  V  = %d\n", 1 << 6, (sr & (1 << 6)) != 0);
						printf("    7  %#04x  N  = %d\n", 1 << 7, (sr & (1 << 7)) != 0);
					}
				} else if (o.operand_info_specific().has_mem_operand()) {
					const auto &mo = o.operand_info_specific().mem_operand();
					char *hex = rz_hex_bin2strdup((const ut8 *)o.value().data(), o.value().size());
					printf("  [0x%04" PFMT64x "] = %s\n", (ut64)mo.address(), hex);
				}
			}
		};
		printf(Color_GREEN "PRE-OPERANDS:" Color_RESET "\n");
		print_operands(sf.operand_pre_list());
		printf(Color_GREEN "POST-OPERANDS EXPECTED:" Color_RESET "\n");
		print_operands(sf.operand_post_list());
		printf("\n");

		printf(Color_GREEN "IL EVENTS:" Color_RESET "\n");
		RzListIter *it;
		void *evtp;
		rz_list_foreach (vm->vm->events, it, evtp) {
			RzStrBuf sb;
			rz_strbuf_init(&sb);
			rz_il_event_stringify((RzILEvent *)evtp, &sb);
			printf("  %s\n", rz_strbuf_get(&sb));
			rz_strbuf_fini(&sb);
		}
		printf("\n");

		rz_strbuf_fini(&sb);
	};

	// trace -> vm: check that every post-operand is correctly represented in the vm
	for (const auto &o : sf.operand_post_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			RzRegItem *ri = rz_reg_get(reg.get(), RegTraceToRizin(ro.name().c_str()), RZ_REG_TYPE_ANY);
			if (!ri) {
				printf("Unknown reg: %s\n", ro.name().c_str());
				continue;
			}
			RzBitVector *tbv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RZ_MIN(o.value().size() * 8, o.bit_length()));
			RzBitVector *rbv = rz_reg_get_bv(reg.get(), ri);
			if (!strcmp(ro.name().c_str(), "sr") && o.value().size()) {
				// TODO: generalize this for other archs too
				// mask out the unused bit for 6502
				rz_bv_set(tbv, 5, false);
				rz_bv_set(rbv, 5, false);
			}
			if (!rz_bv_eq(tbv, rbv)) {
				mismatched();
				char *ts = rz_bv_as_hex_string(tbv, true);
				char *rs = rz_bv_as_hex_string(rbv, true);
				printf(Color_RED "MISMATCH" Color_RESET " post-register:\n");
				printf("  expected %8s = %s\n", ro.name().c_str(), ts);
				printf("  got      %8s = %s\n", ri->name, rs);
				rz_mem_free(ts);
				rz_mem_free(rs);
			}
			rz_bv_free(tbv);
			rz_bv_free(rbv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			// TODO
		} else {
			printf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	// vm -> trace: try to find a valid explanation in the trace for every part of the vm state
	// TODO

	if (mismatch) {
		printf("\n");
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
