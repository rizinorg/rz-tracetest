
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

static ut32 RegOperandSizeBits(const operand_info &o) {
	assert(o.operand_info_specific().has_reg_operand());
	return RZ_MIN(o.value().size() * 8, o.bit_length());
}

static ut64 MemOperandSizeBytes(const operand_info &o) {
	assert(o.operand_info_specific().has_mem_operand());
	if (o.bit_length() % 8 != 0) {
		printf("Bit length of mem operand not byte-aligned\n");
	}
	return RZ_MIN(o.value().size(), o.bit_length() / 8);
}

static void PrintEvent(ut64 index, const RzILEvent *ev) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_il_event_stringify(ev, &sb);
	printf("%4" PFMT64u "  %s\n", index, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
}

static bool MemAccessJustifiedByOperands(RzBitVector *address, ut32 bits, const operand_value_list &operands) {
	ut64 addr = rz_bv_to_ut64(address);
	ut64 size = (bits + 7) / 8; // round IL accesses up to be on the safe side
	for (const auto &o : operands.elem()) {
		if (!o.operand_info_specific().has_mem_operand()) {
			continue;
		}
		ut64 oaddr = o.operand_info_specific().mem_operand().address();
		// At the moment, we consider a memory access only justified if it is contained within a single
		// operand. If e.g. multiple contiguous operands contain a single IL access, this will result
		// in a false positive mismatch.
		// So this can be refined if necessary for other archs in the future:
		if (addr >= oaddr && addr + size <= oaddr + o.bit_length() / 8) {
			return true;
		}
	}
	return false;
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
			RzRegItem *ri = rz_reg_get(reg.get(), TraceRegToRizin(ro.name().c_str()), RZ_REG_TYPE_ANY);
			if (!ri) {
				printf("Unknown reg: %s\n", ro.name().c_str());
				continue;
			}
			RzBitVector *bv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RegOperandSizeBits(o));
			rz_reg_set_bv(reg.get(), ri, bv);
			rz_bv_free(bv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			rz_io_write_at(io, mo.address(), (const ut8 *)o.value().data(), MemOperandSizeBytes(o));
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
		uint64_t i = 0;
		rz_list_foreach (vm->vm->events, it, evtp) {
			printf("  ");
			PrintEvent(i++, (RzILEvent *)evtp);
		}
		printf("\n");

		rz_strbuf_fini(&sb);
	};

	// trace -> vm: check that every post-operand is correctly represented in the vm

	// fallback if next program counter not specified explicitly in post operands: fallthrough to next instruction
	ut64 pc_expect = sf.address() + sf.rawbytes().length();
	RzRegItem *pc_ri = rz_reg_get_by_role(reg.get(), RZ_REG_NAME_PC);
	if (!pc_ri) {
		mismatched();
		printf("RzReg has no program counter\n");
		return FrameCheckResult::Unimplemented;
	}
	std::string pc_tracename = pc_ri->name;

	for (const auto &o : sf.operand_post_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			RzRegItem *ri = rz_reg_get(reg.get(), TraceRegToRizin(ro.name().c_str()), RZ_REG_TYPE_ANY);
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
			if (ri == pc_ri) {
				pc_tracename = ro.name();
				pc_expect = rz_bv_to_ut64(tbv);
			}
			if (!rz_bv_eq(tbv, rbv)) {
				mismatched();
				char *ts = rz_bv_as_hex_string(tbv, true);
				char *rs = rz_bv_as_hex_string(rbv, true);
				printf(Color_RED "MISMATCH" Color_RESET " post register:\n");
				printf("  expected %8s = %s\n", ro.name().c_str(), ts);
				printf("  got      %8s = %s\n", ri->name, rs);
				rz_mem_free(ts);
				rz_mem_free(rs);
			}
			rz_bv_free(tbv);
			rz_bv_free(rbv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			ut64 size = MemOperandSizeBytes(o);
			std::vector<ut8> actual(size);
			rz_io_read_at(io, mo.address(), actual.data(), size);
			if (memcmp(actual.data(), o.value().data(), size)) {
				mismatched();
				char *ts = rz_hex_bin2strdup((const ut8 *)o.value().data(), size);
				char *rs = rz_hex_bin2strdup(actual.data(), size);
				printf(Color_RED "MISMATCH" Color_RESET " post memory:\n");
				printf("  expected [0x%04" PFMT64x "] = %s\n", (ut64)mo.address(), ts);
				printf("  got      [0x%04" PFMT64x "] = %s\n", (ut64)mo.address(), rs);
				rz_mem_free(ts);
				rz_mem_free(rs);
			}
		} else {
			printf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}

	// check program counter
	ut64 pc_actual = rz_reg_get_value(reg.get(), pc_ri);
	if (pc_actual != pc_expect) {
		mismatched();
		printf(Color_RED "MISMATCH" Color_RESET " post program counter:\n");
		printf("  expected %8s = 0x%" PFMT64x "\n", pc_tracename.c_str(), pc_expect);
		printf("  got      %8s = 0x%" PFMT64x "\n", pc_ri->name, pc_actual);
	}

	// vm -> trace: try to find a valid explanation (justification) in the trace for every event that happened
	RzListIter *it;
	void *evtp;
	uint64_t evi = 0;
	bool unjustified_printed = false;
	rz_list_foreach (vm->vm->events, it, evtp) {
		RzILEvent *ev = (RzILEvent *)evtp;
		bool justified = false;
		switch (ev->type) {
		case RZ_IL_EVENT_VAR_READ: {
			for (const auto &o : sf.operand_pre_list().elem()) {
				if (!o.operand_info_specific().has_reg_operand()) {
					continue;
				}
				if (TraceRegCoversILVar(o.operand_info_specific().reg_operand().name().c_str(), ev->data.var_read.variable)) {
					justified = true;
					break;
				}
			}
			break;
		}
		case RZ_IL_EVENT_VAR_WRITE:
			// The case where a global var is written to some value other than the final one, but
			// set to the actual final one later and the final one is equal to the original one will
			// cause false-positives here.
			// So extend this if it becomes a problem with other archs in the future:
			if (rz_il_value_eq(ev->data.var_write.old_value, ev->data.var_write.new_value)) {
				// Especially relevant for 6502 from VICE, which does not record
				// variables assigned to the same value as post operands.
				justified = true;
				break;
			}
			for (const auto &o : sf.operand_post_list().elem()) {
				if (!o.operand_info_specific().has_reg_operand()) {
					continue;
				}
				if (TraceRegCoversILVar(o.operand_info_specific().reg_operand().name().c_str(), ev->data.var_write.variable)) {
					// No need to check contents here. Since there is a post operand, this has already been checked in the above loop.
					justified = true;
					break;
				}
			}
			break;
		case RZ_IL_EVENT_MEM_READ:
			justified = MemAccessJustifiedByOperands(ev->data.mem_read.address, rz_bv_len(ev->data.mem_read.value), sf.operand_pre_list());
			break;
		case RZ_IL_EVENT_MEM_WRITE:
			justified = MemAccessJustifiedByOperands(ev->data.mem_write.address, rz_bv_len(ev->data.mem_write.new_value), sf.operand_post_list());
			break;
		default:
			// pc write is already handled
			justified = true;
			break;
		}

		if (!justified) {
			mismatched();
			if (!unjustified_printed) {
				printf(Color_RED "UNJUSTIFIED" Color_RESET " event(s) performed by IL:\n");
				unjustified_printed = true;
			}
			printf("  ");
			PrintEvent(evi, ev);
		}
		evi++;
	}

	if (mismatch) {
		printf("\n");
	}
	return mismatch ? FrameCheckResult::PostStateMismatch : FrameCheckResult::Success;
}

/**
 * Get the name of the register in RzReg for a reg name given by the trace
 */
const char *RizinEmulator::TraceRegToRizin(const char *tracereg) {
	// This can be done nicer with some declarative tables when more mapping is needed
	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strcmp(arch, "6502") && !strcmp(tracereg, "sr")) {
		return "flags";
	}
	return tracereg;
}

static bool RegIsBound(RzILRegBinding *rb, const char *var) {
	for (size_t i = 0; i < rb->regs_count; i++) {
		RzILRegBindingItem *rbi = &rb->regs[i];
		if (!strcmp(rbi->name, var)) {
			return true;
		}
	}
	return false;
}

/**
 * Check if the global IL variable \p var is contained inside the RzReg register corresponding to the given trace register name
 */
bool RizinEmulator::TraceRegCoversILVar(const char *tracereg, const char *var) {
	const char *rzreg = TraceRegToRizin(tracereg);
	RzRegItem *ri = rz_reg_get(reg.get(), rzreg, RZ_REG_TYPE_ANY);
	if (!ri) {
		return false;
	}
	if (!RegIsBound(vm->reg_binding, var)) {
		return false;
	}
	if (!strcmp(rzreg, var)) {
		return true;
	}
	RzRegItem *vi = rz_reg_get(reg.get(), var, RZ_REG_TYPE_ANY);
	if (!vi || ri->type != vi->type) {
		return false;
	}
	return vi->offset >= ri->offset && vi->offset + vi->size <= ri->offset + ri->size;
}
