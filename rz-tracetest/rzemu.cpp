// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rzemu.h"
#include "dump.h"
#include "trace.h"

RizinEmulator::RizinEmulator(std::unique_ptr<TraceAdapter> adapter_arg)
    : adapter(std::move(adapter_arg)),
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
	rz_config_set(core->config, "asm.arch", adapter->RizinArch().c_str());
	auto cpu = adapter->RizinCPU();
	if (!cpu.empty()) {
		rz_config_set(core->config, "asm.cpu", cpu.c_str());
	}
	int bits = adapter->RizinBits(std::nullopt, adapter->GetMachine());
	if (bits) {
		rz_config_set_i(core->config, "asm.bits", bits);
	}
	rz_config_set_b(core->config, "cfg.bigendian", adapter->IsBigEndian());
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
	bool improved = false; // whether a new piece of the access was justified in the last iteration
	do {
		for (const auto &o : operands.elem()) {
			if (!o.operand_info_specific().has_mem_operand()) {
				continue;
			}
			ut64 oaddr = o.operand_info_specific().mem_operand().address();
			ut64 osize = MemOperandSizeBytes(o);
			if (addr >= oaddr && addr + size <= oaddr + osize) {
				// fully contained
				return true;
			}
			// check for partial overlap
			if (addr >= oaddr && addr < oaddr + osize) {
				// our chunk begins inside the operand, so its head is justified and can be chopped off
				size = (addr + size) - (oaddr + osize);
				addr = oaddr + osize;
				improved = true;
			} else if (addr + size >= oaddr && addr + size < oaddr + osize) {
				// our chunk ends inside the operand, so its tail is justified and can be chopped off
				size = (oaddr + osize) - addr;
				improved = true;
			}
		}
	} while (improved);
	return false;
}

FrameCheckResult RizinEmulator::RunFrame(ut64 index, frame *f, std::optional<ut64> next_pc, int verbose, bool invalid_op_quiet,
	std::optional<std::function<bool(const std::string &)>> skip_by_disasm) {
	if (!f->has_std_frame()) {
		printf("Non-std frame, can't deal with this (yet)\n");
		return FrameCheckResult::Unimplemented;
	}

	RzIO *io = core->io;

	const std_frame &sf = f->std_frame();
	const std::string &code = sf.rawbytes();

	int need_bits = adapter->RizinBits(sf.has_mode() ? std::make_optional(sf.mode()) : std::nullopt, adapter->GetMachine());
	if (need_bits && need_bits != core->rasm->bits) {
		rz_config_set_i(core->config, "asm.bits", need_bits);
	}

	struct Disasm {
			bool failed;
			std::string disasm_str;
			std::string hex_str;
	};
	std::optional<Disasm> disasm;
	auto disassemble = [&]() {
		if (disasm) {
			return;
		}
		disasm = Disasm();
		RzAsmOp asmop = {};
		core->rasm->pc = sf.address();
		disasm->failed = !code.size() || rz_asm_disassemble(core->rasm, &asmop, (const ut8 *)code.data(), code.size()) <= 0;
		if (!disasm->failed) {
			disasm->disasm_str = rz_strbuf_get(&asmop.buf_asm);
			char *hex = rz_hex_bin2strdup((const ut8 *)code.data(), asmop.size);
			disasm->hex_str = hex;
			rz_mem_free(hex);
		}
		rz_asm_op_fini(&asmop);
	};

	bool disasm_printed = false;
	auto print_disasm = [&]() {
		if (disasm_printed) {
			return;
		}
		disasm_printed = true;
		disassemble();
		printf(Color_BCYAN "-- %5" PFMT64u "     0x%08" PFMT64x "    ", index, (ut64)sf.address());
		if (!disasm->failed) {
			printf("%-16s    %s", disasm->hex_str.c_str(), disasm->disasm_str.c_str());
		} else {
			printf("?");
		}
		if (sf.has_mode()) {
			printf("    (mode: %s)", sf.mode().c_str());
		}
		printf(Color_RESET "\n");
	};
	if (verbose > 0) {
		print_disasm();
	}

	if (!code.size()) {
		print_disasm();
		printf("no code supplied.\n");
		return FrameCheckResult::InvalidOp;
	}

	if (skip_by_disasm) {
		disassemble();
		if (!disasm->failed && (*skip_by_disasm)(disasm->disasm_str)) {
			return FrameCheckResult::Skipped;
		}
	}

	RzRegItem *pc_ri = rz_reg_get_by_role(reg.get(), RZ_REG_NAME_PC);
	if (!pc_ri) {
		print_disasm();
		printf("RzReg has no program counter\n");
		return FrameCheckResult::Unimplemented;
	}

	//////////////////////////////////////////
	// Set up pre-state

	// effects of ops should only depend on the operands given explicitly in the frame, so reset everything.
	rz_io_cache_reset(io, RZ_PERM_R | RZ_PERM_W);
	rz_reg_arena_zero(reg.get(), RZ_REG_TYPE_ANY);

	rz_io_write_at(io, sf.address(), (const ut8 *)code.data(), code.size());

	for (const auto &o : sf.operand_pre_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			auto rn = adapter->TraceRegToRizin(ro.name());
			if (rn.empty()) {
				continue;
			}
			RzRegItem *ri = rz_reg_get(reg.get(), rn.c_str(), RZ_REG_TYPE_ANY);
			if (!ri) {
				if (adapter->IgnoreUnknownReg(ro.name())) {
					continue;
				}
				printf("Unknown reg: %s\n", ro.name().c_str());
				print_disasm();
				continue;
			}
			RzBitVector *bv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RegOperandSizeBits(o));
			RzBitVector *extra = rz_reg_get_bv(reg.get(), ri);
			adapter->AdjustRegContentsFromTrace(ro.name(), bv, extra);
			if (rz_bv_len(bv) != ri->size) {
				print_disasm();
				printf("Can't apply reg value of %s (%s) because its size (%u) is not equal to the one in RzReg (%u)\n",
					ro.name().c_str(), rn.c_str(), (unsigned int)rz_bv_len(bv), (unsigned int)ri->size);
			}
			rz_reg_set_bv(reg.get(), ri, bv);
			rz_bv_free(bv);
		} else if (o.operand_info_specific().has_mem_operand()) {
			const auto &mo = o.operand_info_specific().mem_operand();
			rz_io_write_at(io, mo.address(), (const ut8 *)o.value().data(), MemOperandSizeBytes(o));
		} else {
			print_disasm();
			printf("No or unknown operand type\n");
			return FrameCheckResult::Unimplemented;
		}
	}
	rz_reg_set_value_by_role(reg.get(), RZ_REG_NAME_PC, sf.address());

	//////////////////////////////////////////
	// Check manually disassembled op

	std::unique_ptr<RzAnalysisOp, std::function<void(RzAnalysisOp *)>> aop(rz_analysis_op_new(), [](RzAnalysisOp *op) {
		rz_analysis_op_free(op);
	});
	if (rz_analysis_op(core->analysis, aop.get(), sf.address(), (const ut8 *)code.data(), code.size(), RZ_ANALYSIS_OP_MASK_ALL) <= 0) {
		if (!invalid_op_quiet) {
			print_disasm();
			printf("rz_analysis_op() failed\n");
		}
		return FrameCheckResult::InvalidOp;
	}
	if (!aop->il_op) {
		if (!invalid_op_quiet) {
			print_disasm();
			printf("analysis plugin did not lift to IL\n");
		}
		return FrameCheckResult::InvalidOp;
	}
	RzILValidateReport validate_report = nullptr;
	if (!rz_il_validate_effect(aop->il_op, validate_ctx.get(), NULL, NULL, &validate_report)) {
		print_disasm();
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb, false);
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
		print_disasm();
		printf("Step failed: ");
		switch (sr) {
		case RZ_ANALYSIS_IL_STEP_IL_RUNTIME_ERROR:
			printf("runtime error\n");
			return FrameCheckResult::VMRuntimeError;
		case RZ_ANALYSIS_IL_STEP_INVALID_OP:
			printf("unlifted or invalid op\n");
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

	bool exec_info_printed = false;
	auto print_exec_info = [&]() {
		if (exec_info_printed) {
			return;
		}
		exec_info_printed = true;
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(aop->il_op, &sb, false);
		printf("%s\n\n", rz_strbuf_get(&sb));

		auto print_operands = [this](const operand_value_list &operands) {
			DumpOperandList("  ", operands, [this](const operand_info &o, size_t real_bits) {
				if (!o.operand_info_specific().has_reg_operand())
					return;
				const auto &ro = o.operand_info_specific().reg_operand();
				adapter->PrintRegisterDetails(ro.name(), o.value(), real_bits);
			});
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
	if (verbose > 1) {
		print_exec_info();
	}

	bool mismatch = false;
	auto mismatched = [&]() {
		if (mismatch) {
			return;
		}
		mismatch = true;
		print_disasm();
		print_exec_info();
	};

	// trace -> vm: check that every post-operand is correctly represented in the vm

	// fallback if next program counter not specified explicitly in post operands: fallthrough to next instruction
	ut64 pc_expect = next_pc.value_or(sf.address() + sf.rawbytes().length());
	std::string pc_tracename = pc_ri->name;

	for (const auto &o : sf.operand_post_list().elem()) {
		if (o.operand_info_specific().has_reg_operand()) {
			const auto &ro = o.operand_info_specific().reg_operand();
			auto rn = adapter->TraceRegToRizin(ro.name());
			if (rn.empty()) {
				continue;
			}
			RzRegItem *ri = rz_reg_get(reg.get(), rn.c_str(), RZ_REG_TYPE_ANY);
			if (!ri) {
				if (!adapter->IgnoreUnknownReg(ro.name())) {
					printf("Unknown reg: %s\n", ro.name().c_str());
				}
				continue;
			}
			RzBitVector *tbv = rz_bv_new_from_bytes_le((const ut8 *)o.value().data(), 0, RegOperandSizeBits(o));
			RzBitVector *rbv = rz_reg_get_bv(reg.get(), ri);
			adapter->AdjustRegContentsFromTrace(ro.name(), tbv, aop.get());
			adapter->AdjustRegContentsFromRizin(ro.name(), rbv);
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
	if (pc_actual != pc_expect && !adapter->IgnorePCMismatch(pc_actual, pc_expect)) {
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
			auto check_oplist = [&](const ::google::protobuf::RepeatedPtrField<::operand_info> &l) {
				for (const auto &o : l) {
					if (!o.operand_info_specific().has_reg_operand()) {
						continue;
					}
					if (TraceRegOverlapsILVar(o.operand_info_specific().reg_operand().name().c_str(), ev->data.var_read.variable)) {
						justified = true;
						break;
					}
				}
			};
			check_oplist(sf.operand_pre_list().elem());
			if (justified) {
				break;
			}
			check_oplist(sf.operand_post_list().elem());
			break;
		}
		case RZ_IL_EVENT_VAR_WRITE:
			// The case where a global var is written to some value other than the final one, but
			// set to the actual final one later and the final one is equal to the original one will
			// cause false-positives here.
			// So extend this if it becomes a problem with other archs in the future:
			if (adapter->AllowNoOperandSameValueAssignment() && rz_il_value_eq(ev->data.var_write.old_value, ev->data.var_write.new_value)) {
				// Especially relevant for 6502 from VICE, which does not record
				// variables assigned to the same value as post operands.
				justified = true;
				break;
			}
			for (const auto &o : sf.operand_post_list().elem()) {
				if (!o.operand_info_specific().has_reg_operand()) {
					continue;
				}
				if (TraceRegOverlapsILVar(o.operand_info_specific().reg_operand().name().c_str(), ev->data.var_write.variable)) {
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
bool RizinEmulator::TraceRegOverlapsILVar(const char *tracereg, const char *var) {
	std::string rzreg = adapter->TraceRegToRizin(tracereg);
	if (rzreg.empty()) {
		return false;
	}
	RzRegItem *ri = rz_reg_get(reg.get(), rzreg.c_str(), RZ_REG_TYPE_ANY);
	if (!ri) {
		return false;
	}
	if (!RegIsBound(vm->reg_binding, var)) {
		return false;
	}
	if (rzreg == var) {
		return true;
	}
	RzRegItem *vi = rz_reg_get(reg.get(), var, RZ_REG_TYPE_ANY);
	if (!vi || ri->type != vi->type) {
		return false;
	}
	return !(vi->offset >= ri->offset + ri->size || vi->offset + vi->size <= ri->offset);
}
