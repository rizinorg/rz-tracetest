// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _TRACEADAPTER_H
#define _TRACEADAPTER_H

#include <rz_util/rz_bitvector.h>
#include <trace.container.hpp>

#include <rz_util.h>
#include <rz_analysis.h>

#include <string>
#include <optional>

// Mask to exclude ISA3 flags (ca32, ov32).
#define PPC_XER_ISA2_BITS_MASK 0xfffffffffff3ffff

struct reg_name_mapping {
	const char *qemu;
	const char *rz;
};

static struct reg_name_mapping hexagon_reg_mapping[] {
	{ .qemu = "r00", .rz = "R0" },
	{ .qemu = "r01", .rz = "R1" },
	{ .qemu = "r02", .rz = "R2" },
	{ .qemu = "r03", .rz = "R3" },
	{ .qemu = "r04", .rz = "R4" },
	{ .qemu = "r05", .rz = "R5" },
	{ .qemu = "r06", .rz = "R6" },
	{ .qemu = "r07", .rz = "R7" },
	{ .qemu = "r08", .rz = "R8" },
	{ .qemu = "r09", .rz = "R9" },
	{ .qemu = "r10", .rz = "R10" },
	{ .qemu = "r11", .rz = "R11" },
	{ .qemu = "r12", .rz = "R12" },
	{ .qemu = "r13", .rz = "R13" },
	{ .qemu = "r14", .rz = "R14" },
	{ .qemu = "r15", .rz = "R15" },
	{ .qemu = "r16", .rz = "R16" },
	{ .qemu = "r17", .rz = "R17" },
	{ .qemu = "r18", .rz = "R18" },
	{ .qemu = "r19", .rz = "R19" },
	{ .qemu = "r20", .rz = "R20" },
	{ .qemu = "r21", .rz = "R21" },
	{ .qemu = "r22", .rz = "R22" },
	{ .qemu = "r23", .rz = "R23" },
	{ .qemu = "r24", .rz = "R24" },
	{ .qemu = "r25", .rz = "R25" },
	{ .qemu = "r26", .rz = "R26" },
	{ .qemu = "r27", .rz = "R27" },
	{ .qemu = "r28", .rz = "R28" },
	{ .qemu = "r29", .rz = "R29" },
	{ .qemu = "r30", .rz = "R30" },
	{ .qemu = "r31", .rz = "R31" },

	{ .qemu = "sa0", .rz = "C0" },
	{ .qemu = "lc0", .rz = "C1" },
	{ .qemu = "sa1", .rz = "C2" },
	{ .qemu = "lc1", .rz = "C3" },
	{ .qemu = "p3_0", .rz = "C4" },
	// C5 = reserved
	{ .qemu = "m0", .rz = "C6" },
	{ .qemu = "m1", .rz = "C7" },
	{ .qemu = "usr", .rz = "C8" },
	// PC = C9
	{ .qemu = "ugp", .rz = "C10" },
	{ .qemu = "gp", .rz = "C11" },
	{ .qemu = "cs0", .rz = "C12" },
	{ .qemu = "cs1", .rz = "C13" },
	{ .qemu = "upcyclelo", .rz = "C14" },
	{ .qemu = "upcyclehi", .rz = "C15" },
	{ .qemu = "framelimit", .rz = "C16" },
	{ .qemu = "framekey", .rz = "C17" },
	{ .qemu = "pktcountlo", .rz = "C18" },
	{ .qemu = "pktcounthi", .rz = "C19" },
	// Dummy regs (supposingly)
	// { .qemu = "pkt_cnt", .rz = "pkt_cnt" },
	// { .qemu = "insn_cnt", .rz = "C0" },
	// { .qemu = "hvx_cnt", .rz = "C0" },
	{ .qemu = "utimerlo", .rz = "C30" },
	{ .qemu = "utimerhi", .rz = "C31" },
};

/*
 * Interface for any arch/source/... specific adjustments
 */
class TraceAdapter {
	protected:
		bool failed_custom_compare = false;
		virtual void CompareSubreg(RzReg *rz_reg, const char *rname, ut64 rexpected, RzStrBuf *miss_name, RzStrBuf *miss_val) {}

	public:
		virtual ~TraceAdapter() {}

		/**
		 * value for asm.arch/analysis.arch
		 */
		virtual std::string RizinArch() const = 0;

		/**
		 * value for asm.cpu
		 */
		virtual std::string RizinCPU() const;

		/**
		 * \brief Returns the bits for asm.bits.
		 *
		 * \param mode The frame mode from TraceContainerReader.
		 * \param machine The machine type from TraceContainerReader.
		 * \return int The architecture bits of the trace.
		 */
		virtual int RizinBits(std::optional<std::string> mode, std::optional<uint64_t> machine) const;

		/**
		 * \brief Get the name of the register in RzReg for a reg name given by the trace.
		 * May return an empty string to indicate that the trace register does not exist in rizin and should be ignored.
		 *
		 * \param tracereg The trace register name.
		 * \return std::string The equivalent register name in Rizin.
		 */
		virtual std::string TraceRegToRizin(const std::string &tracereg) const;

		/**
		 * \brief Edit the contents of a register from the trace before comparison or before applying to RzReg
		 * This is useful e.g. for masking out information that is unsupported by rizin.
		 *
		 * \param tracename The register name in the trace.
		 * \param trace_val The register content to manipulate.
		 * \param op given only when checking post-operands (otherwise null), to mask out anything op-dependent
		 */
		virtual void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzAnalysisOp *op = nullptr) const;

		/**
		 * \brief Edit the contents of a register from RzReg before comparison
		 * This is useful e.g. for masking out information that is unsupported by the trace.
		 *
		 * \param tracename The register name in the trace.
		 * \param trace_val The register content to manipulate.
		 * \param op The RzAnalysisOp this register belongs to.
		 */
		virtual void AdjustRegContentsFromRizin(const std::string &tracename, RzBitVector *rizin_val) const;

		/**
		 * \brief Print additional arch-specific info about the register contents to stdout
		 * This can be used for example to expand the individual flag bits of a status register.
		 *
		 * \param tracename Register name in the trace.
		 * \param data The register content.
		 * \param bits_size Size of the register.
		 */
		virtual void PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const;

		/**
		 * Return true here for specific next program counters to accept mismatches as correct.
		 */
		virtual bool IgnorePCMismatch(ut64 pc_actual, ut64 pc_expect) const;

		/**
		 * Return true If a mismatch between the io mem and the memop can be ignored.
		 * The memop still gets checked for justified events.
		 */
		virtual bool IgnoreCompareMemMismatch() const { return false; }

		/**
		 * \brief Returns if a given register name from the trace should be ignored
		 * if it isn't implemented in Rizin.
		 *
		 * \param trace_reg_name The trace register name.
		 * \return true The register, missing in Rizin, should be ignored.
		 * \return false Notify the user about the missing register in Rizin.
		 */
		virtual bool IgnoreUnknownReg(const std::string &trace_reg_name) const;

		/**
		 * \brief Returns true of the Adapter has to setup and comapre the register.
		 * This is useful if a single register from the trace maps to several
		 * registers in Rizin or the other way around.
		 *
		 * \param trace_reg_name The trace register name.
		 *
		 * \return true The register is setup by the adapter.
		 * \return false Default handling for this register.
		 */
		virtual bool RegNeedsCustomHandling(const std::string &trace_reg_name) const { return false; }

		/**
		 * \brief Adapter custom setup of a given trace register.
		 *
		 * \param rz_reg The RzReg instance of Rizin to update.
		 * \param trace_reg_name The trace register name.
		 * \param trace_bv The value of the trace register.
		 */
		virtual void CustomRegSetup(RzReg *rz_reg, const std::string &trace_reg_name, const RzBitVector *trace_bv) const { return; }

		/**
		 * \brief Adapter custom setup of a given trace register.
		 *
		 * \param rz_reg The RzReg instance of Rizin to update.
		 * \param trace_reg_name The trace register name.
		 * \param trace_bv The value of the trace register.
		 * \param mismatch_name The register name in Rizin which doesn't match. NULL if match was successful.
		 * \param mismatch_value The register value in Rizin which doesn't match. NULL if match was successful.
		 *
		 * \return true If the custom comparison matches.
		 * \return false In case of mismatch.
		 */
		virtual bool CustomRegCompare(RzReg *rz_reg, const std::string &trace_reg_name, const RzBitVector *trace_bv, RZ_OUT char **mismatch_name, RZ_OUT char **mismatch_val) { return false; }

		/**
		 * \brief Returns if a post state mismatch
		 * of the given register can be ignored.
		 *
		 * \param rz_reg_name The Rizin register name.
		 * \return true The register mismatch can be ignored.
		 * \return false Mismatch should be logged.
		 */
		virtual bool IgnorePostMismatchReg(const std::string &rz_reg_name) const { return false; }

		/**
		 * \brief Checks if the given even can be ignored during justification checks.
		 * NOTE: This won't ignore found any value mismatches.
		 *
		 * \param event The VM event to check.
		 * \return true If the given event should be treated as justified.
		 * \return false If the given event should be treated as any other event.
		 */
		virtual bool AssumeEventIsJustified(const RzILEvent *event) const { return false; };

		/**
		 * If this returns true, assignments to a variable with the same value as the variable had before
		 * will be justified even if they are not recorded as post operands.
		 */
		virtual bool AllowNoOperandSameValueAssignment() const;

		/**
		 * \brief Get the is big endian flag
		 *
		 * \return true Instruction bytes are in big endian.
		 * \return false Instruction bytes are in little endian.
		 */
		bool IsBigEndian() { return this->big_endian; }

		/**
		 * \brief Set the is big endian flag.
		 *
		 * \param be True if instruction bytes are in big endian. False otherwise.
		 */
		void SetIsBigEndian(bool be) { this->big_endian = be; }

		void SetMachine(uint64_t machine) { this->machine = machine; }

		uint64_t GetMachine() { return this->machine; }

		void SetISA(const std::string &isa) { this->isa = isa; }

	private:
		bool big_endian = false;
		uint64_t machine = 0;
		std::string isa;
};

std::unique_ptr<TraceAdapter> SelectTraceAdapter(frame_architecture arch, size_t mach);

#endif
