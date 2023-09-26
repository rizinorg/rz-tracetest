// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _TRACEADAPTER_H
#define _TRACEADAPTER_H

#include <trace.container.hpp>

#include <rz_util.h>
#include <rz_analysis.h>

#include <string>
#include <optional>

// Mask to exclude ISA3 flags (ca32, ov32).
#define PPC_XER_ISA2_BITS_MASK 0xfffffffffff3ffff

/*
 * Interface for any arch/source/... specific adjustments
 */
class TraceAdapter {
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
		virtual void AdjustRegContentsFromTrace(const std::string &tracename, RzBitVector *trace_val, RzBitVector *extra_info, RzAnalysisOp *op = nullptr) const;

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
		 * \brief Returns if a given register name from the trace should be ignored if it isn't implemented in Rizin.
		 *
		 * \param rz_reg_name The trace register name.
		 * \return true The register, missing in Rizin, should be ignored.
		 * \return false Notify the user about the missing register in Rizin.
		 */
		virtual bool IgnoreUnknownReg(const std::string &rz_reg_name) const;

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

	private:
		bool big_endian = false;
		uint64_t machine = 0;
};

std::unique_ptr<TraceAdapter> SelectTraceAdapter(frame_architecture arch);

#endif
