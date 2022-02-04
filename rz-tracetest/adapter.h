// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _TRACEADAPTER_H
#define _TRACEADAPTER_H

#include <trace.container.hpp>

#include <rz_util.h>

#include <string>

/*
 * Interface for any arch/source/... specific adjustments
 */
class TraceAdapter
{
	public:
		virtual ~TraceAdapter() {}

		/**
		 * value for asm.arch/analysis.arch
		 */
		virtual std::string RizinArch() const =0;

		/**
		 * value for asm.cpu
		 */
		virtual std::string RizinCPU() const;

		/**
		 * value for asm.bits
		 */
		virtual int RizinBits() const;

		/**
		 * Get the name of the register in RzReg for a reg name given by the trace.
		 * May return an empty string to indicate that the trace register does not exist in rizin and should be ignored.
		 */
		virtual std::string TraceRegToRizin(const std::string &tracereg) const;

		/**
		 * Edit the contents of a register from the trace or RzReg before comparison
		 * This is useful e.g. for masking out information that is unsupported by the other side.
		 */
		virtual void AdjustRegContents(const std::string &tracename, RzBitVector *trace_val, RzBitVector *rizin_val) const;

		/**
		 * Print additional arch-specific info about the register contents to stdout
		 * This can be used for example to expand the individual flag bits of a status register.
		 */
		virtual void PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const;
};

std::unique_ptr<TraceAdapter> SelectTraceAdapter(frame_architecture arch);

#endif
