
#ifndef _RZEMU_H
#define _RZEMU_H

#include <rz_core.h>

#include <trace.container.hpp>

#include <exception>
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
		FrameCheckResult RunFrame(ut64 index, frame *f);
		const char *RegTraceToRizin(const char *tracereg);
};

#endif