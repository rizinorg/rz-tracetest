
#include "rzemu.h"

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
		auto res = r.RunFrame(offset++, trace.get_frame().get());
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
