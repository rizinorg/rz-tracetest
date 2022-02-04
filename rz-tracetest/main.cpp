// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rzemu.h"
#include "dump.h"

static int help(bool verbose) {
	printf("Usage: rz-tracetest [-dhiv] [-c count] [-o offset] <filename>.frames\n");
	if (verbose) {
		printf(" -c [count]    number of frames to check, default: all\n");
		printf(" -d            dump trace as text, but do not run or test anything\n");
		printf(" -h            show help message\n");
		printf(" -i            do not print unlifted instructions verbosely\n");
		printf(" -o [offset]   index of the first frame to check, default: 0\n");
		printf(" -v            be more verbose (can be repeated)\n");
	}
	return 1;
}

int main(int argc, const char *argv[]) {
	ut64 count = UT64_MAX;
	ut64 offset = 0;
	bool invalid_op_quiet = false;
	bool dump_only = false;
	int verbose = 0;

	RzGetopt opt;
	rz_getopt_init(&opt, argc, (const char **)argv, "hc:o:idv");
	int c;
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'h':
			return help(true);
		case 'c':
			count = strtoull(opt.arg, NULL, 0);
			break;
		case 'o':
			offset = strtoull(opt.arg, NULL, 0);
			break;
		case 'i':
			invalid_op_quiet = true;
			break;
		case 'd':
			dump_only = true;
			break;
		case 'v':
			verbose++;
			break;
		default:
			return help(false);
		}
	}
	if (opt.ind + 1 != argc) { // expect exactly 1 positional arg
		return help(false);
	}

	SerializedTrace::TraceContainerReader trace(argv[opt.ind]);
	auto adapter = SelectTraceAdapter(trace.get_arch());
	if (dump_only) {
		DumpTrace(trace, offset, count, verbose, adapter.get());
		return 0;
	}
	if (!adapter) {
		throw RizinException("Failed to match frame_architecture %d to TraceAdapter.\n", (int)trace.get_arch());
	}
	RizinEmulator r(std::move(adapter));
	trace.seek(offset);
	ut64 stats[FRAME_CHECK_RESULT_COUNT] = {};
	std::unique_ptr<frame> cur_frame = trace.get_frame();
	while (cur_frame && !rz_cons_is_breaked() && count) {
		std::unique_ptr<frame> next_frame = trace.end_of_trace() ? nullptr : trace.get_frame();
		std::optional<ut64> next_pc = std::nullopt;
		if (next_frame && next_frame->has_std_frame()) {
			next_pc = next_frame->std_frame().address();
		}
		auto res = r.RunFrame(offset++, cur_frame.get(), next_pc, verbose, invalid_op_quiet);
		stats[static_cast<int>(res)]++;
		count--;
		cur_frame = std::move(next_frame);
	}

	printf("\n---------------------------------\n");
	for (int i = 0; i < FRAME_CHECK_RESULT_COUNT; i++) {
		switch (static_cast<FrameCheckResult>(i)) {
		case FrameCheckResult::Success:
			printf("            success: ");
			break;
		case FrameCheckResult::InvalidOp:
			printf("         invalid op: ");
			break;
		case FrameCheckResult::InvalidIL:
			printf("         invalid il: ");
			break;
		case FrameCheckResult::VMRuntimeError:
			printf("   vm runtime error: ");
			break;
		case FrameCheckResult::PostStateMismatch:
			printf("post state mismatch: ");
			break;
		case FrameCheckResult::Unimplemented:
			printf("      unimplemented: ");
			break;
		}
		printf("%" PFMT64u "\n", stats[i]);
	}

	return 0;
}
