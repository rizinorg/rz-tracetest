// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rzemu.h"
#include "dump.h"

#include <regex>

static int help(bool verbose) {
	printf("Usage: rz-tracetest [-dbeurmphivn] [-c count] [-o offset] [-s regex] <filename>.frames\n");
	if (verbose) {
		printf(" -c [count]    number of frames to check, default: all\n");
		printf(" -d            dump trace as text, but do not run or test anything\n");
		printf(" -b            Interpret instruction bytes in the frames in big endian\n");
		printf(" -e            fail early/stop at the first error\n");
		printf(" -u            fail early/stop at the first unlifted execption\n");
		printf(" -r            fail early/stop at the first runtime error\n");
		printf(" -m            fail early/stop at the first execution mismatch\n");
		printf(" -p            prettify IL outputs\n");
		printf(" -n            no io cache reset. Bytes of all frames will be written once and won't be reset for every frame.\n");
		printf(" -h            show help message\n");
		printf(" -i            do not print unlifted instructions verbosely\n");
		printf(" -o [offset]   index of the first frame to check, default: 0\n");
		printf(" -s [regex]    skip every frame whose disassembly string matches the given regex\n");
		printf(" -v            be more verbose (can be repeated)\n");
	}
	return 1;
}

int main(int argc, const char *argv[]) {
	ut64 count = UT64_MAX;
	ut64 offset = 0;
	bool invalid_op_quiet = false;
	bool dump_only = false;
	bool fail_early = false;
	bool fail_unlifted = false;
	bool fail_runtime = false;
	bool fail_misexec = false;
	bool big_endian = false;
	bool prettify_il = false;
	bool cache_reset = true;
	int verbose = 0;
	std::optional<std::regex> skip_re;

	RzGetopt opt;
	rz_getopt_init(&opt, argc, (const char **)argv, "hc:o:idbvs:eurmpn");
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
		case 'b':
			big_endian = true;
			break;
		case 'd':
			dump_only = true;
			break;
		case 'e':
			fail_early = true;
			break;
		case 'u':
			fail_unlifted = true;
			break;
		case 'r':
			fail_runtime = true;
			break;
		case 'm':
			fail_misexec = true;
			break;
		case 'p':
			prettify_il = true;
			break;
		case 'n':
			cache_reset = false;
			break;
		case 's':
			if (skip_re) {
				eprintf("-s can only be specified once. (use |)\n");
				return 1;
			}
			skip_re = std::regex(opt.arg, std::regex_constants::egrep);
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

	std::optional<std::function<bool(const std::string &)>> skip_by_disasm;
	if (skip_re) {
		const std::regex &re = *skip_re;
		skip_by_disasm = [&re](const std::string &disasm) {
			return std::regex_match(disasm, re);
		};
	}

	SerializedTrace::TraceContainerReader trace(argv[opt.ind]);
	auto adapter = SelectTraceAdapter(trace.get_arch());
	if (!adapter) {
		throw RizinException("Failed to match frame_architecture %d to TraceAdapter.\n", (int)trace.get_arch());
	}
	adapter->SetMachine(trace.get_machine());
	adapter.get()->SetIsBigEndian(big_endian);
	if (dump_only) {
		DumpTrace(trace, offset, count, verbose, adapter.get());
		return 0;
	}
	RizinEmulator r(std::move(adapter));
	if (!cache_reset) {
		r.SetMem(trace);
	}
	r.SetPrettyIL(prettify_il);
	trace.seek(offset);
	ut64 stats[FRAME_CHECK_RESULT_COUNT] = {};
	std::unique_ptr<frame> cur_frame = trace.get_frame();

	printf("\nCompare frames...\n");
	ut64 n = trace.get_num_frames();
	ut64 total = 0;
	while (cur_frame && !rz_cons_is_breaked() && count) {
		std::unique_ptr<frame> next_frame = trace.end_of_trace() ? nullptr : trace.get_frame();
		std::optional<ut64> next_pc = std::nullopt;
		if (next_frame && next_frame->has_std_frame()) {
			next_pc = next_frame->std_frame().address();
		}
		auto res = r.RunFrame(offset++, cur_frame.get(), next_pc, verbose, invalid_op_quiet, skip_by_disasm, cache_reset);
		stats[static_cast<int>(res)]++;
		count--;
		total++;
		cur_frame = std::move(next_frame);
		if (fail_early && res != FrameCheckResult::Success && res != FrameCheckResult::Skipped) {
			break;
		}
		if (fail_unlifted && res == FrameCheckResult::InvalidOp) {
			break;
		}
		if (fail_runtime && res == FrameCheckResult::VMRuntimeError) {
			break;
		}
		if (fail_misexec &&
			res == FrameCheckResult::PostStateMismatch) {
			break;
		}
		float done = 100.00f * (float) total / (float) n;
		printf("\rFrames: %llu Done: %5.2f%%", n, done);
	}
	printf("\n");

	printf("\n--------------------------------------\n");
	bool all_succeeded = true;
	for (int i = 0; i < FRAME_CHECK_RESULT_COUNT; i++) {
		if (static_cast<FrameCheckResult>(i) == FrameCheckResult::Success) {
			continue;
		}
		if (stats[i] > 0) {
			all_succeeded = false;
			break;
		}
	}

	for (int i = 0; i < FRAME_CHECK_RESULT_COUNT; i++) {
		switch (static_cast<FrameCheckResult>(i)) {
		case FrameCheckResult::Success:
			printf("              success: ");
			break;
		case FrameCheckResult::Skipped:
			printf("              skipped: ");
			break;
		case FrameCheckResult::InvalidOp:
			printf("             unlifted: ");
			break;
		case FrameCheckResult::InvalidIL:
			printf("           invalid il: ");
			break;
		case FrameCheckResult::VMRuntimeError:
			printf("     vm runtime error: ");
			break;
		case FrameCheckResult::PostStateMismatch:
			printf("          misexecuted: ");
			break;
		case FrameCheckResult::Unimplemented:
			printf("missing trace feature: ");
			break;
		}
		float percent = 100.0f * (float)stats[i] / (float)total;
		if (!all_succeeded && static_cast<FrameCheckResult>(i) == FrameCheckResult::Success && percent > 99.98f) {
			// Never print 100% if a single test failed.
			percent = 99.99f;
		}
		printf("%-7" PFMT64u " %5.2f%%\n", stats[i], percent);
	}

	return 0;
}
