
#include "adapter.h"

#include <memory>

std::string TraceAdapter::RizinCPU() const {
	return std::string();
}

int TraceAdapter::RizinBits() const {
	return 0;
}

std::string TraceAdapter::TraceRegToRizin(const std::string &tracereg) const {
	return tracereg;
}

void TraceAdapter::AdjustRegContents(const std::string &tracename, RzBitVector *trace_val, RzBitVector *rizin_val) const {
}

void TraceAdapter::PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const {
}

class VICETraceAdapter : public TraceAdapter
{
	public:
		std::string RizinArch() const override { return "6502"; }

		std::string TraceRegToRizin(const std::string &tracereg) const override {
			if (tracereg == "sr") {
				return "flags";
			}
			return tracereg;
		}

		void AdjustRegContents(const std::string &tracename, RzBitVector *trace_val, RzBitVector *rizin_val) const override {
			if (tracename == "sr") {
				// mask out the unused and break bits, which rizin does not represent
				rz_bv_set(trace_val, 5, false);
				rz_bv_set(rizin_val, 5, false);
			}
		}

		void PrintRegisterDetails(const std::string &tracename, const std::string &data, size_t bits_size) const override {
			if (tracename == "sr") {
				if (bits_size != 8) {
					return;
				}
				ut8 sr = data[0];
				printf("    0  %#04x  C  = %d\n", 1 << 0, (sr & (1 << 0)) != 0);
				printf("    1  %#04x  Z  = %d\n", 1 << 1, (sr & (1 << 1)) != 0);
				printf("    2  %#04x  I  = %d\n", 1 << 2, (sr & (1 << 2)) != 0);
				printf("    3  %#04x  D  = %d\n", 1 << 3, (sr & (1 << 3)) != 0);
				printf("    4  %#04x (B) = %d\n", 1 << 4, (sr & (1 << 4)) != 0);
				printf("    5  %#04x     = %d\n", 1 << 5, (sr & (1 << 5)) != 0);
				printf("    6  %#04x  V  = %d\n", 1 << 6, (sr & (1 << 6)) != 0);
				printf("    7  %#04x  N  = %d\n", 1 << 7, (sr & (1 << 7)) != 0);
			}
		}
};

std::unique_ptr<TraceAdapter> SelectTraceAdapter(frame_architecture arch) {
	switch (arch) {
		case frame_arch_6502:
			return std::unique_ptr<TraceAdapter>(new VICETraceAdapter());
		default:
			return nullptr;
	}
}
