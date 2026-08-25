// SPDX-FileCopyrightText: 2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "adapter.h"
#include "bitvector_helpers.h"

#include <cassert>
#include <cstdint>
#include <string>

static RzBitVector *M68KExtended96(uint16_t signexp, uint64_t significand,
	bool dirty_padding) {
	RzBitVector *value = rz_bv_new(96);
	assert(value);
	RzBitVectorWriteBitsAt(value, 0, 64, significand);
	RzBitVectorWriteBitsAt(value, 64, 16, dirty_padding ? UINT16_MAX : 0);
	RzBitVectorWriteBitsAt(value, 80, 16, signexp);
	return value;
}

static RzBitVector *Binary80(uint16_t signexp, uint64_t significand) {
	RzBitVector *value = rz_bv_new(80);
	assert(value);
	RzBitVectorWriteBitsAt(value, 0, 64, significand);
	RzBitVectorWriteBitsAt(value, 64, 16, signexp);
	return value;
}

static void TestBitVectorBitsAt() {
	RzBitVector *value = rz_bv_new(80);
	assert(value);

	RzBitVectorWriteBitsAt(value, 80, 0, UINT64_MAX);
	assert(RzBitVectorReadBitsAt(value, 80, 0) == 0);

	RzBitVectorWriteBitsAt(value, 79, 1, 1);
	assert(RzBitVectorReadBitsAt(value, 79, 1) == 1);
	RzBitVectorWriteBitsAt(value, 79, 1, 0);
	assert(RzBitVectorReadBitsAt(value, 79, 1) == 0);

	RzBitVectorWriteBitsAt(value, 17, 16, UINT16_C(0xa55a));
	assert(RzBitVectorReadBitsAt(value, 17, 16) == UINT16_C(0xa55a));

	const uint64_t pattern = UINT64_C(0x0123456789abcdef);
	RzBitVectorWriteBitsAt(value, 8, 64, pattern);
	assert(RzBitVectorReadBitsAt(value, 8, 64) == pattern);

	rz_bv_free(value);
}

static void TestMachines() {
	struct MachineCase {
			size_t machine;
			const char *cpu;
	};
	static const MachineCase machines[] = {
		{ frame_mach_m68000, "68000" },
		{ frame_mach_m68010, "68010" },
		{ frame_mach_m68020, "68020" },
		{ frame_mach_m68030, "68030" },
		{ frame_mach_m68040, "68040" },
		{ frame_mach_m68060, "68060" },
		{ frame_mach_mcf_isa_a, "cfv2" },
		{ frame_mach_mcf_isa_aplus_emac, "cfv2" },
		{ frame_mach_mcf_isa_b_float_emac, "cfv4e" },
	};

	for (const MachineCase &machine : machines) {
		auto adapter = SelectTraceAdapter(frame_arch_m68k, machine.machine);
		assert(adapter);
		assert(adapter->RizinArch() == "m68k");
		assert(adapter->RizinCPU() == machine.cpu);
		assert(adapter->RizinHaltOnExceptions() == "none");
		assert(adapter->RizinBits(std::nullopt, machine.machine) == 32);
		assert(adapter->IsBigEndian());
		assert(adapter->TraceRegToRizin("fp") == "a6");
		assert(adapter->TraceRegToRizin("sp") == "a7");
		assert(adapter->TraceRegToRizin("ps") == "sr");
		assert(adapter->TraceRegToRizin("fpcontrol") == "fpcr");
		assert(adapter->TraceRegToRizin("fpstatus") == "fpsr");
		assert(adapter->TraceRegToRizin("fpiaddr") == "fpiar");
		assert(adapter->TraceRegToRizin("D3") == "d3");
		assert(adapter->RegNeedsCustomHandling("fp0"));
		assert(adapter->RegNeedsCustomHandling("fp7"));
		assert(!adapter->RegNeedsCustomHandling("fp"));
		assert(adapter->AllowNoOperandSameValueAssignment());
	}

	assert(!SelectTraceAdapter(frame_arch_m68k, 0));
	assert(!SelectTraceAdapter(frame_arch_m68k, frame_mach_m68008));
	assert(!SelectTraceAdapter(frame_arch_m68k, frame_mach_cpu32));

	auto adapter = SelectTraceAdapter(frame_arch_m68k, frame_mach_m68020);
	RzBitVector *ps = rz_bv_new_from_ut64(32, 0xabcd1234);
	adapter->AdjustRegContentsFromTrace("ps", ps);
	assert(rz_bv_len(ps) == 16);
	assert(rz_bv_to_ut16(ps) == 0x1234);
	rz_bv_free(ps);
}

static void TestFloatConversions() {
	struct FloatCase {
			uint16_t signexp;
			uint64_t significand;
			uint64_t normalized_significand;
	};
	static const FloatCase values[] = {
		{ 0x0000, 0x0000000000000000ULL, 0x0000000000000000ULL }, // +0
		{ 0x8000, 0x0000000000000000ULL, 0x0000000000000000ULL }, // -0
		{ 0x4000, 0x8000000000000000ULL, 0x8000000000000000ULL }, // finite
		{ 0x7fff, 0x8000000000000000ULL, 0x8000000000000000ULL }, // +infinity
		{ 0xffff, 0x8000000000000000ULL, 0x8000000000000000ULL }, // -infinity
		{ 0x7fff, 0x0000000000000000ULL, 0x8000000000000000ULL }, // +pseudo-infinity
		{ 0x7fff, 0xc000000000000001ULL, 0xc000000000000001ULL }, // qNaN
	};

	for (const FloatCase &value : values) {
		RzBitVector *qemu = M68KExtended96(value.signexp, value.significand, true);
		RzBitVector *rizin = RzBitVectorBinary80FromM68KExtended96(qemu);
		assert(rizin);
		assert(rz_bv_len(rizin) == 80);
		assert(rz_bv_to_ut64(rizin) == value.normalized_significand);
		assert(RzBitVectorReadBitsAt(rizin, 64, 16) == value.signexp);

		RzBitVector *roundtrip = RzBitVectorM68KExtended96FromBinary80(rizin);
		assert(roundtrip);
		assert(rz_bv_len(roundtrip) == 96);
		assert(rz_bv_to_ut64(roundtrip) == value.normalized_significand);
		assert(RzBitVectorReadBitsAt(roundtrip, 80, 16) == value.signexp);
		assert(RzBitVectorReadBitsAt(roundtrip, 64, 16) == 0);

		rz_bv_free(roundtrip);
		rz_bv_free(rizin);
		rz_bv_free(qemu);
	}
	assert(!M68KQemuFPRegisterToRizin(nullptr));
	assert(!M68KRizinFPRegisterToQemu(nullptr));
	RzBitVector *invalid = rz_bv_new(80);
	assert(!M68KRizinFPRegisterToQemu(invalid, 32));
	rz_bv_free(invalid);
}

static void TestFloatEventEquivalence() {
	auto adapter = SelectTraceAdapter(frame_arch_m68k, frame_mach_m68040);
	RzBitVector *qemu_payload = M68KExtended96(0x7fff, UINT64_C(0xffffffffffffffff), false);
	RzBitVector *qemu_canonical = M68KExtended96(0x7fff, UINT64_C(0xc000000000000001), false);
	RzBitVector *payload = M68KQemuFPRegisterToRizin(qemu_payload);
	RzBitVector *canonical = M68KQemuFPRegisterToRizin(qemu_canonical);
	RzFloat *old_float = RZ_NEW0(RzFloat);
	RzFloat *new_float = RZ_NEW0(RzFloat);
	assert(old_float && new_float);
	old_float->r = RZ_FLOAT_IEEE754_BIN_80;
	old_float->s = rz_bv_dup(payload);
	new_float->r = RZ_FLOAT_IEEE754_BIN_80;
	new_float->s = rz_bv_dup(canonical);
	RzILVal *old_value = rz_il_value_new_float(old_float);
	RzILVal *new_value = rz_il_value_new_float(new_float);
	RzILEvent *event = rz_il_event_var_write_new("fp2", old_value, new_value);
	assert(!adapter->AssumeEventIsJustified(event));
	rz_il_event_free(event);
	rz_il_value_free(new_value);
	rz_il_value_free(old_value);
	old_value = rz_il_value_new_bitv(rz_bv_dup(payload));
	new_value = rz_il_value_new_bitv(rz_bv_dup(canonical));
	event = rz_il_event_var_write_new("fp2", old_value, new_value);
	assert(!adapter->AssumeEventIsJustified(event));
	rz_il_event_free(event);
	rz_il_value_free(new_value);
	rz_il_value_free(old_value);
	rz_bv_free(canonical);
	rz_bv_free(payload);
	rz_bv_free(qemu_canonical);
	rz_bv_free(qemu_payload);
}

static void TestDoubleConversions() {
	static const uint64_t values[] = {
		UINT64_C(0x0000000000000000), // +0
		UINT64_C(0x8000000000000000), // -0
		UINT64_C(0x0000000000000001), // minimum subnormal
		UINT64_C(0x000fffffffffffff), // maximum subnormal
		UINT64_C(0x0010000000000000), // minimum normal
		UINT64_C(0x3ff0000000000000), // 1.0
		UINT64_C(0xc000000000000000), // -2.0
		UINT64_C(0x7fefffffffffffff), // maximum finite
		UINT64_C(0x7ff0000000000000), // +infinity
		UINT64_C(0xfff0000000000000), // -infinity
		UINT64_C(0x7ff8000000000001), // qNaN with payload
	};

	for (uint64_t value : values) {
		RzBitVector *qemu = rz_bv_new_from_ut64(64, value);
		RzBitVector *rizin = RzBitVectorBinary80FromBinary64(qemu);
		assert(rizin);
		assert(rz_bv_len(rizin) == 80);
		RzBitVector *roundtrip = RzBitVectorBinary64FromBinary80(rizin);
		assert(roundtrip);
		assert(rz_bv_len(roundtrip) == 64);
		assert(rz_bv_to_ut64(roundtrip) == value);
		rz_bv_free(roundtrip);
		rz_bv_free(rizin);
		rz_bv_free(qemu);
	}

	RzBitVector *one = rz_bv_new_from_ut64(64, UINT64_C(0x3ff0000000000000));
	RzBitVector *extended_one = M68KQemuFPRegisterToRizin(one);
	assert(RzBitVectorReadBitsAt(extended_one, 64, 16) == 0x3fff);
	assert(rz_bv_to_ut64(extended_one) == UINT64_C(0x8000000000000000));
	rz_bv_free(extended_one);
	rz_bv_free(one);
}

static void TestQemuSoftFloatRegisterOracle() {
	// These bit results come from QEMU 1f5dd528 target/m68k/helper.c using
	// float64_to_floatx80 / floatx80_to_float64 with the M68K fp_status from
	// target/m68k/cpu.c. The GDB path uses a scratch status, so exception flags
	// are deliberately not part of the trace ABI. Rizin canonicalizes the
	// explicit integer bit of infinity after the QEMU conversion.
	struct FromBinary64Case {
			uint64_t binary64;
			uint16_t signexp;
			uint64_t significand;
	};
	static const FromBinary64Case from_binary64[] = {
		{ UINT64_C(0x7ff8000000000001), 0x7fff, UINT64_C(0xc000000000000800) }, // qNaN payload
		{ UINT64_C(0x7fffffffffffffff), 0x7fff, UINT64_C(0xfffffffffffff800) }, // maximum qNaN payload
		{ UINT64_C(0xfff8000000000001), 0xffff, UINT64_C(0xc000000000000800) }, // negative qNaN
		{ UINT64_C(0x7ff0000000000001), 0x7fff, UINT64_C(0xc000000000000800) }, // sNaN quieted
		{ UINT64_C(0x7ff0000000000000), 0x7fff, UINT64_C(0x8000000000000000) }, // canonicalized infinity
		{ UINT64_C(0x0000000000000001), 0x3bcd, UINT64_C(0x8000000000000000) }, // minimum subnormal
		{ UINT64_C(0x000fffffffffffff), 0x3c00, UINT64_C(0xfffffffffffff000) }, // maximum subnormal
		{ UINT64_C(0x7fefffffffffffff), 0x43fe, UINT64_C(0xfffffffffffff800) }, // maximum finite
	};
	for (const FromBinary64Case &test : from_binary64) {
		RzBitVector *qemu = rz_bv_new_from_ut64(64, test.binary64);
		RzBitVector *rizin = RzBitVectorBinary80FromBinary64(qemu);
		assert(rizin);
		assert(RzBitVectorReadBitsAt(rizin, 64, 16) == test.signexp);
		assert(rz_bv_to_ut64(rizin) == test.significand);
		rz_bv_free(rizin);
		rz_bv_free(qemu);
	}

	struct ToBinary64Case {
			uint16_t signexp;
			uint64_t significand;
			uint64_t binary64;
	};
	static const ToBinary64Case to_binary64[] = {
		{ 0x7fff, UINT64_C(0xc000000000000800), UINT64_C(0x7ff8000000000001) }, // qNaN payload
		{ 0xffff, UINT64_C(0xc000000000000800), UINT64_C(0xfff8000000000001) }, // negative qNaN
		{ 0x7fff, UINT64_C(0x8000000000000800), UINT64_C(0x7ff8000000000001) }, // sNaN quieted
		{ 0x7fff, UINT64_C(0x8000000000000000), UINT64_C(0x7ff0000000000000) }, // canonical infinity
		{ 0x7fff, UINT64_C(0x0000000000000000), UINT64_C(0x7ff0000000000000) }, // pseudo-infinity
		{ 0x3fff, UINT64_C(0x8000000000000400), UINT64_C(0x3ff0000000000000) }, // exact half, even down
		{ 0x3fff, UINT64_C(0x8000000000000401), UINT64_C(0x3ff0000000000001) }, // above half
		{ 0x3fff, UINT64_C(0x8000000000000c00), UINT64_C(0x3ff0000000000002) }, // exact half, odd up
		{ 0x0000, UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000) }, // underflows to zero
	};
	for (const ToBinary64Case &test : to_binary64) {
		RzBitVector *rizin = Binary80(test.signexp, test.significand);
		RzBitVector *qemu = RzBitVectorBinary64FromBinary80(rizin);
		assert(qemu);
		assert(rz_bv_to_ut64(qemu) == test.binary64);
		rz_bv_free(qemu);
		rz_bv_free(rizin);
	}

	RzBitVector *snan = Binary80(0x7fff, UINT64_C(0x8000000000000800));
	RzBitVector *qnan = Binary80(0x7fff, UINT64_C(0xc000000000000800));
	assert(M68KRizinFloatsEquivalent(snan, qnan, 64));
	assert(!M68KRizinFloatsEquivalent(snan, qnan, 96));
	rz_bv_free(qnan);
	rz_bv_free(snan);
}

static void TestNaNEquivalence() {
	RzBitVector *qemu_payload = M68KExtended96(0x7fff, UINT64_C(0xffffffffffffffff), false);
	RzBitVector *qemu_canonical = M68KExtended96(0x7fff, UINT64_C(0x8000000000000001), false);
	RzBitVector *qemu_negative = M68KExtended96(0xffff, UINT64_C(0x8000000000000001), false);
	RzBitVector *qemu_infinity = M68KExtended96(0x7fff, UINT64_C(0x8000000000000000), false);
	RzBitVector *payload = M68KQemuFPRegisterToRizin(qemu_payload);
	RzBitVector *canonical = M68KQemuFPRegisterToRizin(qemu_canonical);
	RzBitVector *negative = M68KQemuFPRegisterToRizin(qemu_negative);
	RzBitVector *infinity = M68KQemuFPRegisterToRizin(qemu_infinity);
	assert(!M68KRizinFloatsEquivalent(payload, canonical, 96));
	assert(M68KRizinFloatsEquivalent(payload, payload, 96));
	assert(!M68KRizinFloatsEquivalent(canonical, negative, 96));
	assert(!M68KRizinFloatsEquivalent(payload, infinity, 96));
	assert(!M68KRizinFloatsEquivalent(nullptr, canonical, 96));
	rz_bv_free(infinity);
	rz_bv_free(negative);
	rz_bv_free(canonical);
	rz_bv_free(payload);
	rz_bv_free(qemu_infinity);
	rz_bv_free(qemu_negative);
	rz_bv_free(qemu_canonical);
	rz_bv_free(qemu_payload);
}

int main() {
	TestBitVectorBitsAt();
	TestMachines();
	TestFloatConversions();
	TestDoubleConversions();
	TestQemuSoftFloatRegisterOracle();
	TestNaNEquivalence();
	TestFloatEventEquivalence();
	return 0;
}
