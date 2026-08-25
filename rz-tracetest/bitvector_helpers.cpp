// SPDX-FileCopyrightText: 2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bitvector_helpers.h"

#include <rz_util.h>

uint64_t RzBitVectorReadBitsAt(const RzBitVector *value, size_t offset, size_t bits) {
	rz_return_val_if_fail(value && bits <= 64, 0);
	const size_t length = rz_bv_len(value);
	rz_return_val_if_fail(offset <= length && bits <= length - offset, 0);
	uint64_t result = 0;
	for (size_t i = 0; i < bits; i++) {
		if (rz_bv_get(value, offset + i)) {
			result |= UINT64_C(1) << i;
		}
	}
	return result;
}

void RzBitVectorWriteBitsAt(RzBitVector *value, size_t offset, size_t bits, uint64_t data) {
	rz_return_if_fail(value && bits <= 64);
	const size_t length = rz_bv_len(value);
	rz_return_if_fail(offset <= length && bits <= length - offset);
	for (size_t i = 0; i < bits; i++) {
		rz_bv_set(value, offset + i, (data >> i) & 1U);
	}
}

static unsigned Uint64HighestSetBit(uint64_t value) {
	unsigned bit = 0;
	while (value >>= 1U) {
		bit++;
	}
	return bit;
}

static uint64_t Uint64RoundShiftRightToEven(uint64_t value, unsigned shift) {
	if (!shift) {
		return value;
	}
	if (shift > 64) {
		return 0;
	}
	if (shift == 64) {
		const uint64_t half = UINT64_C(1) << 63;
		return value > half ? 1 : 0;
	}
	const uint64_t quotient = value >> shift;
	const uint64_t remainder = value & ((UINT64_C(1) << shift) - 1);
	const uint64_t half = UINT64_C(1) << (shift - 1);
	return quotient + (remainder > half || (remainder == half && (quotient & 1)));
}

RzBitVector *RzBitVectorBinary80FromBinary64(const RzBitVector *binary64_value) {
	rz_return_val_if_fail(binary64_value && rz_bv_len(binary64_value) == 64, nullptr);
	const uint64_t binary = RzBitVectorReadBitsAt(binary64_value, 0, 64);
	const uint16_t sign = static_cast<uint16_t>(binary >> 63);
	const uint16_t exponent = static_cast<uint16_t>((binary >> 52) & 0x7ff);
	const uint64_t fraction = binary & UINT64_C(0x000fffffffffffff);
	uint16_t signexp = static_cast<uint16_t>(sign << 15);
	uint64_t significand = 0;

	if (exponent == 0x7ff) {
		signexp |= 0x7fff;
		if (fraction) {
			const uint64_t quiet_fraction = fraction | (UINT64_C(1) << 51);
			significand = UINT64_C(0x8000000000000000) | (quiet_fraction << 11);
		} else {
			significand = UINT64_C(0x8000000000000000);
		}
	} else if (exponent) {
		signexp |= static_cast<uint16_t>(exponent - 1023 + 16383);
		significand = UINT64_C(0x8000000000000000) | (fraction << 11);
	} else if (fraction) {
		const unsigned top = Uint64HighestSetBit(fraction);
		const int unbiased = static_cast<int>(top) - 1074;
		signexp |= static_cast<uint16_t>(unbiased + 16383);
		significand = fraction << (63 - top);
	}

	RzBitVector *binary80_value = rz_bv_new(80);
	if (!binary80_value) {
		return nullptr;
	}
	RzBitVectorWriteBitsAt(binary80_value, 0, 64, significand);
	RzBitVectorWriteBitsAt(binary80_value, 64, 16, signexp);
	return binary80_value;
}

RzBitVector *RzBitVectorBinary64FromBinary80(const RzBitVector *binary80_value) {
	rz_return_val_if_fail(binary80_value && rz_bv_len(binary80_value) == 80, nullptr);
	const uint16_t signexp = static_cast<uint16_t>(RzBitVectorReadBitsAt(binary80_value, 64, 16));
	const uint64_t significand = RzBitVectorReadBitsAt(binary80_value, 0, 64);
	const uint64_t sign = static_cast<uint64_t>(signexp >> 15) << 63;
	const uint16_t exponent = signexp & 0x7fff;
	uint64_t binary = sign;

	if (exponent == 0x7fff) {
		const uint64_t payload = significand & UINT64_C(0x7fffffffffffffff);
		binary |= UINT64_C(0x7ff0000000000000);
		if (payload) {
			const uint64_t fraction = (payload >> 11) | (UINT64_C(1) << 51);
			binary |= fraction;
		}
	} else if (significand) {
		const unsigned top = Uint64HighestSetBit(significand);
		const int base_exponent = (exponent ? static_cast<int>(exponent) - 16383 : 1 - 16383) - 63;
		int unbiased = base_exponent + static_cast<int>(top);
		if (unbiased > 1023) {
			binary |= UINT64_C(0x7ff0000000000000);
		} else if (unbiased >= -1022) {
			uint64_t rounded = top > 52
				? Uint64RoundShiftRightToEven(significand, top - 52)
				: significand << (52 - top);
			if (rounded == (UINT64_C(1) << 53)) {
				rounded >>= 1;
				unbiased++;
			}
			if (unbiased > 1023) {
				binary |= UINT64_C(0x7ff0000000000000);
			} else {
				binary |= static_cast<uint64_t>(unbiased + 1023) << 52;
				binary |= rounded & UINT64_C(0x000fffffffffffff);
			}
		} else {
			const int scale = base_exponent + 1074;
			const uint64_t fraction = scale >= 0
				? significand << static_cast<unsigned>(scale)
				: Uint64RoundShiftRightToEven(significand, static_cast<unsigned>(-scale));
			if (fraction >= (UINT64_C(1) << 52)) {
				binary |= UINT64_C(1) << 52;
			} else {
				binary |= fraction;
			}
		}
	}

	return rz_bv_new_from_ut64(64, binary);
}

RzBitVector *RzBitVectorBinary80FromM68KExtended96(const RzBitVector *extended96_value) {
	rz_return_val_if_fail(extended96_value && rz_bv_len(extended96_value) == 96, nullptr);
	RzBitVector *binary80_value = rz_bv_new(80);
	if (!binary80_value) {
		return nullptr;
	}
	uint64_t significand = RzBitVectorReadBitsAt(extended96_value, 0, 64);
	const uint16_t signexp = static_cast<uint16_t>(RzBitVectorReadBitsAt(extended96_value, 80, 16));
	if ((signexp & 0x7fff) == 0x7fff && (significand << 1) == 0) {
		significand = UINT64_C(0x8000000000000000);
	}
	RzBitVectorWriteBitsAt(binary80_value, 0, 64, significand);
	RzBitVectorWriteBitsAt(binary80_value, 64, 16, signexp);
	return binary80_value;
}

RzBitVector *RzBitVectorM68KExtended96FromBinary80(const RzBitVector *binary80_value) {
	rz_return_val_if_fail(binary80_value && rz_bv_len(binary80_value) == 80, nullptr);
	RzBitVector *extended96_value = rz_bv_new(96);
	if (!extended96_value) {
		return nullptr;
	}
	RzBitVectorWriteBitsAt(extended96_value, 0, 64, RzBitVectorReadBitsAt(binary80_value, 0, 64));
	RzBitVectorWriteBitsAt(extended96_value, 80, 16, RzBitVectorReadBitsAt(binary80_value, 64, 16));
	return extended96_value;
}
