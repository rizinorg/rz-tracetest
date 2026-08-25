// SPDX-FileCopyrightText: 2026 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TRACETEST_BITVECTOR_HELPERS_H
#define RZ_TRACETEST_BITVECTOR_HELPERS_H

#include <cstddef>
#include <cstdint>
#include <rz_util/rz_bitvector.h>

uint64_t RzBitVectorReadBitsAt(const RzBitVector *value, size_t offset, size_t bits);
void RzBitVectorWriteBitsAt(RzBitVector *value, size_t offset, size_t bits, uint64_t data);
RzBitVector *RzBitVectorBinary80FromBinary64(const RzBitVector *binary64_value);
RzBitVector *RzBitVectorBinary64FromBinary80(const RzBitVector *binary80_value);
RzBitVector *RzBitVectorBinary80FromM68KExtended96(const RzBitVector *extended96_value);
RzBitVector *RzBitVectorM68KExtended96FromBinary80(const RzBitVector *binary80_value);

#endif // RZ_TRACETEST_BITVECTOR_HELPERS_H
