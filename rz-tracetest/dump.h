// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _DUMP_H
#define _DUMP_H

#include <trace.container.hpp>
#include <rz_util.h>

void DumpTrace(SerializedTrace::TraceContainerReader &trace, ut64 offset, ut64 count);
void DumpOperandList(const char *prefix, const operand_value_list &operands, std::function<void(const operand_info &, size_t)> print_detail);

#endif
