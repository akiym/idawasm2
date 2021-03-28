import wasm
import wasm.decode
import wasm.wasmtypes

# decoded from VarInt7
WASM_TYPE_I32 = -1
WASM_TYPE_I64 = -2
WASM_TYPE_F32 = -3
WASM_TYPE_F64 = -4
WASM_TYPE_ANYFUNC = -0x10
WASM_TYPE_FUNC = -0x20
WASM_TYPE_EMPTY2 = -0x40
# TODO(wb): check
WASM_TYPE_EMPTY = 0xFFFFFFC0

WASM_TYPE_NAMES = {
    WASM_TYPE_I32: 'i32',
    WASM_TYPE_I64: 'i64',
    WASM_TYPE_F32: 'f32',
    WASM_TYPE_F64: 'f64',
    WASM_TYPE_ANYFUNC: 'anyfunc',
    WASM_TYPE_FUNC: 'func',
    WASM_TYPE_EMPTY: 'empty',
}

WASM_SECTION_NAMES = {
    wasm.wasmtypes.SEC_TYPE: 'types',
    wasm.wasmtypes.SEC_IMPORT: 'imports',
    wasm.wasmtypes.SEC_FUNCTION: 'functions',
    wasm.wasmtypes.SEC_TABLE: 'tables',
    wasm.wasmtypes.SEC_MEMORY: 'memory',
    wasm.wasmtypes.SEC_GLOBAL: 'globals',
    wasm.wasmtypes.SEC_EXPORT: 'exports',
    wasm.wasmtypes.SEC_START: 'starts',
    wasm.wasmtypes.SEC_ELEMENT: 'elements',
    wasm.wasmtypes.SEC_CODE: 'code',
    wasm.wasmtypes.SEC_DATA: 'data',
}

# via: https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md#external_kind
WASM_EXTERNAL_KIND_FUNCTION = 0
WASM_EXTERNAL_KIND_TABLE = 1
WASM_EXTERNAL_KIND_MEMORY = 2
WASM_EXTERNAL_KIND_GLOBAL = 3

WASM_OPCODE_DESCRIPTIONS = {
    wasm.OP_BLOCK: 'begin a sequence of expressions, yielding 0 or 1 values',
    wasm.OP_BR: 'break that targets an outer nested block',
    wasm.OP_BR_IF: 'conditional break that targets an outer nested block',
    wasm.OP_BR_TABLE: 'branch table control flow construct',
    wasm.OP_CALL: 'call a function by its index',
    wasm.OP_CALL_INDIRECT: 'call a function indirect with an expected signature',
    wasm.OP_CURRENT_MEMORY: 'query the size of memory',
    wasm.OP_DROP: 'ignore value',
    wasm.OP_ELSE: 'begin else expression of if',
    wasm.OP_END: 'end a block, loop, or if',
    wasm.OP_F32_ABS: 'absolute value',
    wasm.OP_F32_ADD: 'addition',
    wasm.OP_F32_CEIL: 'ceiling operator',
    wasm.OP_F32_CONST: 'a constant value interpreted as f32',
    wasm.OP_F32_CONVERT_S_I32: 'convert a signed 32-bit integer to a 32-bit float',
    wasm.OP_F32_CONVERT_S_I64: 'convert a signed 64-bit integer to a 32-bit float',
    wasm.OP_F32_CONVERT_U_I32: 'convert an unsigned 32-bit integer to a 32-bit float',
    wasm.OP_F32_CONVERT_U_I64: 'convert an unsigned 64-bit integer to a 32-bit float',
    wasm.OP_F32_COPYSIGN: 'copysign',
    wasm.OP_F32_DEMOTE_F64: 'demote a 64-bit float to a 32-bit float',
    wasm.OP_F32_DIV: 'division',
    wasm.OP_F32_EQ: 'compare ordered and equal',
    wasm.OP_F32_FLOOR: 'floor operator',
    wasm.OP_F32_GE: 'compare ordered and greater than or equal',
    wasm.OP_F32_GT: 'compare ordered and greater than',
    wasm.OP_F32_LE: 'compare ordered and less than or equal',
    wasm.OP_F32_LOAD: 'load from memory',
    wasm.OP_F32_LT: 'compare ordered and less than',
    wasm.OP_F32_MAX: 'maximum (binary operator); if either operand is NaN, returns NaN',
    wasm.OP_F32_MIN: 'minimum (binary operator); if either operand is NaN, returns NaN',
    wasm.OP_F32_MUL: 'multiplication',
    wasm.OP_F32_NE: 'compare unordered or unequal',
    wasm.OP_F32_NEAREST: 'round to nearest integer, ties to even',
    wasm.OP_F32_NEG: 'negation',
    wasm.OP_F32_REINTERPRET_I32: 'reinterpret the bits of a 32-bit integer as a 32-bit float',
    wasm.OP_F32_SQRT: 'square root',
    wasm.OP_F32_STORE: 'store to memory',
    wasm.OP_F32_SUB: 'subtraction',
    wasm.OP_F32_TRUNC: 'round to nearest integer towards zero',
    wasm.OP_F64_ABS: 'absolute value',
    wasm.OP_F64_ADD: 'addition',
    wasm.OP_F64_CEIL: 'ceiling operator',
    wasm.OP_F64_CONST: 'a constant value interpreted as f64',
    wasm.OP_F64_CONVERT_S_I32: 'convert a signed 32-bit integer to a 64-bit float',
    wasm.OP_F64_CONVERT_S_I64: 'convert a signed 64-bit integer to a 64-bit float',
    wasm.OP_F64_CONVERT_U_I32: 'convert an unsigned 32-bit integer to a 64-bit float',
    wasm.OP_F64_CONVERT_U_I64: 'convert an unsigned 64-bit integer to a 64-bit float',
    wasm.OP_F64_COPYSIGN: 'copysign',
    wasm.OP_F64_DIV: 'division',
    wasm.OP_F64_EQ: 'compare ordered and equal',
    wasm.OP_F64_FLOOR: 'floor operator',
    wasm.OP_F64_GE: 'compare ordered and greater than or equal',
    wasm.OP_F64_GT: 'compare ordered and greater than',
    wasm.OP_F64_LE: 'compare ordered and less than or equal',
    wasm.OP_F64_LOAD: 'load from memory',
    wasm.OP_F64_LT: 'compare ordered and less than',
    wasm.OP_F64_MAX: 'maximum (binary operator); if either operand is NaN, returns NaN',
    wasm.OP_F64_MIN: 'minimum (binary operator); if either operand is NaN, returns NaN',
    wasm.OP_F64_MUL: 'multiplication',
    wasm.OP_F64_NE: 'compare unordered or unequal',
    wasm.OP_F64_NEAREST: 'round to nearest integer, ties to even',
    wasm.OP_F64_NEG: 'negation',
    wasm.OP_F64_PROMOTE_F32: 'promote a 32-bit float to a 64-bit float',
    wasm.OP_F64_REINTERPRET_I64: 'reinterpret the bits of a 64-bit integer as a 64-bit float',
    wasm.OP_F64_SQRT: 'square root',
    wasm.OP_F64_STORE: 'store to memory',
    wasm.OP_F64_SUB: 'subtraction',
    wasm.OP_F64_TRUNC: 'round to nearest integer towards zero',
    wasm.OP_GET_GLOBAL: 'read a global variable',
    wasm.OP_GET_LOCAL: 'read a local variable or parameter',
    wasm.OP_GROW_MEMORY: 'grow the size of memory',
    wasm.OP_I32_ADD: 'sign-agnostic addition',
    wasm.OP_I32_AND: 'sign-agnostic bitwise and',
    wasm.OP_I32_CLZ: 'sign-agnostic count leading zero bits',
    wasm.OP_I32_CONST: 'a constant value interpreted as i32',
    wasm.OP_I32_CTZ: 'sign-agnostic count trailing zero bits',
    wasm.OP_I32_DIV_S: 'signed division (result is truncated toward zero)',
    wasm.OP_I32_DIV_U: 'unsigned division (result is floored)',
    wasm.OP_I32_EQ: 'sign-agnostic compare equal',
    wasm.OP_I32_EQZ: 'compare equal to zero (return 1 if operand is zero, 0 otherwise)',
    wasm.OP_I32_GE_S: 'signed greater than or equal',
    wasm.OP_I32_GE_U: 'unsigned greater than or equal',
    wasm.OP_I32_GT_S: 'signed greater than',
    wasm.OP_I32_GT_U: 'unsigned greater than',
    wasm.OP_I32_LE_S: 'signed less than or equal',
    wasm.OP_I32_LE_U: 'unsigned less than or equal',
    wasm.OP_I32_LOAD16_S: 'load from memory',
    wasm.OP_I32_LOAD16_U: 'load from memory',
    wasm.OP_I32_LOAD8_S: 'load from memory',
    wasm.OP_I32_LOAD8_U: 'load from memory',
    wasm.OP_I32_LOAD: 'load from memory',
    wasm.OP_I32_LT_S: 'signed less than',
    wasm.OP_I32_LT_U: 'unsigned less than',
    wasm.OP_I32_MUL: 'sign-agnostic multiplication (lower 32-bits)',
    wasm.OP_I32_NE: 'sign-agnostic compare unequal',
    wasm.OP_I32_OR: 'sign-agnostic bitwise inclusive or',
    wasm.OP_I32_POPCNT: 'sign-agnostic count number of one bits',
    wasm.OP_I32_REINTERPRET_F32: 'reinterpret the bits of a 32-bit float as a 32-bit integer',
    wasm.OP_I32_REM_S: 'signed remainder (result has the sign of the dividend)',
    wasm.OP_I32_REM_U: 'unsigned remainder',
    wasm.OP_I32_ROTL: 'sign-agnostic rotate left',
    wasm.OP_I32_ROTR: 'sign-agnostic rotate right',
    wasm.OP_I32_SHL: 'sign-agnostic shift left',
    wasm.OP_I32_SHR_S: 'sign-replicating (arithmetic) shift right',
    wasm.OP_I32_SHR_U: 'zero-replicating (logical) shift right',
    wasm.OP_I32_STORE16: 'store to memory',
    wasm.OP_I32_STORE8: 'store to memory',
    wasm.OP_I32_STORE: 'store to memory',
    wasm.OP_I32_SUB: 'sign-agnostic subtraction',
    wasm.OP_I32_TRUNC_S_F32: 'truncate a 32-bit float to a signed 32-bit integer',
    wasm.OP_I32_TRUNC_S_F64: 'truncate a 64-bit float to a signed 32-bit integer',
    wasm.OP_I32_TRUNC_U_F32: 'truncate a 32-bit float to an unsigned 32-bit integer',
    wasm.OP_I32_TRUNC_U_F64: 'truncate a 64-bit float to an unsigned 32-bit integer',
    wasm.OP_I32_WRAP_I64: 'wrap a 64-bit integer to a 32-bit integer',
    wasm.OP_I32_XOR: 'sign-agnostic bitwise exclusive or',
    wasm.OP_I64_CONST: 'a constant value interpreted as i64',
    wasm.OP_I64_EXTEND_S_I32: 'extend a signed 32-bit integer to a 64-bit integer',
    wasm.OP_I64_EXTEND_U_I32: 'extend an unsigned 32-bit integer to a 64-bit integer',
    wasm.OP_I64_LOAD16_S: 'load from memory',
    wasm.OP_I64_LOAD16_U: 'load from memory',
    wasm.OP_I64_LOAD32_S: 'load from memory',
    wasm.OP_I64_LOAD32_U: 'load from memory',
    wasm.OP_I64_LOAD8_S: 'load from memory',
    wasm.OP_I64_LOAD8_U: 'load from memory',
    wasm.OP_I64_LOAD: 'load from memory',
    wasm.OP_I64_REINTERPRET_F64: 'reinterpret the bits of a 64-bit float as a 64-bit integer',
    wasm.OP_I64_STORE16: 'store to memory',
    wasm.OP_I64_STORE32: 'store to memory',
    wasm.OP_I64_STORE8: 'store to memory',
    wasm.OP_I64_STORE: 'store to memory',
    wasm.OP_I64_TRUNC_S_F32: 'truncate a 32-bit float to a signed 64-bit integer',
    wasm.OP_I64_TRUNC_S_F64: 'truncate a 64-bit float to a signed 64-bit integer',
    wasm.OP_I64_TRUNC_U_F32: 'truncate a 32-bit float to an unsigned 64-bit integer',
    wasm.OP_I64_TRUNC_U_F64: 'truncate a 64-bit float to an unsigned 64-bit integer',
    wasm.OP_IF: 'begin if expression',
    wasm.OP_LOOP: 'begin a block which can also form control flow loops',
    wasm.OP_NOP: 'no operation',
    wasm.OP_RETURN: 'return zero or one value from this function',
    wasm.OP_SELECT: 'select one of two values based on condition',
    wasm.OP_SET_GLOBAL: 'write a global variable',
    wasm.OP_SET_LOCAL: 'write a local variable or parameter',
    wasm.OP_TEE_LOCAL: 'write a local variable or parameter and return the same value',
    wasm.OP_UNREACHABLE: 'trap immediately',
}
