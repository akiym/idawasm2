from .types import SignedLeb128Field as SignedLeb128Field, UIntNField as UIntNField, UnsignedLeb128Field as UnsignedLeb128Field
from typing import Any

UInt8Field: Any
UInt16Field: Any
UInt32Field: Any
UInt64Field: Any
VarUInt1Field: Any
VarUInt7Field: Any
VarUInt32Field: Any
VarInt7Field: Any
VarInt32Field: Any
VarInt64Field: Any
ElementTypeField = VarInt7Field
ValueTypeField = VarInt7Field
ExternalKindField = UInt8Field
BlockTypeField = VarInt7Field
SEC_UNK: int
SEC_TYPE: int
SEC_IMPORT: int
SEC_FUNCTION: int
SEC_TABLE: int
SEC_MEMORY: int
SEC_GLOBAL: int
SEC_EXPORT: int
SEC_START: int
SEC_ELEMENT: int
SEC_CODE: int
SEC_DATA: int
SEC_NAME: bytes
LANG_TYPE_I32: int
LANG_TYPE_I64: int
LANG_TYPE_F32: int
LANG_TYPE_F64: int
LANG_TYPE_ANYFUNC: int
LANG_TYPE_FUNC: int
LANG_TYPE_EMPTY: int
VAL_TYPE_I32 = LANG_TYPE_I32
VAL_TYPE_I64 = LANG_TYPE_I64
VAL_TYPE_F32 = LANG_TYPE_F32
VAL_TYPE_F64 = LANG_TYPE_F64
NAME_SUBSEC_FUNCTION: int
NAME_SUBSEC_LOCAL: int
IMMUTABLE: int
MUTABLE: int
