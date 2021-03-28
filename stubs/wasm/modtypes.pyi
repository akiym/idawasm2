from .wasmtypes import *
from .opcodes import OP_END as OP_END
from .types import BytesField as BytesField, ChoiceField as ChoiceField, CondField as CondField, ConstField as ConstField, RepeatField as RepeatField, Structure as Structure, WasmField as WasmField
from typing import Any

class ModuleHeader(Structure):
    magic: Any = ...
    version: Any = ...

class FunctionImportEntryData(Structure):
    type: Any = ...

class ResizableLimits(Structure):
    flags: Any = ...
    initial: Any = ...
    maximum: Any = ...

class TableType(Structure):
    element_type: Any = ...
    limits: Any = ...

class MemoryType(Structure):
    limits: Any = ...

class GlobalType(Structure):
    content_type: Any = ...
    mutability: Any = ...

class ImportEntry(Structure):
    module_len: Any = ...
    module_str: Any = ...
    field_len: Any = ...
    field_str: Any = ...
    kind: Any = ...
    type: Any = ...

class ImportSection(Structure):
    count: Any = ...
    entries: Any = ...

class FuncType(Structure):
    form: Any = ...
    param_count: Any = ...
    param_types: Any = ...
    return_count: Any = ...
    return_type: Any = ...

class TypeSection(Structure):
    count: Any = ...
    entries: Any = ...

class FunctionSection(Structure):
    count: Any = ...
    types: Any = ...

class TableSection(Structure):
    count: Any = ...
    entries: Any = ...

class MemorySection(Structure):
    count: Any = ...
    entries: Any = ...

class InitExpr(WasmField):
    def from_raw(self, struct: Any, raw: Any): ...

class GlobalEntry(Structure):
    type: Any = ...
    init: Any = ...

class GlobalSection(Structure):
    count: Any = ...
    globals: Any = ...

class ExportEntry(Structure):
    field_len: Any = ...
    field_str: Any = ...
    kind: Any = ...
    index: Any = ...

class ExportSection(Structure):
    count: Any = ...
    entries: Any = ...

class StartSection(Structure):
    index: Any = ...

class ElementSegment(Structure):
    index: Any = ...
    offset: Any = ...
    num_elem: Any = ...
    elems: Any = ...

class ElementSection(Structure):
    count: Any = ...
    entries: Any = ...

class LocalEntry(Structure):
    count: Any = ...
    type: Any = ...

class FunctionBody(Structure):
    body_size: Any = ...
    local_count: Any = ...
    locals: Any = ...
    code: Any = ...

class CodeSection(Structure):
    count: Any = ...
    bodies: Any = ...

class DataSegment(Structure):
    index: Any = ...
    offset: Any = ...
    size: Any = ...
    data: Any = ...

class DataSection(Structure):
    count: Any = ...
    entries: Any = ...

class Naming(Structure):
    index: Any = ...
    name_len: Any = ...
    name_str: Any = ...

class NameMap(Structure):
    count: Any = ...
    names: Any = ...

class LocalNames(Structure):
    index: Any = ...
    local_map: Any = ...

class LocalNameMap(Structure):
    count: Any = ...
    funcs: Any = ...

class NameSubSection(Structure):
    name_type: Any = ...
    payload_len: Any = ...
    payload: Any = ...

class Section(Structure):
    id: Any = ...
    payload_len: Any = ...
    name_len: Any = ...
    name: Any = ...
    payload: Any = ...
    overhang: Any = ...