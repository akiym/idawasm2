from .compat import add_metaclass as add_metaclass, byte2int as byte2int, deprecated_func as deprecated_func, indent as indent
from collections import namedtuple
from typing import Any

logger: Any

class WasmField:
    def __init__(self) -> None: ...
    def from_raw(self, struct: Any, raw: Any) -> None: ...
    def to_string(self, value: Any): ...

class UIntNField(WasmField):
    CONVERTER_MAP: Any = ...
    n: Any = ...
    byte_size: Any = ...
    converter: Any = ...
    def __init__(self, n: Any, **kwargs: Any) -> None: ...
    def from_raw(self, ctx: Any, raw: Any): ...
    def to_string(self, value: Any): ...

class UnsignedLeb128Field(WasmField):
    def from_raw(self, ctx: Any, raw: Any): ...
    def to_string(self, value: Any): ...

class SignedLeb128Field(WasmField):
    def from_raw(self, ctx: Any, raw: Any): ...

class CondField(WasmField):
    field: Any = ...
    condition: Any = ...
    def __init__(self, field: Any, condition: Any, **kwargs: Any) -> None: ...
    def from_raw(self, ctx: Any, raw: Any): ...
    def to_string(self, value: Any): ...

class RepeatField(WasmField):
    field: Any = ...
    repeat_count_getter: Any = ...
    def __init__(self, field: Any, repeat_count_getter: Any, **kwargs: Any) -> None: ...
    def from_raw(self, ctx: Any, raw: Any): ...
    def to_string(self, value: Any): ...

class ConstField(WasmField):
    const: Any = ...
    def __init__(self, const: Any, **kwargs: Any) -> None: ...
    def from_raw(self, ctx: Any, raw: Any): ...

class ChoiceField(WasmField):
    choice_field_map: Any = ...
    choice_getter: Any = ...
    def __init__(self, choice_field_map: Any, choice_getter: Any, **kwargs: Any) -> None: ...
    def from_raw(self, ctx: Any, raw: Any): ...

class BytesField(RepeatField):
    is_str: Any = ...
    def __init__(self, length_getter: Any, is_str: bool = ...) -> None: ...
    def to_string(self, value: Any): ...

FieldMeta = namedtuple('FieldMeta', 'name field')

class MetaInfo:
    fields: Any = ...
    data_class: Any = ...
    structure: Any = ...
    def __init__(self) -> None: ...

class StructureData:
    def __init__(self, for_decoding: bool = ...) -> None: ...
    def get_meta(self): ...
    def get_decoder_meta(self): ...

class StructureMeta(type):
    def __new__(mcs: Any, name: Any, bases: Any, cls_dict: Any): ...

class Structure(WasmField):
    def from_raw(self, ctx: Any, raw: Any): ...
    def to_string(self, value: Any): ...