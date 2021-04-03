from typing import Any, Optional, TypedDict


class Function(TypedDict):
    index: int
    name: str
    offset: int
    type: Any
    exported: bool
    imported: bool
    local_types: list[Any]
    size: int


class FrameReference(TypedDict, total=False):
    # offset into frame of access.
    frame_offset: int
    # size of element being accessed.
    element_size: str
    # type of reference, either "load" or "store".
    access_type: str
    # offset into the bitcode of the reference instruction.
    offset: int
    # the parameter index being loaded.
    parameter: Optional[int]


class Block(TypedDict):
    index: int
    offset: int
    end_offset: Optional[int]
    else_offset: Optional[int]
    br_table_target: Optional[int]
    depth: int
    # "block", "loop", "if", "function"
    type: str


class Global(TypedDict):
    index: int
    offset: int
    type: str
    name: str
