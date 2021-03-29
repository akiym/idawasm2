from collections.abc import Iterator
from typing import Any, NamedTuple, Union

from wasm.types import StructureData


def offset_of(struc: StructureData, fieldname: str) -> int:
    """
    given a wasm struct instance and a field name, return the offset into the struct where you'd find the field.
    """
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        if field.name != fieldname:
            p += dec_meta['lengths'][field.name]
        else:
            return p
    raise KeyError('field not found: ' + fieldname)


def size_of(struc: StructureData, fieldname: str = None) -> int:
    """
    given a wasm struct instance, compute the size of the element.
    if a field name is provided, fetch the size of the given field.
    otherwise, fetch the size of the entire struct.
    """
    if fieldname is not None:
        # size of the given field, by name
        dec_meta = struc.get_decoder_meta()
        return dec_meta['lengths'][fieldname]
    else:
        # size of the entire given struct
        return sum(struc.get_decoder_meta()['lengths'].values())


class Field(NamedTuple):
    offset: int
    name: str
    size: int
    value: Union[StructureData, list[StructureData], int]


def get_fields(struc: StructureData) -> Iterator[Field]:
    p = 0
    dec_meta = struc.get_decoder_meta()
    for field in struc.get_meta().fields:
        flen = dec_meta['lengths'][field.name]
        if flen > 0:
            yield Field(p, field.name, flen, getattr(struc, field.name))
        p += flen


def is_struc(o: Any) -> bool:
    """
    does the given object look like a structure from the wasm library.

    this is super ugly, but since the wasm library creates types on demand, i'm not sure how else to test for them.

    Example::

        assert is_struc(section.data) == True

    Example::

        assert is_struc(1) == False

    Args:
      o (Any): the object to test.

    Returns:
      bool: if the object appears to be a structure from the wasm library.
    """
    return '.GeneratedStructureData' in str(type(o))


def struc_to_dict(struc: Any) -> Any:
    if isinstance(struc, str):
        return struc
    elif isinstance(struc, int):
        return struc
    elif isinstance(struc, dict):
        return {k: struc_to_dict(v) for k, v in struc.items()}
    elif isinstance(struc, list):
        return [struc_to_dict(f) for f in struc]
    elif is_struc(struc):
        return {f.name: struc_to_dict(f.value) for f in get_fields(struc)}
    elif isinstance(struc, memoryview):
        return struc.tobytes().decode('utf-8')
    else:
        raise ValueError('unexpected type: ' + str(type(struc)))
