from .compat import byte2int as byte2int
from .modtypes import ModuleHeader as ModuleHeader, NameSubSection as NameSubSection, SEC_NAME as SEC_NAME, SEC_UNK as SEC_UNK, Section as Section
from .opcodes import OPCODE_MAP as OPCODE_MAP
from collections import namedtuple
from collections.abc import Iterator
from typing import Any

Instruction = namedtuple('Instruction', 'op imm len')

ModuleFragment = namedtuple('ModuleFragment', 'type data')

def decode_bytecode(bytecode: Any) -> Iterator[Instruction]: ...
def decode_module(module: Any, decode_name_subsections: bool = ...) -> Iterator[ModuleFragment]: ...
