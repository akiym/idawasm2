from .immtypes import *
from collections import namedtuple
from typing import Any

Opcode = namedtuple('Opcode', 'id mnemonic imm_struct flags')
INSN_ENTER_BLOCK: Any
INSN_LEAVE_BLOCK: Any
INSN_BRANCH: Any
INSN_NO_FLOW: Any
OPCODES: Any
OPCODE_MAP: Any
