import atexit
import gc
import io
import logging
import os
import pathlib
import re
import shutil
import time
from typing import Generator, Self, overload

# angr prints an error when it's imported and unicorn engine is not installed
logging.getLogger('angr').setLevel(logging.CRITICAL)

import angr
import archinfo
from angr import Block
from angr.knowledge_plugins import Function
from capstone.arm import ARM_OP_MEM
from capstone.arm64 import ARM64_OP_MEM
from claripy.ast.base import Base as AstBase
from cle.backends.elf import ELF
from cle.backends.elf.elf import ELFSymbol

from common.capstone_utils import *
from common.utils import abort, warn

# angr prints too many warnings when executing simulations
logging.getLogger('angr').setLevel(logging.ERROR)

class VirtualAddress:
    def __init__(self, addr: int, rebased: bool):
        self._addr = addr
        self._rebased = rebased
    
    @property
    def has_thumb_bit(self) -> bool:
        return (self._addr & 1) != 0

    def linked_addr(self, lib: 'Lib') -> int:
        """Returns the linked address corresponding to this virtual address.
        
        On ARM, the thumb bit is removed.
        """
        addr = self._addr
        if self._rebased:
            addr -= lib.lib.mapped_base
            addr += lib.lib.linked_base

        if addr < 0 or addr >= lib.lib.max_addr - lib.lib.min_addr:
            abort(f'Invalid address: {hex(addr)}')
        if addr % 2 != 0 and lib.is_aarch64:
            abort(f'Unaligned address: {hex(addr)}')

        addr = addr & ~1
        return addr

    def rebased_addr(self, lib: 'Lib') -> int:
        """Returns the rebased address corresponding to this virtual address.
        
         On ARM, the thumb bit is removed.
        """
        return self.linked_addr(lib) + lib.lib.mapped_base - lib.lib.linked_base
    
    def calculate_offset(self, lib: 'Lib', target: 'VirtualAddress') -> int:
        """Calculates the offset required to branch from this 
        virtual address to the target one.
        """
        from_addr = self.linked_addr(lib)
        to_addr = target.linked_addr(lib)
        return to_addr - from_addr
    
    def __str__(self):
        return hex(self._addr)
    
    def __add__(self, other) -> 'VirtualAddress':
        if isinstance(other, int):
            return VirtualAddress(self._addr + other, self._rebased)
        if isinstance(other, VirtualAddress):
            if self._rebased != other._rebased:
                abort('Cannot add rebased and non-rebased virtual addresses')
            return VirtualAddress(self._addr + other._addr, self._rebased)
        
        return NotImplemented
        
    def __sub__(self, other) -> 'VirtualAddress':
        if isinstance(other, int):
            return VirtualAddress(self._addr - other, self._rebased)
        if isinstance(other, VirtualAddress):
            if self._rebased != other._rebased:
                abort('Cannot subtract rebased and non-rebased virtual addresses')
            return VirtualAddress(self._addr - other._addr, self._rebased)

        return NotImplemented

class Mod:
    def __init__(self, start_addr: VirtualAddress, max_size: int, is_aarch64: bool):
        self._start_addr = start_addr
        self._max_size = max_size
        self._is_aarch64 = is_aarch64
        self._instructions: list[str] = []
        self._exit_instructions: list[str] = [
            self.exit_label + ':',
        ]

        if max_size <= 0:
            abort(f'Invalid mod max size: {max_size}')

    @property
    def start_addr(self) -> VirtualAddress:
        return self._start_addr
    @property
    def max_size(self) -> int:
        return self._max_size
    @property
    def exit_label(self) -> str:
        """The label that should be branched to in order to exit the mod."""
        return 'exit'
    
    def add_instruction(self, ins: str|bytes|bytearray):
        """Adds the given instruction to the mod.
        
        Branches to places outside the mod should use absolute (linked) addresses.
        """
        if not isinstance(ins, str):
            if self._is_aarch64 and len(ins) % 4 != 0:
                abort(f'Invalid instruction size: {len(ins)} bytes')
            elif not self._is_aarch64 and len(ins) % 2 != 0:
                abort(f'Invalid instruction size: {len(ins)} bytes')

            hex_list = [f'0x{b:02x}' for b in ins]
            ins = '.byte ' + ', '.join(hex_list)

        # Ensure the instruction is valid
        asm(ins + f'\n{self.exit_label}:\nNOP', self._is_aarch64)
        self._instructions.append(ins)

    def add_exit_instruction(self, ins: str|bytes|bytearray):
        """Exit instructions are added after the `exit_label` and will
        be executed when the mod exits.

        Branches to places outside the mod should use absolute (linked) addresses
        (e.g. `b 0x12345`).
        """
        if not isinstance(ins, str):
            if self._is_aarch64 and len(ins) % 4 != 0:
                abort(f'Invalid instruction size: {len(ins)} bytes')
            elif not self._is_aarch64 and len(ins) % 2 != 0:
                abort(f'Invalid instruction size: {len(ins)} bytes')

            hex_list = [f'0x{b:02x}' for b in ins]
            ins = '.byte ' + ', '.join(hex_list)

        # Ensure the instruction is valid
        asm(ins + f'\n{self.exit_label}:\nNOP', self._is_aarch64)
        self._exit_instructions.append(ins)

    def assemble(self, lib: 'Lib') -> bytes:
        """Assembles the mod's instructions and returns the corresponding bytes."""
        if len(self._exit_instructions) == 1:
            abort('Cannot assemble a mod with no exit instructions')

        bytes = asm(
            self._instructions + self._exit_instructions,
            self._is_aarch64,
            self.start_addr.linked_addr(lib)
        )
        if len(bytes) > self._max_size:
            abort(f'Assembled mod is too big: {len(bytes)} bytes (max {self._max_size}).' +
                  ' Try again with less modifications')
            
        return bytes
    
    def assemble_branch_to_mod(self, lib: 'Lib', from_addr: VirtualAddress) -> bytes:
        """Assembles a branch instruction to the mod from the given address."""
        offset = from_addr.calculate_offset(lib, self.start_addr)
        return asm(f'b #{offset}', self._is_aarch64)

class Lib:
    def __init__(self, bytes: bytes):
        self._bytes = bytearray(bytes)
        self._bytes_len = len(self._bytes)

        self._project = angr.Project(
            io.BytesIO(bytes), load_options={'auto_load_libs': False}
        )
        _open_libs.append(self)

        self._aarch64 = isinstance(self.lib.arch, archinfo.ArchAArch64)
        if not self._aarch64 and not isinstance(self.lib.arch, archinfo.ArchARM):
            abort(f'Unexpected arch: {self.lib.arch}')

    @classmethod
    def from_path(cls, path: str) -> Self:
        if not os.path.isfile(path):
            abort(f'File "{path}" does not exist')

        with open(path, 'rb') as file:
            return cls(file.read())

    @property
    def project(self):
        return self._project

    @property
    def lib(self) -> ELF:
        """Equivalent to `project.loader.main_object`."""
        return self._project.loader.main_object

    @property
    def is_aarch64(self) -> bool:
        """`True` if the lib is for the aarch64 architecture, 
        `False` if it's for arm.
        """
        return self._aarch64

    def apply_patch(self, addr: VirtualAddress, patch: bytes|bytearray):
        """Applies the given patch to the lib at the specified address.
        The patch must not modify the size of the lib.
        
        Does not modify the file nor the angr project.
        """
        file_address = self.lib.addr_to_offset(addr.rebased_addr(self))
        if file_address is None:
            abort(f'Failed to convert address {addr} to file offset')

        self._bytes[file_address:file_address + len(patch)] = patch
        if len(self._bytes) != self._bytes_len:
            abort('The size of the patched lib was modified')

    def write_to_file(self, output_path: str):
        """Writes the patched lib to the specified output path."""
        if os.path.exists(output_path):
            abort(f'File "{output_path}" already exists')

        with open(output_path, 'wb') as file:
            file.write(self._bytes)

    def find_symbols(self, name_pattern: str) -> list[ELFSymbol]:
        """Returns a list of all the symbols in the lib 
        whose name matches the given regex pattern.
        """
        name_pattern = re.compile(name_pattern)
        return [
            sym for sym in self.lib.symbols_by_name.values() if name_pattern.match(sym.name)
        ]
    
    @overload
    def find_symbol(self, name_pattern: str) -> ELFSymbol|None:
        """Returns the symbol in the lib whose name matches the given regex pattern,
        or `None` if no symbol matches.
        
        If multiple symbols match the pattern, aborts.
        """
        ...
    @overload
    def find_symbol(self, address: VirtualAddress) -> ELFSymbol|None:
        """Returns the symbol in the lib whose address matches the given one,
        or `None` if no symbol matches.

        On ARM, the thumb bit matters.
        """
        ...
    def find_symbol(self, name_or_addr: str|VirtualAddress) -> ELFSymbol|None:
        if isinstance(name_or_addr, VirtualAddress):
            addr = name_or_addr.rebased_addr(self)
            if name_or_addr.has_thumb_bit:
                addr += 1

            return self.project.loader.find_symbol(addr)

        syms = self.find_symbols(name_or_addr)
        if len(syms) == 0:
            return None
        elif len(syms) > 1:
            abort(f'Found multiple symbols that match "{name_or_addr}"')

        return syms[0]
    
_open_libs: list[Lib] = []
def cleanup_angr_cache():
    """Deletes all the cache directories created by angr."""
    print('[*] Cleaning up temp files...')

    # Delete all open angr projects to release file locks
    for lib in _open_libs:
        del lib

    _open_libs.clear()
    gc.collect()
    # Wait a little to ensure the OS released all file locks
    time.sleep(0.1)

    # Delete dirs that only contain the files "data.mdb" and "lock.mdb"
    for item in pathlib.Path.cwd().iterdir():
        if not item.is_dir():
            continue

        files = list(item.iterdir())
        if len(files) != 2 or not all(f.name in ['data.mdb', 'lock.mdb'] for f in files):
            continue

        shutil.rmtree(item, ignore_errors=True)

atexit.register(cleanup_angr_cache)

################################ CLARIPY ################################
def get_offset_from_symbolic_ast(
        ast: AstBase, aarch64: bool, def_insn: CsInsn|None = None
    ) -> int|None:
    """
    * If `ast` is TOP ± offset returns offset (with the corresponding sign).
    * If `ast` is TOP and `def_insn` is "LDR reg1, [reg2, #offset]", returns offset.
    * If `ast` is TOP, returns `None`.

    Useful to get the offset of a value in a struct.
    """
    if ast.concrete:
        abort(f'Expected a symbolic AST, but got a concrete one: {ast}')

    if ast.op == '__add__' or ast.op == '__sub__':
        if len(ast.args) != 2:
            abort(f'Expected an addition/subtraction operation with 2 arguments, but got: {ast}')
        if ast.args[0].op != 'BVS' or not ast.args[1].concrete:
            abort(f'Expected an addition/subtraction operation between TOP and a concrete value, but got: {ast}')

        val = ast.args[1].concrete_value
        return val if ast.op == '__add__' else -val
    
    if ast.op == 'Reverse':
        # Likely not an offset
        return None
    if ast.op != 'BVS':
        abort(f'Unexpected AST operation "{ast.op}": {ast}')

    if def_insn is not None:
        if def_insn.mnemonic == 'ldrd':
            # TODO: Check if we can handle this. It doesn't seem to be the case
            return None

        if not def_insn.mnemonic.startswith('ldr'):
            if (def_insn.mnemonic == 'ldp' and
                    len(def_insn.operands) == 3 and
                    def_insn.operands[2].type in [ARM_OP_MEM, ARM64_OP_MEM] and
                    reg_name(def_insn.operands[2].mem.base, aarch64) == 'sp'
                ):
                # Likely not an offset
                return None

            abort(f'Unexpected definition instruction "{def_insn.mnemonic} {def_insn.op_str}"')
        if len(def_insn.operands) != 2:
            abort(f'Unexpected number of operands in definition instruction: {def_insn.mnemonic} {def_insn.op_str}')

        mem_op = def_insn.operands[1]
        if mem_op.type not in [ARM_OP_MEM, ARM64_OP_MEM]:
            abort(f'Unexpected second operand type in definition instruction: {def_insn.mnemonic} {def_insn.op_str}')

        src_reg_name = reg_name(mem_op.mem.base, aarch64)
        if src_reg_name == 'sp':
            # Likely not an offset
            return None

        offset = mem_op.mem.disp
        return offset

    return None

################################ ANALYSIS ################################
def get_called_functions(lib: Lib, func: Function) -> Generator[tuple[CsInsn, Function], None, None]:
    """Yields all the functions called by `func`, along with the call instruction.

    Requires all the functions called by `func` to be present in the knowledge base.
    """
    for block_node in func.nodes:
        if block_node.size == 0:
            continue

        block: Block = lib.project.factory.block(block_node.addr, size=block_node.size)
        last_ins: CsInsn = block.capstone.insns[-1]
        if last_ins.mnemonic not in ['bl', 'blx']:
            continue

        branch_target = last_ins.operands[0].imm
        target_func = lib.project.kb.functions.get(branch_target, None)
        if target_func is None:
            warn(f'Failed to find function at address {hex(branch_target)}')
            continue

        yield last_ins, target_func