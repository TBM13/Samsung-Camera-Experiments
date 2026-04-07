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

from common.capstone_utils import *
from common.utils import KeywordFilter, abort, warn

# angr prints an error when it's imported and unicorn engine is not installed
logging.getLogger('angr.state_plugins.unicorn_engine').setLevel(logging.CRITICAL)

import angr
import archinfo
from angr import Block
from angr.knowledge_plugins import Function
from capstone.arm import ARM_OP_MEM
from capstone.arm64 import ARM64_OP_MEM
from claripy.ast.base import Base as AstBase
from cle.backends.elf import ELF
from cle.backends.elf.elf import ELFSymbol

# Filter unnecesary log lines
logging.getLogger('cle.loader').addFilter(
    KeywordFilter('Symbol imported without a known size')
)

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
    
    def _add_instruction(self, ins: str|bytes|bytearray, is_exit_ins: bool = False):
        original_ins = ins
        if not isinstance(ins, str):
            if self._is_aarch64 and len(ins) != 4:
                abort(f'Invalid instruction size: {len(ins)} bytes')
            elif not self._is_aarch64 and len(ins) not in [2, 4]:
                abort(f'Invalid instruction size: {len(ins)} bytes')

            hex_list = [f'0x{b:02x}' for b in ins]
            ins = '.byte ' + ', '.join(hex_list)
        
        if '\n' in ins:
            abort('Only a single instruction can be added at a time')

        # Ensure the instruction is valid and keystone can assemble it
        assembled = asm(f'{self.exit_label}:\n' + ins, self._is_aarch64)
        if isinstance(original_ins, str):
            if len(assembled) != 4 and (len(assembled) != 2 or self._is_aarch64):
                abort(f'Keystone failed to assemble "{ins}"')
        elif assembled != original_ins:
            abort(f'Keystone failed to assemble "{ins}"')

        if is_exit_ins:
            self._exit_instructions.append(ins)
        else:
            self._instructions.append(ins)

    def add_instruction(self, ins: str|bytes|bytearray):
        """Adds the given instruction to the mod.
        
        * Branches to places outside the mod should use absolute (linked) addresses
        (e.g. `b 0x12345`).
        """
        self._add_instruction(ins, False)
    def add_exit_instruction(self, ins: str|bytes|bytearray):
        """Exit instructions are added after the `exit_label` and will
        be executed when the mod exits.

        * Branches to places outside the mod should use absolute (linked) addresses
        (e.g. `b 0x12345`).
        """
        self._add_instruction(ins, True)

    def assemble(self, lib: 'Lib') -> bytes:
        """Assembles the mod's instructions and returns the corresponding bytes."""
        if len(self._exit_instructions) == 1:
            abort('Cannot assemble a mod with no exit instructions')

        # instructions added with .byte aren't considered by keystone when calculating
        # branch offsets, so lets temporarily replace them with placeholders
        nop1 = 'nop'
        nop1_asm = asm(nop1, self._is_aarch64)
        nop2 = 'mov x0, x0' if self._is_aarch64 else 'mov r1, r1'
        nop2_asm = asm(nop2, self._is_aarch64)
        if len(nop1_asm) != len(nop2_asm):
            abort('Unexpected placeholder instruction sizes')
        for (b1, b2) in zip(nop1_asm, nop2_asm):
            if b1 == b2:
                abort('Invalid placeholder instructions, they must not contain common bytes')

        instructions_with_nops1 = self._instructions + self._exit_instructions
        instructions_with_nops2 = self._instructions + self._exit_instructions
        raw_bytes: list[bytes] = []
        for i, ins in enumerate(instructions_with_nops1):
            if not ins.startswith('.byte '):
                continue

            ins_bytes = ins[6:].strip().split(', ')
            ins_bytes = bytes([int(b, 0) for b in ins_bytes])
            raw_bytes.append(ins_bytes)

            if len(ins_bytes) == 0 or len(ins_bytes) % len(nop1_asm) != 0:
                abort(f'Invalid .byte instruction: {ins}')

            required_nops = len(ins_bytes) // len(nop1_asm)
            instructions_with_nops1[i] = '\n'.join([nop1] * required_nops)
            instructions_with_nops2[i] = '\n'.join([nop2] * required_nops)

        asm_bytes_nops1 = asm(
            instructions_with_nops1,
            self._is_aarch64,
            self.start_addr.linked_addr(lib)
        )
        if len(asm_bytes_nops1) > self._max_size:
            abort(f'Assembled mod is too big: {len(asm_bytes_nops1)} bytes (max {self._max_size}).' +
                  ' Try again with less modifications')
        if len(raw_bytes) == 0:
            # No need to do anything since there aren't any .byte directives
            return asm_bytes_nops1

        asm_bytes_nops2 = asm(
            instructions_with_nops2,
            self._is_aarch64,
            self.start_addr.linked_addr(lib)
        )
        if len(asm_bytes_nops1) != len(asm_bytes_nops2):
            abort('Assembled bytes have different sizes')

        # Replace the placeholders with the original raw bytes
        placed_raw_bytes = 0
        consecutive_different_bytes = 0
        final_bytes = bytearray(asm_bytes_nops1)
        def place_raw_bytes(i: int):
            nonlocal placed_raw_bytes, consecutive_different_bytes

            to_place = raw_bytes[placed_raw_bytes]
            if consecutive_different_bytes != len(to_place):
                abort('Something went wrong with the mod assembly')

            final_bytes[i - consecutive_different_bytes:i] = to_place
            placed_raw_bytes += 1
            consecutive_different_bytes = 0

        for i, (b1, b2) in enumerate(zip(asm_bytes_nops1, asm_bytes_nops2)):
            if b1 != b2:
                if placed_raw_bytes >= len(raw_bytes):
                    abort('Something went wrong with the mod assembly')

                consecutive_different_bytes += 1
                continue

            if consecutive_different_bytes != 0:
                place_raw_bytes(i)

        if consecutive_different_bytes != 0:
            place_raw_bytes(len(asm_bytes_nops1))
        if placed_raw_bytes != len(raw_bytes):
            abort('Failed to place all raw bytes')

        return final_bytes
    
    def assemble_branch_to_mod(self, lib: 'Lib', from_addr: VirtualAddress) -> bytes:
        """Assembles a branch instruction to the mod from the given address."""
        offset = from_addr.calculate_offset(lib, self.start_addr)
        return asm(f'b #{offset}', self._is_aarch64)

class AppliedPatch:
    """Represents a patch that has been applied to a binary."""
    def __init__(self, file_offset: int, original_bytes: bytes|bytearray, patched_bytes: bytes|bytearray):
        self._file_offset = file_offset
        self._original_bytes = original_bytes
        self._patched_bytes = patched_bytes

    @property
    def file_offset(self) -> int:
        return self._file_offset
    @property
    def original_bytes(self) -> bytes|bytearray:
        return self._original_bytes
    @property
    def patched_bytes(self) -> bytes|bytearray:
        return self._patched_bytes

class Lib:
    def __init__(self, bytes: bytes):
        self._bytes = bytearray(bytes)
        self._bytes_len = len(self._bytes)
        self._applied_patches: list[AppliedPatch] = []

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
    
    @property
    def applied_patches(self) -> list[AppliedPatch]:
        """A list of all the patches that have been applied to the lib."""
        return list(self._applied_patches)

    def apply_patch(self, addr: VirtualAddress, patch: bytes|bytearray):
        """Applies the given patch to the lib at the specified address.
        The patch must not modify the size of the lib.
        
        Does not modify the file nor the angr project.
        """
        file_address = self.lib.addr_to_offset(addr.rebased_addr(self))
        if file_address is None:
            abort(f'Failed to convert address {addr} to file offset')

        self._applied_patches.append(
            AppliedPatch(file_address, self._bytes[file_address:file_address + len(patch)], patch)
        )
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