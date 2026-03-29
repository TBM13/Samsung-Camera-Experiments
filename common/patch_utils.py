import atexit
import gc
import io
import logging
import os
import pathlib
import re
import shutil
import time
from itertools import combinations
from typing import Generator, Self, overload

# angr prints an error when it's imported and unicorn engine is not installed
logging.getLogger('angr').setLevel(logging.CRITICAL)

import angr
import archinfo
from angr import Block
from angr.knowledge_plugins import Function
from capstone import *
from capstone.arm import ARM_OP_MEM
from capstone.arm64 import ARM64_OP_MEM
from claripy.ast.base import Base as AstBase
from cle.backends.elf import ELF
from cle.backends.elf.elf import ELFSymbol
from keystone import *

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

    def linked_addr(self, lib: 'Lib'):
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

    def rebased_addr(self, lib: 'Lib'):
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

############################ CAPSTONE / KEYSTONE ############################
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
cs_aarch64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
ks_aarch64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

HEX = r'(?:0x[0-9a-fA-F]+?)'
IMMEDIATE = fr'(?:-?\d+?|{HEX})'

def disasm_lite(instructions: bytes, aarch64: bool):
    cs = cs_aarch64 if aarch64 else cs_thumb
    return cs.disasm_lite(instructions, 0x0)

def asm(instructions: str|list[str], aarch64: bool) -> bytes:
    ks = ks_aarch64 if aarch64 else ks_thumb

    if isinstance(instructions, list):
        res = bytes()

        for ins in instructions:
            res += bytes(ks.asm(ins)[0])
        return res
    
    return bytes(ks.asm(instructions)[0])

def reg_name(register, aarch64: bool) -> str:
    if aarch64:
        return cs_aarch64.reg_name(register)

    return cs_thumb.reg_name(register)

def sanitize(pattern: str|None) -> str|None:
    if pattern is None:
        return None

    return f'(?:{pattern})'

def register(aarch64: bool, register: int|None = None) -> str:
    if aarch64:
        if register is not None:
            return fr'[rxw]{register}|sp'

        return r'(?:[rxw][0-9]|[rxw][1-2][0-9]|[rxw]30|sp)'

    if register is not None:
        return fr'r{register}'

    return r'(?:r1[0-5]|r[0-9])'

def register_range(aarch64: bool, min: int, max: int) -> str:
    possibilities = '|'.join(str(i) for i in range(min, max + 1))
    if aarch64:
        return fr'(?:[rxw](?:{possibilities}))'

    return fr'(?:r(?:{possibilities}))'

def any_instruction_pattern(min: int, max: int) -> list[tuple[str, str]|None]:
    res = []
    for _ in range(min):
        res.append((r'^.+$', r'^.+?$'))
    for _ in range(max - min):
        res.append(None)

    return res

def add_pattern(
        aarch64: bool,
        dst_reg: str|None = None,
        src_reg: str|None = None,
        value: str|None = None
) -> tuple[str, str]:
    dst_reg = sanitize(dst_reg) or register(aarch64)
    src_reg = sanitize(src_reg) or register(aarch64)
    value = sanitize(value)

    return r'^add$', fr'^{dst_reg}, {src_reg}, (?:#{value or IMMEDIATE}|{value or register(aarch64)})$'

def adr_pattern(
        aarch64: bool,
        dst_reg: str|None = None,
        label: str|None = None
) -> tuple[str, str]:
    dst_reg = sanitize(dst_reg) or register(aarch64)
    label = sanitize(label) or IMMEDIATE

    return r'^adrp?$', fr'^{dst_reg}, #{label}$'

def branch_pattern(
        aarch64: bool,
        label_or_reg: str|None = None
) -> tuple[str, str]:
    label_or_reg = sanitize(label_or_reg)
    label_or_reg = fr'^(?:#?{label_or_reg or IMMEDIATE}|{label_or_reg or register(aarch64)})$'

    if not aarch64:
        return r'^(b|bx|bl|blx)$', label_or_reg
    else:
        return r'^(b|bl|br|blr)$', label_or_reg

def ldr_pattern(
        aarch64: bool,
        dst_reg: str|None = None, src_reg: str|None = None,
        offset: str|None = None
) -> tuple[str, str]:
    dst_reg = sanitize(dst_reg) or register(aarch64)
    src_reg = sanitize(src_reg) or register(aarch64)
    offset = sanitize(offset) or IMMEDIATE

    if not aarch64:
        return r'^ldr(?:b|sb|h|sh)?(?:\.w)?$', fr'^{dst_reg}, \[{src_reg}, #{offset}\]$'
    else:
        return r'^ldr(?:b|sb|h|sh|sw)?$', fr'^{dst_reg}, \[{src_reg}, #{offset}\]$'

def mov_pattern(
        aarch64: bool,
        dst_reg: str|None = None,
        value_or_src_reg: str|None = None
) -> tuple[str, str]:
    dst_reg = sanitize(dst_reg) or register(aarch64)
    value_or_src_reg = sanitize(value_or_src_reg)

    return r'^mov(?:\.w)?$', fr'^{dst_reg}, (?:#{value_or_src_reg or IMMEDIATE}|{value_or_src_reg or register(aarch64)})$'

def pop_pattern(
        popped_registers: list[str]|None = None,
        match_on_extra_regs: bool = False) -> tuple[str, str]:
    ins = r'^pop(?:\.w)?$'
    if popped_registers is None:
        return ins, r'^.+?$'
    
    regs = ', '.join([sanitize(reg) for reg in popped_registers])
    if match_on_extra_regs:
        return ins, fr'^\{{.+?{regs}.+?\}}$'
    
    return ins, fr'^\{{{regs}\}}$'

def ret_pattern(dst_reg: str = 'LR') -> tuple[str, str]:
    if dst_reg == 'LR':
        return r'^ret$', r'^$'

    dst_reg = sanitize(dst_reg)
    return r'^ret$', fr'^{dst_reg}$'

def str_pattern(
        aarch64: bool,
        src_reg: str|None = None,
        dst_reg: str|None = None,
        offset: str|None = None
) -> tuple[str, str]:
    src_reg = sanitize(src_reg) or register(aarch64)
    dst_reg = sanitize(dst_reg) or register(aarch64)
    offset = sanitize(offset)

    if offset is not None:
        return r'^str(?:b|h)?(?:\.w)?$', fr'^{src_reg}, \[{dst_reg}, #{offset}\]$'
    else:
        offset = IMMEDIATE
        return r'^str(?:b|h)?(?:\.w)?$', fr'^{src_reg}, \[{dst_reg}(?:, #{offset})?\]$'

def strd_pattern(
        aarch64: bool,
        src_reg1: str|None = None, src_reg2: str|None = None,
        dst_reg: str|None = None,
        offset: str|None = None
) -> tuple[str, str]:
    src_reg1 = sanitize(src_reg1) or register(aarch64)
    src_reg2 = sanitize(src_reg2) or register(aarch64)
    dst_reg = sanitize(dst_reg) or register(aarch64)
    offset = sanitize(offset) or IMMEDIATE

    if not aarch64:
        return r'^strd(?:\.w)?$', fr'^{src_reg1}, {src_reg2}, \[{dst_reg}, #{offset}\]$'
    else:
        raise NotImplementedError()

class InstructionsBlockPattern:
    """Contains the patterns necessary to match 
    a consecutive block of instructions.
    """
    def __init__(self, name: str, aarch64: bool,
                 patterns: list[tuple[str, str]|None]):
        self.name = name
        self.aarch64 = aarch64
        self.patterns = patterns

def _match_instruction_block(
        instructions: list[tuple[int, int, str, str]],
        block_pattern: InstructionsBlockPattern
) -> list[str]|None:
    patterns = block_pattern.patterns
    if len(patterns) == 0 or patterns.count(None) == len(patterns):
        return None
    
    for i, pattern in enumerate(patterns):
        if pattern is not None:
            break

        # Remove leading None patterns
        patterns = patterns[i + 1:]

    first_mnemonic_pattern = patterns[0][0]
    first_op_pattern = patterns[0][1]
    for i, (addr, size, mnemonic, op_str) in enumerate(instructions):
        if i + len(patterns) > len(instructions):
            # Not enough instructions left to match block
            return None

        matches = []
        mnemonic_match = re.match(first_mnemonic_pattern, mnemonic)
        op_match = re.match(first_op_pattern, op_str)
        if mnemonic_match is None or op_match is None:
            continue

        matches.extend(mnemonic_match.groups())
        matches.extend(op_match.groups())
        found_matches = 1
        if found_matches == len(patterns):
            if _match_instruction_block(instructions[i + 1:], block_pattern) is not None:
                abort(f'Multiple matching instruction blocks found using pattern "{block_pattern.name}"')

            return matches

        # Found the first match, now check if the following consecutive instructions match
        for j in range(1, len(patterns)):
            if i + j >= len(instructions):
                # Not enough instructions left to match block
                break

            if patterns[j] is None:
                found_matches += 1
                continue

            ins_pattern, op_pattern = patterns[j]
            for match_i in range(len(matches) - 1, -1, -1):
                ins_pattern = ins_pattern.replace(f'${match_i}', matches[match_i])
                op_pattern = op_pattern.replace(f'${match_i}', matches[match_i])

            addr, size, mnemonic, op_str = instructions[i + j]
            mnemonic_match = re.match(ins_pattern, mnemonic)
            op_match = re.match(op_pattern, op_str)
            if mnemonic_match is None or op_match is None:
                break

            matches.extend(mnemonic_match.groups())
            matches.extend(op_match.groups())
            found_matches += 1
            if found_matches == len(patterns):
                if _match_instruction_block(instructions[i + 1:], block_pattern) is not None:
                    abort(f'Multiple matching instruction blocks found using pattern "{block_pattern.name}"')

                return matches

def match_instruction_block(
        instructions: bytes,
        block_pattern: InstructionsBlockPattern
) -> list[str]|None:
    patterns = block_pattern.patterns

    # 'None' represents optional instructions that may or may not be present
    # First lets try to match without the None(s), then with the different
    # permutations of the pattern using a single 'None', and so on.
    # Example with patterns = [A, None, B, None, C]:
    # 1) [A, B, C]
    # 2) [A, None, B, C], [A, B, None, C]
    # 3) [A, None, B, None, C]
    none_indices = [i for i, x in enumerate(patterns) if x is None]
    tried = set()

    instructions = list(disasm_lite(instructions, block_pattern.aarch64))
    for i in range(len(patterns) + 1):
        for none_pos in combinations(none_indices, i):
            pattern = patterns.copy()
            for i in sorted(set(none_indices) - set(none_pos), reverse=True):
                pattern.pop(i)

            t = tuple(pattern)
            if t not in tried:
                tried.add(t)
                matches = _match_instruction_block(
                    instructions, 
                    InstructionsBlockPattern(
                        block_pattern.name, block_pattern.aarch64, pattern
                    )
                )
                if matches is not None:
                    return matches

def match_single_instruction_block(
        instructions: bytes,
        blocks: list[InstructionsBlockPattern]
) -> list[str]:
    """Returns the first matching instruction block found."""

    for block in blocks:
        matches = match_instruction_block(instructions, block)
        if matches is not None:
            print(f'[+] Found match using "{block.name}" pattern')
            return matches

    abort('No matching instruction block found')