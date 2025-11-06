import re
from itertools import combinations
from typing import Generator

import lief
from capstone import *
from keystone import *
from common.utils import abort

class Function:
    def __init__(self, lib: lief.ELF.Binary, function: lief.Function):
        self._lib = lib
        self._function = function

    @property
    def name(self) -> str:
        return self._function.name

    @property
    def address(self) -> int:
        if self._lib.header.machine_type == lief.ELF.ARCH.ARM:
            return self._function.address & ~1  # Remove Thumb bit

        return self._function.address

    @property
    def size(self) -> int:
        return self._function.size
    
    @property
    def has_thumb_bit(self) -> bool:
        if self._lib.header.machine_type == lief.ELF.ARCH.ARM:
            return (self._function.address & 1) != 0

        return False
    
    def bytes(self, offset: int = 0, amount: int|None = None) -> bytes:
        target = self.address + offset
        if target < 0:
            abort(f'Function "{self.name}": requested bytes at invalid offset {hex(offset)}')

        return self._lib.get_content_from_virtual_address(
            target, amount or self.size
        ).tobytes()
    
    def instructions(self, offset: int = 0,
                     amount: int|None = None) -> Generator[CsInsn, None, None]:
        return disasm(
            self.bytes(offset, amount),
            self._lib.header.machine_type == lief.ELF.ARCH.AARCH64
        )

    @classmethod
    def from_name(self, lib: lief.ELF.Binary,
                  name_pattern: str) -> Generator['Function', None, None]:
        """Returns all functions that match the name pattern."""

        pattern = re.compile(name_pattern)
        functions = (Function(lib, f) for f in lib.functions)
        return (f for f in functions if pattern.match(f.name))

    @classmethod
    def from_name_single(self, lib: lief.ELF.Binary, name_pattern: str) -> 'Function':
        """Returns a single function that matches the name pattern.
        
        Aborts if none or more than one function is found.
        """
        found = list(Function.from_name(lib, name_pattern))
        if len(found) == 0:
            abort(f'No function matches found for "{name_pattern}"')
        if len(found) > 1:
            abort(f'Found multiple functions that match "{name_pattern}"')

        return found[0]
    
    @classmethod
    def from_address(self, lib: lief.ELF.Binary, address: int) -> 'Function|None':
        """Returns the function with the given address,
        or `None` if no function is found.
        
        Aborts if multiple functions are found.
        """
        functions = (Function(lib, f) for f in lib.functions)
        found = [f for f in functions if f.address == address]

        if len(found) == 0:
            return None
        elif len(found) > 1:
            # Some ARM binaries contain the same function twice in the
            # symbol table, once without the Thumb bit and once with it.
            if len(found) == 2 and not found[0].has_thumb_bit and found[1].has_thumb_bit:
                if found[0].size == 0 and found[1].size > 0:
                    return found[1]

            abort(f'Found multiple functions with address {hex(address)}')

        return found[0]
    
    def get_called_functions(self) -> Generator['Function', None, None]:
        """Gets all the functions called by this function (with `bl`),
        excluding thunks without symbols.
        """
        thunk_patterns = [
            ['adrp', 'ldr', 'add', 'br'],
            ['bx pc']
        ]

        for ins in self.instructions():
            if ins.mnemonic != 'bl':
                continue

            offset = ins.operands[0].value.imm
            target_addr = self.address + offset
            target_func = Function.from_address(self._lib, target_addr)
            if target_func is None:
                # This can happen on functions that return early
                # and have junk instructions after the return
                if target_addr < 0:
                    continue

                # Check if the function is a thunk
                is_thunk = False
                instructions = list(self.instructions(offset, amount=16))
                for pattern in thunk_patterns:
                    for i, expected in enumerate(pattern):
                        ins = instructions[i]
                        if ins.mnemonic != expected and f'{ins.mnemonic} {ins.op_str}' != expected:
                            break
                    else:
                        is_thunk = True
                        break

                # We don't care about thunk functions
                if is_thunk:
                    continue

                abort(f'Couldn\'t find any function with address {hex(target_addr)}')

            yield target_func

    def get_return_instructions(self) -> Generator[CsInsn, None, None]:
        """Finds all the return instructions in this function
        (`ret`, `pop {..., pc}`).
        """
        aarch64 = self._lib.header.machine_type == lief.ELF.ARCH.AARCH64
        for ins in self.instructions():
            if aarch64:
                if ins.mnemonic == 'ret':
                    yield ins         
            if 'pc' in ins.op_str:
                if ins.mnemonic.startswith('pop'):
                    yield ins

def apply_patch(data: bytearray, lib: lief.ELF.Binary, address: int, patch: bytes):
    # We avoid patching with LIEF because it makes too many modifications to the binary
    for seg in lib.segments:
        seg_va = seg.virtual_address
        seg_size = seg.virtual_size
        if seg_va <= address < seg_va + seg_size:
            file_address = seg.file_offset + (address - seg_va)
            data[file_address:file_address + len(patch)] = patch
            return

    abort(f'Failed to translate virtual address {hex(address)} to file offset')

########################################################################
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
cs_thumb.detail = True
cs_aarch64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cs_aarch64.detail = True
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
ks_aarch64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

def disasm(instructions: bytes,
           aarch64: bool) -> Generator[CsInsn, None, None]:
    cs = cs_aarch64 if aarch64 else cs_thumb
    return cs.disasm(instructions, 0x0)

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

########################################################################
HEX = r'(?:0x[0-9a-fA-F]+?)'
IMMEDIATE = fr'(?:-?\d+?|{HEX})'

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
        return ins, fr'^.+?$'
    
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