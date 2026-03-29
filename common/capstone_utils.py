import re
from itertools import combinations

from capstone import *
from keystone import (
    KS_ARCH_ARM,
    KS_ARCH_ARM64,
    KS_MODE_LITTLE_ENDIAN,
    KS_MODE_THUMB,
    Ks,
)

from common.utils import abort

cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
cs_aarch64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
ks_aarch64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

HEX = r'(?:0x[0-9a-fA-F]+?)'
IMMEDIATE = fr'(?:-?\d+?|{HEX})'

def disasm_lite(instructions: bytes, aarch64: bool):
    cs = cs_aarch64 if aarch64 else cs_thumb
    return cs.disasm_lite(instructions, 0x0)

def asm(instructions: str|list[str], aarch64: bool, addr: int = 0) -> bytes:
    if isinstance(instructions, list):
        instructions = '\n'.join(instructions)
    
    ks = ks_aarch64 if aarch64 else ks_thumb
    return bytes(ks.asm(instructions, addr)[0])

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