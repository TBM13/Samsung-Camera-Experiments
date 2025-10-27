#!/usr/bin/python3
import argparse
import enum
import math
import os
import re
import shutil
import sys
import zipfile
from itertools import combinations
from typing import Generator

import lief
from capstone import *
from keystone import *


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
        return self._lib.get_content_from_virtual_address(
            self.address + offset, amount or self.size
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
                # Check if the function is a thunk
                is_thunk = False
                instructions = list(self.instructions(offset, amount=16))
                for pattern in thunk_patterns:
                    for i, expected in enumerate(pattern):
                        ins = instructions[i]
                        if (ins.mnemonic != expected and f'{ins.mnemonic} {ins.op_str}' != expected):
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

cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
cs_thumb.detail = True
cs_arm64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cs_arm64.detail = True
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_LITTLE_ENDIAN)
ks_aarch64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

def disasm(instructions: bytes, aarch64: bool) -> Generator[CsInsn, None, None]:
    cs = cs_arm64 if aarch64 else cs_thumb
    return cs.disasm(instructions, 0x0)

def asm(instruction: str, aarch64: bool) -> bytes:
    ks = ks_aarch64 if aarch64 else ks_thumb
    return bytes(ks.asm(instruction)[0])

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
    label_or_reg = fr'^(?:#{label_or_reg or IMMEDIATE}|{label_or_reg or register(aarch64)})$'

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
    def __init__(self, name: str, patterns: list[tuple[str, str]|None]):
        self.patterns = patterns
        self.name = name

def _match_instruction_block(
        instructions: list[CsInsn],
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
    for i, ins in enumerate(instructions):
        if i + len(patterns) > len(instructions):
            # Not enough instructions left to match block
            return None

        matches = []
        mnemonic_match = re.match(first_mnemonic_pattern, ins.mnemonic)
        op_match = re.match(first_op_pattern, ins.op_str)
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

            ins = instructions[i + j]
            mnemonic_match = re.match(ins_pattern, ins.mnemonic)
            op_match = re.match(op_pattern, ins.op_str)
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
        instructions: list[CsInsn],
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
                    InstructionsBlockPattern(block_pattern.name, pattern)
                )
                if matches is not None:
                    return matches

def match_single_instruction_block(
        instructions: list[CsInsn],
        blocks: list[InstructionsBlockPattern]
) -> list[str]:
    """Returns the first matching instruction block found."""

    for block in blocks:
        matches = match_instruction_block(instructions, block)
        if matches is not None:
            print(f'[+] Found match using "{block.name}" pattern')
            return matches

    abort('No matching instruction block found')

########################################################################
class Capability(enum.IntEnum):
    # These three are automatically enabled if the hardware level is 1 (FULL)
    MANUAL_SENSOR_AND_READ_SENSOR_SETTINGS = 2
    MANUAL_POST_PROCESSING = 4
    BURST_CAPTURE = 8

    # If this is disabled, GCam doesn't work and shows a black screen in photo mode.
    # Enabling it is enough to make it work on some devices
    RAW = 16

    ZSL_AND_PRIVATE_REPROCESSING = 32
    YUV_REPROCESSING = 64
    # Used only on depth cameras
    DEPTH_OUTPUT = 128
    CONSTRAINED_HIGH_SPEED_VIDEO = 256
    MOTION_TRACKING = 512
    LOGICAL_MULTI_CAMERA = 1024
    SECURE_IMAGE_DATA = 2048

class HardwareLevel(enum.IntEnum):
    # Default level on most Exynos devices
    LIMITED = 0
    # Full level automatically enables the capabilities mentioned before
    FULL = 1
    # Legacy level will disable some features
    LEGACY = 2
    # The lib doesn't seem to expect the level to be 3, so it'll probably behave like LIMITED
    LEVEL_3 = 3
    # For external cameras
    EXTERNAL = 4

def find_capabilities_and_hw_level_offsets(lib: lief.ELF.Binary) -> tuple[int, int]:
    aarch64 = lib.header.machine_type == lief.ELF.ARCH.AARCH64
    func = Function.from_name_single(lib, '^_ZN7android29ExynosCameraMetadataConverter29m_createAvailableCapabilities.+')
    # We only care about the android_log_print that is at the start of the function,
    # since it logs "supportedHwLevel(%d) supportedCapabilities(0x%4ju)"
    instructions = list(func.instructions(amount=120 if aarch64 else 70))

    expected_blocks = [
        InstructionsBlockPattern('Generic (32-bit)', [
            # $0 = HW level/capabilities value register
            # $1 = ExynosCameraSensorInfo struct register
            # $2 = HW level/capabilities offset
            ldr_pattern(aarch64, '(r5|r6|r7)', fr'({register(aarch64)})', fr'({IMMEDIATE})'),
            *any_instruction_pattern(0, 2),
            # $3 = capabilities/HW level value register
            # $4 = capabilities/HW level offset
            ldr_pattern(aarch64, '(r5|r6|r7)', '$1', fr'({IMMEDIATE})'),
            *any_instruction_pattern(0, 2),
            ldr_pattern(aarch64, src_reg='pc'),
            ldr_pattern(aarch64, src_reg='pc'),
        ]),
        InstructionsBlockPattern('Generic (64-bit)', [
            # $0 = HW level/capabilities value register
            # $1 = ExynosCameraSensorInfo struct register
            # $2 = HW level/capabilities offset
            ldr_pattern(aarch64, fr'({register_range(aarch64, 19, 29)})', fr'({register(aarch64)})', fr'({IMMEDIATE})'),
            *any_instruction_pattern(0, 5),
            # $3 = capabilities/HW level value register
            # $4 = capabilities/HW level offset
            ldr_pattern(aarch64, fr'({register_range(aarch64, 19, 29)})', '$1', fr'({IMMEDIATE})'),
            *any_instruction_pattern(6, 13),
            mov_pattern(aarch64, value_or_src_reg='$0'),
            str_pattern(aarch64, src_reg='$3'),
            branch_pattern(aarch64),
        ]),
    ]
    print('[*] Finding hardware level & available capabilities offsets...')
    matches = match_single_instruction_block(instructions, expected_blocks)
    hw_offset =  int(matches[2], 16)
    cap_offset = int(matches[4], 16)
    print(hex(hw_offset), hex(cap_offset))

    # Both offsets are usually close to each other
    if abs(cap_offset - hw_offset) > 8:
        print('\033[33m[w] Big difference between offsets, one or both may be wrong\033[0m')
    if hw_offset == cap_offset:
        abort('Both offsets have the same value')

    return cap_offset, hw_offset

def createExynosCameraSensorInfo_mod(
        lib: lief.ELF.Binary,
        enable_capabilities: list[int]|None = None,
        disable_capabilities: list[int]|None = None,
        hw_level: int|None = None,
        skip_depth_cameras: bool = False
    ) -> Generator[tuple[int, bytes], None, None]:
    # Camera configs are created on 'createExynosCameraSensorInfo'.
    # The function calls different camera config struct constructors
    # (e.g. 'ExynosCameraSensorIMX754') depending on the camera,
    # and returns the config struct.

    # Many config constructors are included in the lib, but only
    # those called by 'createExynosCameraSensorInfo' are used.
    # This means we can safely replace one of the unused ones with our own
    # instructions and branch to it at the end of 'createExynosCameraSensorInfo'.

    # Find createExynosCameraSensorInfo function
    aarch64 = lib.header.machine_type == lief.ELF.ARCH.AARCH64
    createExynosCameraSensorInfo = Function.from_name_single(
        lib, r'^_ZN7android28createExynosCameraSensorInfo.+'
    )
    print(f'[+] Found createExynosCameraSensorInfo function')

    # Recursively find all the used constructors, example:
    # createExynosCameraSensorInfo -> ExynosCameraSensorIMX754
    #   -> ExynosCameraSensorIMX754Base -> ExynosCameraSensorInfoBase
    constructor_pattern = r'^_ZN7android\d\dExynosCameraSensor(.+?)(Base)?(C1|C2|C3).+'
    constructors = {
        f.name : f for f in Function.from_name(lib, constructor_pattern) 
    }
    cam_names = set()
    called_functions = [createExynosCameraSensorInfo]
    for f in called_functions:
        called_functions.extend(f.get_called_functions())
        if not f.name in constructors:
            continue

        cam_name = re.match(constructor_pattern, f.name).group(1)
        if cam_name not in cam_names:
            if cam_name != 'Info':
                print(f'- Constructor for {cam_name} is called')

            cam_names.add(cam_name)

        constructors.pop(f.name)

    if len(cam_names) == 0:
        abort('No used camera config constructors found')
    if len(constructors) == 0:
        abort('No unused camera config constructors found')
    if not any('ExynosCameraSensorInfoBase' in f.name for f in called_functions):
        abort('ExynosCameraSensorInfoBase constructor not called, this is unexpected')
    unused_constructor = constructors.popitem()[1]
    print('[+] Selected unused constructor:', unused_constructor.name)

    # Find createExynosCameraSensorInfo's return instruction
    return_ins = list(createExynosCameraSensorInfo.get_return_instructions())
    if len(return_ins) == 0:
        abort('Failed to find return instruction of "createExynosCameraSensorInfo"')
    elif len(return_ins) > 1:
        abort('Multiple return instructions found in "createExynosCameraSensorInfo"')
    return_ins = return_ins[-1]

    # Find struct offsets & build the instructions of the mod
    available_cap_offset, hw_lvl_offset = find_capabilities_and_hw_level_offsets(lib)
    struct_reg = 'x0' if aarch64 else 'r0'
    free_reg = 'w2' if aarch64 else 'r2'
    free_reg2 = 'w3' if aarch64 else 'r3'
    mod: list[bytes] = []

    if (
        skip_depth_cameras or
        enable_capabilities is not None or
        disable_capabilities is not None
    ):
        # Read available capabilities
        mod.extend([
            asm(f'ldr {free_reg}, [{struct_reg}, #{available_cap_offset}]', aarch64)
        ])

    # Skip cameras with depth output capability
    if skip_depth_cameras:
        if aarch64:
            mod.extend([
                # Skip next instruction (return) if depth output capability is not set
                asm(f'tbz {free_reg}, #{int(math.log2(Capability.DEPTH_OUTPUT))}, #8', aarch64),
                return_ins.bytes
            ])
        else:
            mod.extend([
                asm(f'tst {free_reg}, {Capability.DEPTH_OUTPUT}', aarch64),
                # Skip next instruction (return) if depth output capability is not set
                asm(f'beq #{2 + return_ins.size}', aarch64),
                return_ins.bytes
            ])
        print('- Depth cameras won\'t be modified')

    # Modify available capabilities value
    if enable_capabilities is not None:
        value = 0
        for cap in enable_capabilities:
            value |= cap

        try:
            mod.append(
                asm(f'orr {free_reg}, {free_reg}, #{value}', aarch64)
            )
        except KsError:
            # ORR doesn't support the immediate value, so store it in a register
            mod.extend([
                asm(f'mov {free_reg2}, #{value}', aarch64),
                asm(f'orr {free_reg}, {free_reg}, {free_reg2}', aarch64)
            ])

        caps = ', '.join([Capability(x).name for x in enable_capabilities])
        print(f'- Enabling capabilities: {caps}')
    if disable_capabilities is not None:
        mask = 0xFFFF
        for cap in disable_capabilities:
            mask &= ~cap

        try:
            mod.append(
                asm(f'and {free_reg}, {free_reg}, #{mask}', aarch64)
            )
        except KsError:
            # AND doesn't support the immediate value, so store it in a register
            mod.extend([
                asm(f'mov {free_reg2}, #{mask}', aarch64),
                asm(f'and {free_reg}, {free_reg}, {free_reg2}', aarch64)
            ])

        caps = ', '.join([Capability(x).name for x in disable_capabilities])
        print(f'- Disabling capabilities: {caps}')

    # Save available capabilities
    if enable_capabilities is not None or disable_capabilities is not None:
        mod.append(
            asm(f'str {free_reg}, [{struct_reg}, #{available_cap_offset}]', aarch64)
        )

    # Set hardware level
    if hw_level is not None:
        mov = 'mov' if aarch64 else 'movs'
        mod.extend([
            asm(f'{mov} {free_reg}, #{hw_level}', aarch64),
            asm(f'strb {free_reg}, [{struct_reg}, #{hw_lvl_offset}]', aarch64)  
        ])
        print(f'- Changing hardware level to {hw_level} ({HardwareLevel(hw_level).name})')

    # Replace the selected constructor's instructions with ours
    mod.append(return_ins.bytes)
    mod = b''.join(mod)
    if len(mod) > unused_constructor.size:
        abort('The mod doesn\'t fit in the unused constructor')
    yield unused_constructor.address, mod

    # Replace createExynosCameraSensorInfo's return instruction with a branch to the mod
    branch_offset = unused_constructor.address - (createExynosCameraSensorInfo.address + return_ins.address)
    return_ins_address = createExynosCameraSensorInfo.address + return_ins.address
    yield return_ins_address, asm(f'b #{branch_offset}', aarch64)

########################################################################
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'libs', type=argparse.FileType('rb'), nargs='+',
        help='Path(s) of the libexynoscamera3.so lib(s) to patch'
    )

    mod_options = parser.add_argument_group('Lib Modifications')
    mod_options.add_argument(
        '--hardware-level', type=int,
        choices=list(HardwareLevel),
        help='The hardware level that will be set'
    )
    mod_options.add_argument(
        '--enable-cap', type=int,
        choices=list(Capability), nargs='+',
        help='The capabilities that will be enabled, separated by spaces'
    )
    mod_options.add_argument(
        '--disable-cap', type=int,
        choices=list(Capability), nargs='+',
        help='The capabilities that will be disabled, separated by spaces'
    )
    mod_options.add_argument(
        '--skip-depth', action='store_true',
        help=(
            'Skips modifications on cameras with the "Depth Output" capability. '
            'Recommended if your device has a depth camera.'
        )
    )

    module_options = parser.add_argument_group(
        'Magisk Module',
        'If the following settings are provided, a Magisk module with the patched lib(s) will be created'
    )
    module_options.add_argument(
        '--model', type=str,
        help='The device the lib comes from (e.g. Galaxy A20)'
    )
    module_options.add_argument(
        '--android-version', type=int,
        help='The Android version the lib comes from (e.g. 11)'
    )
    module_options.add_argument(
        '--version', type=int,
        help='The module version (e.g. 1)'
    )

    return parser.parse_args()

def main():
    args = parse_args()
    if (args.hardware_level is None and
        args.enable_cap is None and 
        args.disable_cap is None):
        abort('No modifications specified')

    out_libs: list[str] = []
    for file in args.libs:
        base, _ = os.path.splitext(file.name)
        output_path = f'{base}_patched.so'

        lib_data = bytearray(file.read())
        original_len = len(lib_data)
        lib = lief.parse(file.name)
        file.close()

        print(f'\n[*] Patching "{file.name}"...')
        for address, bytes in createExynosCameraSensorInfo_mod(
            lib=lib,
            enable_capabilities=args.enable_cap,
            disable_capabilities=args.disable_cap,
            hw_level=args.hardware_level,
            skip_depth_cameras=args.skip_depth
        ):
            apply_patch(lib_data, lib, address, bytes)

        if len(lib_data) != original_len:
            abort('The size of the patched lib was modified')
        with open(output_path, 'wb') as out_file:
            out_file.write(lib_data)

        print(f'[+] Patched lib saved as "{output_path}"')
        out_libs.append(output_path)

    # Create Magisk module
    print()
    if (args.model is not None
        and args.android_version is not None
        and args.version is not None
    ):
        mods = []
        if args.enable_cap is not None:
            mods.append(f'enables {[Capability(x).name for x in args.enable_cap]}')
        if args.disable_cap is not None:
            mods.append(f'disables {[Capability(x).name for x in args.disable_cap]}')
        if args.hardware_level is not None:
            mods.append(f'sets hardware level to {HardwareLevel(args.hardware_level).name}')

        create_magisk_module(
            out_libs, args.model,
            str(args.android_version), str(args.version),
            ', '.join(mods)
        )        

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

def create_magisk_module(
        libs: list[str], 
        model: str, android_version: str, version: str,
        modifications: str
    ):
    if len(libs) > 2:
        abort('Too many libs provided')

    lib32 = None
    lib64 = None
    for lib in libs:
        with open(lib, 'rb') as f:
            magic = f.read(5)
            if magic[4] == 2:
                lib64 = lib
            else:
                lib32 = lib

    assert lib32 is not None or lib64 is not None
    if len(libs) == 2 and (lib32 is None or lib64 is None):
        abort('Two libs of the same architecture were provided')

    module_base_dir = os.path.join(os.getcwd(), 'ModuleBase')
    if not os.path.isdir(module_base_dir):
        abort(f'"{module_base_dir}" not found')

    tmp_dir = module_base_dir + 'Temp'
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir)
    shutil.copytree(module_base_dir, tmp_dir)

    dst_32 = os.path.join(tmp_dir, 'system/vendor/lib/libexynoscamera3.so')
    dst_64 = os.path.join(tmp_dir, 'system/vendor/lib64/libexynoscamera3.so')
    if lib32 is not None:
        os.makedirs(os.path.dirname(dst_32), exist_ok=True)
        shutil.copy(lib32, dst_32)
    if lib64 is not None:
        os.makedirs(os.path.dirname(dst_64), exist_ok=True)
        shutil.copy(lib64, dst_64)

    # Update module.prop
    model = model.replace(' ', '_')
    with open(os.path.join(tmp_dir, 'module.prop'), 'r+') as f:
        data = f.read()
        data = data.replace('$MODEL', model)
        data = data.replace('$VERSION', version)
        data = data.replace('$ANDROIDVERSION', android_version)
        data = data.replace('$MODS', modifications)
        f.seek(0)
        f.truncate(0)
        f.write(data)

    zip_file = f'Module_{model}.zip'
    with zipfile.ZipFile(zip_file, 'w') as zip:
        for dir, _, files in os.walk(tmp_dir):
            for file in files:
                file_path = os.path.join(dir, file)
                zip.write(file_path, file_path.replace(tmp_dir, ''))

    shutil.rmtree(tmp_dir)
    print(f'[*] Module saved as "{zip_file}"')

def abort(msg: str):
    print(f'\nAbort: {msg}')
    sys.exit(1)

if __name__ == '__main__':
    main()