#!/usr/bin/python3
import argparse
import enum
import os
import re
import shutil
import sys
import zipfile

from capstone import *
from keystone import *


class LibModificationPattern:
    def __init__(self, name: str, is_64bit: bool,
                 pattern: bytes, replacement: bytes) -> None:
        self.name = name
        self.is_64bit = is_64bit
        self.pattern = pattern
        self.replacement = replacement

# To generate the patterns, I selected some instructions in Ghidra,
# then opened the Instruction Pattern Search tool (Search->For Instruction Patterns)
# and masked all columns except the first. After that, I copied
# the full search string and converted it with "ghidra_pattern_to_regex.py"

class LibModification:
    def __init__(self, name: str, description: str,
                 patterns: list[LibModificationPattern]) -> None:
        self.name = name
        self.description = description
        self.patterns = patterns

    def try_match(
            self, lib_data: bytes
        ) -> tuple[LibModificationPattern|None, tuple|None]:
        """Tries to match all the patterns against `lib_data`
        until one matches exactly one time.
        
        Returns a tuple containing the matching pattern and the match,
        or `(None, None)`.
        """
        for i, pattern in enumerate(self.patterns):
            matches = re.findall(pattern.pattern, lib_data, re.DOTALL)
            if len(matches) != 1:
                if i < len(self.patterns) - 1:
                    continue

                print(f'[!] [{self.name}] Unexpected number of matches ({len(matches)})')
                return (None, None)
            
            print(f'[*] [{self.name}] Found match using "{pattern.name}" pattern')
            return (pattern, matches[0])

    def try_patch(self, lib_data: bytes) -> bytes|None:
        """Tries to apply the modification to `lib_data`.

        Returns the modified bytes if successful, otherwise `None`.
        """
        pattern, _ = self.try_match(lib_data)
        if pattern is None:
            return None

        return re.sub(pattern.pattern, pattern.replacement, lib_data, 1, re.DOTALL)

########################################################################
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
cs_arm64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_LITTLE_ENDIAN)
ks_arm64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

def disasm(instruction: bytes, arm64: bool) -> tuple[str, str]:
    cs = cs_arm64 if arm64 else cs_thumb
    ins = next(cs.disasm_lite(instruction, 0x0))

    return (ins[2], ins[3])

def disasm_multiple(instructions: bytes, arm64: bool) -> list[tuple[str, str]]:
    cs = cs_arm64 if arm64 else cs_thumb
    ins = cs.disasm_lite(instructions, 0x0)

    return [(x[2], x[3]) for x in ins]

def asm(instruction: str, arm64: bool) -> bytes:
    ks = ks_arm64 if arm64 else ks_thumb

    return bytes(ks.asm(instruction)[0])

def sanitize(instruction: str) -> str:
    return instruction.replace(' ', '').replace('[', '').replace(']', '')

def disasm_ldr(instruction: bytes, arm64: bool) -> tuple[str, str, str|int]:
    op = disasm(instruction, arm64)
    assert op[0].startswith('ldr')

    data = sanitize(op[1]).split(',')
    if data[2].startswith('#'):
        data[2] = int(data[2][1:], 16)

    return (data[0], data[1], data[2])

def disasm_mov(instruction: bytes, arm64: bool) -> tuple[str, str|int]:
    op = disasm(instruction, arm64)
    assert op[0].startswith('mov')

    data = sanitize(op[1]).split(',')
    if data[1].startswith('#'):
        data[1] = int(data[1][1:], 16)

    return (data[0], data[1])

########################################################################
class Capability(enum.IntEnum):
    # Information grabbed from android::ExynosCameraMetadataConverter::m_createAvailableCapabilities

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

def find_capabilities_and_hw_level_offsets(lib_data: bytes) -> tuple[int, int]:
    mod = LibModification(
        name='Find available capabilities & hardware level offsets',
        description=(
            'Finds the offsets of the available capabilities bitmask and '
            'the Hardware Level value inside the ExynosCameraSensorInfo struct'
        ),
        patterns=[
            LibModificationPattern(
                name='Galaxy A20 (Android 9) (32-bit)',
                is_64bit=False,
                pattern=(
                    # Fragment of android::ExynosCameraMetadataConverter::m_createAvailableCapabilities
                    rb'('
                    rb'.\xb0.\x46...\x46.\x46...\x44.......\xd0...\xf8..'
                    # LDRB RX, [RX, #HW_LEVEL_OFFSET]
                    rb'(.\xf8..)'
                    # LDR RX, [RX, #AVAILABLE_CAPABILITIES_OFFSET]
                    rb'(.\xf8..)'
                    rb'....\x4f\xf0'
                    rb')'
                ),
                replacement=b'\\1'
            ),
            LibModificationPattern(
                name='Generic (32-bit)',
                is_64bit=False,
                pattern=(
                    # Fragment of android::ExynosCameraMetadataConverter::m_createAvailableCapabilities
                    rb'('
                    rb'.\xb0.\x46(?:.{5}|.{7})\x44.......\xf0.....\xf0(?:.{2}|.{4})'
                    # LDRB RX, [RX, #HW_LEVEL_OFFSET]
                    rb'(.\xf8..)'
                    rb'(?:.{4}|.{6})?'
                    # LDR RX, [RX, #AVAILABLE_CAPABILITIES_OFFSET]
                    rb'(.\xf8..)'
                    rb'.\xf8'
                    rb')'
                ),
                replacement=b'\\1'
            ),
            LibModificationPattern(
                name='Generic (64-bit)',
                is_64bit=True,
                pattern=(
                    # Fragment of android::ExynosCameraMetadataConverter::m_createAvailableCapabilities
                    rb'('
                    rb'\xd0\x3b\xd5...\xf9(?:.{4}|.{8}).\x03.\xaa(?:.{8})?...\xb4'
                    # LDRB WX, [RX, #HW_LEVEL_OFFSET]
                    rb'(...\x39)'
                    rb'(?:.{4}|.{20})?'
                    # LDR XX, [XX, #AVAILABLE_CAPABILITIES_OFFSET]
                    rb'(...\xf9)'
                    rb'(?:.{16}|.{20})?...\x91...\x91...\x91...\x91'
                    rb')'
                ),
                replacement=b'\\1'
            )
        ]
    )

    pattern, match = mod.try_match(lib_data)
    if pattern is None or match is None:
        abort('Pattern not found')

    hw_offset = disasm_ldr(match[1], pattern.is_64bit)[2]
    cap_offset = disasm_ldr(match[2], pattern.is_64bit)[2]
    print(f'Available capabilities offset: {hex(cap_offset)}')
    print(f'Hardware level offset: {hex(hw_offset)}')

    # Both offsets are usually close to each other
    if abs(cap_offset - hw_offset) > 64:
        print('\033[33m[w] Big difference between offsets, one of them may be wrong\033[0m')

    assert isinstance(cap_offset, int) and isinstance(hw_offset, int)
    assert hw_offset != cap_offset
    return cap_offset, hw_offset

def build_sensor_info_struct_mod(
        lib_data: bytes,
        enable_capabilities: list[int]|None = None,
        disable_capabilities: list[int]|None = None,
        hw_level: int|None = None,
        skip_depth_cameras: bool = False
    ) -> LibModification:

    # The idea is simple; search for the last part of the function that creates the
    # ExynosCameraSensorInfo struct of all cameras (createExynosCameraSensorInfo)
    # & replace a call to _android_log_print with NOPs. Then, we replace
    # the NOPs with our own instructions to modify values inside the struct.

    class Groups(enum.IntEnum):
        ORIGINAL_CODE_1 = 0
        BRANCH_TO_ANDROIDLOGPRINT = 1
        ORIGINAL_CODE_2 = 2
        MOV_R0_RSTRUCT = 3
    
    mod = LibModification(
        name='Modify ExynosCameraSensorInfo struct',
        description=(
            'Modifies values inside the ExynosCameraSensorInfo struct '
            'to enable capabilities, change the hardware level, etc.'
        ),
        patterns=[
            # New patterns should be added at the bottom, so they have less priority

            ###################################################################
            ######################### 32-BIT PATTERNS #########################
            ###################################################################
            LibModificationPattern(
                name='Tab S6 Lite (Android 10-13) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'(.\x44......)' # ORIGINAL_CODE_1 - won't be modified

                    # _android_log_print(4, "ExynosCameraSensorInfo", "INFO(%s[%d]):sensor ID %d name ...
                    rb'..(?:.\xe8\x11\x01|.\xe8\x91\x00)'
                    rb'\x04........\x44.\x44.\x44'
                    rb'(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    # ORIGINAL_CODE_2 - won't be modified
                    rb'((?:.{6}|.{5}\x44.{5}\x42)\x02\xbf'
                        # MOV r0, RSTRUCT. RSTRUCT contains the address of the ExynosCameraSensorInfo struct
                        rb'(.\x46)' # MOV_R0_RSTRUCT
                    rb')'
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 12 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 990/1280/7884/7904/9820/9825 (Android 10-14) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1

                    rb'....(?:.\xe8\x11\x01|.\xe8\x91\x00)'
                    rb'\x04........\x44.\x44.\x44'
                    rb'(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    rb'(......(?:.\xd1|\x02\xbf|.{6}\x02\xbf)(.\x46))'  # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 13 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 11) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1
                    
                    rb'.......\x46.\x44.\xe9..'
                    rb'\x04..\xe9.......\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    rb'(......\x02\xbf(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 16 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 850/1280/9611 (Android 12-14) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1

                    rb'.......\xe9...\x46.\x44.\xe9..'
                    rb'\x04......\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    rb'(.....(?:\x44.....)?\x42..(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 16 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 1280/7884/7904/9825 (Android 9) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1

                    rb'.\x49.\x4a.\x4b.....\xe8\x91\x00'
                    rb'\x04..\x44.\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    rb'(...\x44.........\xd1(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 13 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 9) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1

                    rb'\x4f\xf4...\xe9...\x46'
                    rb'.........\x44...\x44.\x44'
                    rb'\x04.(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    rb'(.....\x44......\x02\xbf(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', False) * 16 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),

            ###################################################################
            ######################### 64-BIT PATTERNS #########################
            ###################################################################
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 10-12) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'....(?:...\x52|...\x32)'
                    rb'.\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9.{0,4}...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 12 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 9) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'....(?:...\x52|...\x32)'
                    rb'...\x91.\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 12 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 850 (Android 13) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'.....\x03.\x2a'
                    rb'(?:...\x52|...\x32)'
                    rb'.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa).{0,4}...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 12 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 1280 (Android 14) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'...\x52...\x91'
                    rb'.....\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 12 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 1280 (Android 13) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'...\x52...\x91'
                    rb'.....\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 11 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 990/7884/7904/9611/9825 (Android 10-14) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'....(?:...\x52|...\x32)'
                    rb'.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9(?:...\xf9)?...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 11 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            ),
            LibModificationPattern(
                name='Exynos 7884/7904/9825 (Android 9) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'....(?:...\x52|...\x32)'
                    rb'...\x91.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\' + str(Groups.ORIGINAL_CODE_1 + 1).encode() +
                    asm('nop', True) * 11 +
                    b'\\' + str(Groups.ORIGINAL_CODE_2 + 1).encode()
                )
            )
        ]
    )

    pattern, match = mod.try_match(lib_data)
    if pattern is None or match is None:
        abort('Pattern not found')

    # Ensure the last instruction we replaced with a NOP is a branch
    last_ins = disasm(match[Groups.BRANCH_TO_ANDROIDLOGPRINT], pattern.is_64bit)[0]
    assert last_ins in ['b', 'bl', 'blx'], last_ins

    # We can safely use both registers since they are originally used
    # as parameters for _android_log_print
    free_reg = 'w0' if pattern.is_64bit else 'r0'
    free_reg2 = 'w1' if pattern.is_64bit else 'r1'
    struct_reg = disasm_mov(match[Groups.MOV_R0_RSTRUCT], pattern.is_64bit)[1]
    print(f'ExynosCameraSensorInfo struct register: {struct_reg}')
    assert isinstance(struct_reg, str)
    assert struct_reg != free_reg
    assert struct_reg != free_reg2

    # Utils that will be used by the mods
    rep = pattern.replacement
    nop = asm('nop', pattern.is_64bit)
    mod_len = rep.count(nop) * len(nop)
    current_position = 0
    def replace_nops(instructions: list[bytes]):
        nonlocal rep, nop, current_position
        required_nops = 0
        for ins in instructions:
            required_nops += int(len(ins) / len(nop))
            current_position += len(ins)

        # ensure the required NOPs are consecutive, since some patterns may keep
        # original instructions between NOPs and that could mess up the instruction order
        if rep.count(nop * required_nops) <= 0:
            abort('Pattern has not enough space left, try again with less modifications')

        rep = rep.replace(
            nop * required_nops, b''.join(instructions), 1
        )

    # Find struct offsets
    available_cap_offset, hw_lvl_offset = find_capabilities_and_hw_level_offsets(lib_data)

    # Lets start with modifications that require reading the value of
    # available capabilities, so we only need a single LDR instruction
    if (
        skip_depth_cameras or
        enable_capabilities is not None or
        disable_capabilities is not None
    ):
        replace_nops([
            asm(f'ldr {free_reg}, [{struct_reg}, #{available_cap_offset}]', pattern.is_64bit)
        ])

        # Add conditional branch to skip depth cameras
        if skip_depth_cameras:
            instructions = []
            branch_offset = mod_len - current_position # in bytes

            if pattern.is_64bit:
                instructions.append(
                    asm(f'tbnz {free_reg}, #7, #{branch_offset}', pattern.is_64bit)
                )
            else:
                instructions.append(
                    asm(f'TST {free_reg}, {Capability.DEPTH_OUTPUT}', pattern.is_64bit),
                )
                branch_offset -= len(instructions[0])
                instructions.append(
                    asm(f'bne #{branch_offset}', pattern.is_64bit)
                )

            replace_nops(instructions)
            print('[+] Added conditional to skip depth cameras')

        # Modify available capabilities
        instructions = []

        if enable_capabilities is not None:
            value = 0
            for cap in enable_capabilities:
                value |= cap

            try:
                instructions.append(
                    asm(f'orr {free_reg}, {free_reg}, #{value}', pattern.is_64bit)
                )
            except KsError:
                # ORR doesn't support the immediate value, so store it in a register
                instructions.extend([
                    asm(f'mov {free_reg2}, #{value}', pattern.is_64bit),
                    asm(f'orr {free_reg}, {free_reg}, {free_reg2}', pattern.is_64bit)
                ])


        if disable_capabilities is not None:
            mask = 0xFFFF
            for cap in disable_capabilities:
                mask &= ~cap

            try:
                instructions.append(
                    asm(f'and {free_reg}, {free_reg}, #{mask}', pattern.is_64bit)
                )
            except KsError:
                # AND doesn't support the immediate value, so store it in a register
                instructions.extend([
                    asm(f'mov {free_reg2}, #{mask}', pattern.is_64bit),
                    asm(f'and {free_reg}, {free_reg}, {free_reg2}', pattern.is_64bit)
                ])

        if len(instructions) > 0:
            instructions.append(
                asm(f'str {free_reg}, [{struct_reg}, #{available_cap_offset}]', pattern.is_64bit)
            )
            replace_nops(instructions)
            
            if enable_capabilities is not None:
                caps = ', '.join([Capability(x).name for x in enable_capabilities])
                print(f'[+] Enabled capabilities: {caps}')
            if disable_capabilities is not None:
                caps = ', '.join([Capability(x).name for x in disable_capabilities])
                print(f'[+] Disabled capabilities: {caps}')

    # Set hardware level
    if hw_level is not None:
        # movs is smaller than mov
        mov = 'mov' if pattern.is_64bit else 'movs'
        replace_nops([
            asm(f'{mov} {free_reg}, #{hw_level}', pattern.is_64bit),
            asm(f'strb {free_reg}, [{struct_reg}, #{hw_lvl_offset}]', pattern.is_64bit)  
        ])
        print(f'[+] Hardware level set to {hw_level} ({HardwareLevel(hw_level).name})')

    assert len(rep) == len(pattern.replacement)
    pattern.replacement = rep
    return mod

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

        data = file.read()
        data_len = len(data)
        file.close()

        print(f'\n[*] Patching "{file.name}"...')
        mod = build_sensor_info_struct_mod(
            lib_data=data,
            enable_capabilities=args.enable_cap,
            disable_capabilities=args.disable_cap,
            hw_level=args.hardware_level,
            skip_depth_cameras=args.skip_depth
        )

        data = apply_modification(data, mod)
        with open(output_path, 'wb') as f:
            f.write(data)
            print(f'[*] Patched lib saved as "{output_path}"')

        # Ensure we didn't add nor remove instructions
        assert len(data) == data_len
        out_libs.append(output_path)

    # Create Magisk module
    print()
    if (args.model is not None
        and args.android_version is not None
        and args.version is not None
    ):
        mods = ''
        if args.enable_cap is not None:
            mods += (
                'enables [' + ', '.join([Capability(x).name for x in args.enable_cap]) + '], '
            )
        if args.disable_cap is not None:
            mods += (
                'disables [' + ', '.join([Capability(x).name for x in args.disable_cap]) + '], '
            )
        if args.hardware_level is not None:
            mods += f'sets the hardware level to {HardwareLevel(args.hardware_level).name}, '

        mods = mods[0].upper() + mods[1:-2]
        create_magisk_module(
            out_libs, args.model,
            str(args.android_version), str(args.version), mods
        )        

def apply_modification(lib_data: bytes, mod: LibModification) -> bytes:
    patched_data = mod.try_patch(lib_data)
    if patched_data is None:
        abort(f'Could not apply "{mod.name}"')

    print(f'[+] Applied "{mod.name}"')
    return patched_data

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
