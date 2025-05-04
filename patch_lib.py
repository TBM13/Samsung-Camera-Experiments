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

# To generate the patterns, I selected some instructions in Ghidra and used
# its Instruction Pattern Search tool. In it, I masked all columns except the
# first one, copied the full search string and converted it using "ghidra_pattern_to_regex.py"

class LibModification:
    def __init__(self, name: str, description: str,
                 patterns: list[LibModificationPattern]) -> None:
        self.name = name
        self.description = description
        self.patterns = patterns

    def try_match(self,
                  lib_data: bytes) -> tuple[LibModificationPattern | None, tuple | None]:
        """Tries to match all the patterns in `self.patterns` against `lib_data`
        until one matches exactly one time.
        
        Returns a tuple containing the matching pattern and the match if successful,
        otherwise `(None, None)`.
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

    def try_patch(self, lib_data: bytes) -> bytes | None:
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
    if arm64:
        ins = next(cs_arm64.disasm_lite(instruction, 0x0))
    else:
        ins = next(cs_thumb.disasm_lite(instruction, 0x0))

    return (ins[2], ins[3])

def disasm_multiple(instructions: bytes, arm64: bool) -> list[tuple[str, str]]:
    if arm64:
        ins = cs_arm64.disasm_lite(instructions, 0x0)
    else:
        ins = cs_thumb.disasm_lite(instructions, 0x0)

    return [(x[2], x[3]) for x in ins]

def asm(instruction: str, arm64: bool) -> bytes:
    if arm64:
        return bytes(ks_arm64.asm(instruction)[0])
    else:
        return bytes(ks_thumb.asm(instruction)[0])

def sanitize(instruction: str) -> str:
    return instruction.replace(' ', '').replace('[', '').replace(']', '')

def disasm_ldr(instruction: bytes, arm64: bool) -> tuple[str, str, str|int]:
    op = disasm(instruction, arm64)
    assert(op[0].startswith('ldr'))

    data = sanitize(op[1]).split(',')
    if data[2].startswith('#'):
        data[2] = int(data[2][1:], 16)

    return (data[0], data[1], data[2])

def disasm_mov(instruction: bytes, arm64: bool) -> tuple[str, str|int]:
    op = disasm(instruction, arm64)
    assert(op[0].startswith('mov'))

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
            'Finds the offsets of the available capabilities bitmask and'
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
        sys.exit(1)

    hw_offset = disasm_ldr(match[1], pattern.is_64bit)[2]
    cap_offset = disasm_ldr(match[2], pattern.is_64bit)[2]
    print(f'Available capabilities offset: {hex(cap_offset)}')
    print(f'Hardware level offset: {hex(hw_offset)}')

    # Both offsets are usually close to each other
    if abs(cap_offset - hw_offset) > 64:
        print('\033[33m[w] Big difference between offsets, one of them may be wrong\033[0m')

    assert(isinstance(cap_offset, int) and isinstance(hw_offset, int))
    assert(hw_offset != cap_offset)
    return (cap_offset, hw_offset)

def build_sensor_info_struct_mod(lib_data: bytes, capabilities: list[int] | None = None,
                                 hw_level: int | None = None,
                                 skip_depth_cameras: bool = False) -> LibModification:
    # The idea is simple; search for the last part of the android::createExynosCameraSensorInfo
    # function (which creates the ExynosCameraSensorInfo struct of all cameras) and replace the
    # instructions related to a call to _android_log_print with NOP instructions.
    # Then, depending on the arguments passed (hw_level, capabilities...), replace those NOPs
    # with the instructions to modify the corresponding values inside the struct

    class Groups():
        ORIGINAL_CODE_1 = 0
        MOV_RX_FOUR = 1
        MOV_WX_X = 2
        BRANCH_TO_ANDROIDLOGPRINT = 3
        ORIGINAL_CODE_2 = 4
        MOV_R0_RSTRUCT = 5
    
    mod = LibModification(
        name='Modify ExynosCameraSensorInfo struct',
        description=(
            'Enables the specified capabilities (Raw, ZSH, etc.) by modifying the available '
            'capabilities bitmask and/or changes the Hardware Level (Limited, Full, Level 3...)'
        ),
        patterns=[
            # New patterns should be added at the bottom, so they have less priority
            ###################################################################
            ######################### 32-BIT PATTERNS #########################
            ###################################################################
            LibModificationPattern(
                name='Exynos 990/1280/7884/7904/9611/9825 (Android 10-14) (32-bit)',
                is_64bit=False,
                pattern=(
                    # This is the last part of the android::createExynosCameraSensorInfo function, corresponding
                    # to _android_log_print(4, "ExynosCameraSensorInfo", "INFO(%s[%d]):sensor ID %d name %s", ...)

                    # STMEA - Unsure if it's safe to replace this with a NOP
                    rb'(.\xe8\x11\x01|.\xe8\x91\x00|.\xe9\x00\x10)' # ORIGINAL_CODE_1 - won't be modified

                    # MOVS RX, #4. We'll remember which register RX is since it's safe to modify it
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X - only present in 64-bit patterns
                    rb'.......\x44.\x44.\x44'
                    rb'(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    # ORIGINAL_CODE_2 - won't be modified
                    rb'(......(?:.\xd1|\x02\xbf|.{6}\x02\xbf)'
                        # MOV r0, RSTRUCT. RSTRUCT contains the address of the ExynosCameraSensorInfo struct
                        rb'(.\x46)' # MOV_R0_RSTRUCT
                    rb')'
                ),
                replacement=(
                    b'\\1' +
                    # These NOPs will be replaced with our mod instructions
                    asm('nop', False) * 9 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 11) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'(\x46)' # ORIGINAL_CODE_1
                    rb'.\x44.\xe9..'
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X
                    rb'.\xe9.......\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(......\x02\xbf(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', False) * 12 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 850/9611 (Android 12-13) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'(\x46)' # ORIGINAL_CODE_1
                    rb'.\x44.\xe9..'
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X
                    rb'.....\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.....(?:\x44.....)?\x42\x02\xbf(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', False) * 10 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 1280/7884/7904/9825 (Android 9) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'.\x49.\x4a.\x4b....'
                    rb'(.\xe8\x91\x00)' # ORIGINAL_CODE_1
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X
                    rb'.\x44.\x44.\x44(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(...\x44.........\xd1(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    asm('nop', False) * 5 +
                    b'\\1' +
                    asm('nop', False) * 6 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 9) (32-bit)',
                is_64bit=False,
                pattern=(
                    rb'(\x4f\xf4...\xe9...\x46)' # ORIGINAL_CODE_1
                    rb'.........\x44...\x44.\x44'
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X
                    rb'(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.....\x44......\x02\xbf(.\x46))' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', False) * 11 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 1280 (Android 14) (32-bit)',
                is_64bit=False,
                pattern=(
                    # This is the last part of the android::createExynosCameraSensorInfo function, corresponding
                    # to _android_log_print(4, "ExynosCameraSensorInfo", "INFO(%s[%d]):sensor ID %d name %s", ...)

                    # MOV.W R0, 0x2CC - should be fine to replace, because it's only used in the log
                    rb'\x4f\xf4\x33\x70'

                    # STMEA - Unsure if it's safe to replace this with a NOP
                    rb'(.{8}.\xe8\x11\x01|.{8}.\xe8\x91\x00|.{8}.\xe9\x00\x10)' # ORIGINAL_CODE_2 - won't be modified

                    # MOVS RX, #4. We'll remember which register RX is since it's safe to modify it
                    rb'(\x04.)' # MOV_RX_FOUR
                    rb'()' # MOV_WX_X - only present in 64-bit patterns
                    rb'.....\x44.\x44'
                    rb'(....)' # BRANCH_TO_ANDROIDLOGPRINT

                    # ORIGINAL_CODE_3 - won't be modified
                    rb'(......(?:.\xd1|\x02\xbf|.{6}\x02\xbf)'
                        # MOV r0, RSTRUCT. RSTRUCT contains the address of the ExynosCameraSensorInfo struct
                        rb'(.\x46)' # MOV_R0_RSTRUCT
                    rb')'
                ),
                replacement=(
                    asm('nop', False) * 2 +
                    b'\\1' +
                    # These NOPs will be replaced with our mod instructions
                    asm('nop', False) * 7 +
                    b'\\5'
                )
            ),
            ###################################################################
            ######################### 64-BIT PATTERNS #########################
            ###################################################################
            # 64-bit Exynos 9610/9611 patterns need to go first since they match the 1280/7884/7904/9825
            # one but have an extra instruction before the branch, so it should have a higher priority
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 10-12) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'(...\x52|...\x32)' # MOV_WX_X
                    rb'.\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9.{0,4}...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 12 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 9610/9611 (Android 9) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'(...\x52|...\x32)' # MOV_WX_X
                    rb'...\x91.\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 12 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 850 (Android 13) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'.\x03.\x2a'
                    rb'(...\x52|...\x32)' # MOV_WX_X
                    rb'.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa).{0,4}...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 12 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 1280 (Android 14) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    # The MOVs are in a different order but it doesn't matter
                    rb'(...\x52)' # MOV_WX_X
                    rb'...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'.\x03.\x2a.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 12 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 1280 (Android 13) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'()' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    # The MOVs are in a different order but it doesn't matter
                    rb'(...\x52)' # MOV_WX_X
                    rb'...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 11 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 990/7884/7904/9611/9825 (Android 10-14) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'(...\x52|...\x32)' # MOV_WX_X
                    rb'.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9(?:...\xf9)?...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 11 +
                    b'\\5'
                )
            ),
            LibModificationPattern(
                name='Exynos 7884/7904/9825 (Android 9) (64-bit)',
                is_64bit=True,
                pattern=(
                    rb'(\x52|\x91....)' # ORIGINAL_CODE_1
                    rb'...............\x91...\x91...\x91'
                    rb'(....)' # MOV_RX_FOUR
                    rb'(...\x52|...\x32)' # MOV_WX_X
                    rb'...\x91.\x03.\x2a(....)' # BRANCH_TO_ANDROIDLOGPRINT
                    rb'(.{0,4}...\xf9.......\xeb...\x54(.\x03.\xaa)...\xa9...\xa9...\xa9)' # ORIGINAL_CODE_2 & MOV_R0_RSTRUCT
                ),
                replacement=(
                    b'\\1' +
                    asm('nop', True) * 11 +
                    b'\\5'
                )
            )
        ]
    )

    pattern, match = mod.try_match(lib_data)
    if pattern is None or match is None:
        sys.exit(1)

    # Ensure the last instruction we replaced with a NOP is a branch instruction
    assert(disasm(match[Groups.BRANCH_TO_ANDROIDLOGPRINT], pattern.is_64bit)[0] in ['b', 'bl', 'blx'])

    # Get registers
    free_reg = disasm_mov(match[Groups.MOV_RX_FOUR], pattern.is_64bit)[0]
    free_reg2 = ''
    if pattern.is_64bit:
        free_reg2 = disasm_mov(match[Groups.MOV_WX_X], pattern.is_64bit)[0]
    struct_reg = disasm_mov(match[Groups.MOV_R0_RSTRUCT], pattern.is_64bit)[1]
    print(f'ExynosCameraSensorInfo struct register: {struct_reg} Free register(s): {free_reg} {free_reg2}')
    assert(struct_reg != free_reg)
    assert(struct_reg != free_reg2)
    assert(free_reg != free_reg2)
    assert(isinstance(struct_reg, str))

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

        # ensure the required NOPs are consecutive, since some patterns may keep
        # original instructions between NOPs and that could mess up the instruction order
        if rep.count(nop * required_nops) <= 0:
            print('[!] Pattern has not enough space left, try again with less modifications')
            sys.exit(1)

        rep = rep.replace(
            nop * required_nops, b''.join(instructions), 1
        )
        current_position += required_nops * len(nop)

    # Find struct offsets
    available_cap_offset, hw_lvl_offset = find_capabilities_and_hw_level_offsets(lib_data)

    # Lets start with modifications that require reading the value of
    # available capabilities, so we only need a single LDR instruction
    if skip_depth_cameras or capabilities is not None:
        replace_nops([
            asm(f'ldr {free_reg}, [{struct_reg}, #{available_cap_offset}]', pattern.is_64bit)
        ])

        # Add conditional branch to skip depth cameras
        if skip_depth_cameras:
            instructions = []
            branch_offset = mod_len - current_position

            if pattern.is_64bit:
                instructions.append(
                    asm(f'tbnz {free_reg}, #7, {branch_offset}', True)
                )
            else:
                instructions.append(
                    asm(f'TST {free_reg}, {Capability.DEPTH_OUTPUT}', False),
                )
                branch_offset -= len(instructions[0])
                instructions.append(
                    asm(f'bne {branch_offset}', False)
                )

            replace_nops(instructions)
            print('[+] Added conditional to skip depth cameras')

        # Modify available capabilities
        if capabilities is not None:
            value = 0
            enabled_caps = []
            for cap in capabilities:
                value |= cap
                enabled_caps.append(Capability(cap).name)

            instructions = []
            # ORR in ARM64 doesn't support many immediate values. If it works for value then great,
            # otherwise we need to store value into another register first
            try:
                instructions.append(
                    asm(f'orr {free_reg}, {free_reg}, #{value}', pattern.is_64bit)
                )
            except KsError:
                if not pattern.is_64bit:
                    raise KsError('Unknown error')

                instructions.append(
                    asm(f'mov {free_reg2}, #{value}', pattern.is_64bit)
                )
                instructions.append(
                    asm(f'orr {free_reg}, {free_reg}, {free_reg2}', pattern.is_64bit)
                )

            instructions.append(
                asm(f'str {free_reg}, [{struct_reg}, #{available_cap_offset}]', pattern.is_64bit)
            )
            replace_nops(instructions)
            print(f'[+] Enabled capabilities: {", ".join(enabled_caps)}')

    # Set hardware level
    if hw_level is not None:
        mov = 'mov' if pattern.is_64bit else 'movs'
        replace_nops([
            asm(f'{mov} {free_reg}, #{hw_level}', pattern.is_64bit),
            asm(f'strb {free_reg}, [{struct_reg}, #{hw_lvl_offset}]', pattern.is_64bit)  
        ])
        print(f'[+] Hardware level set to {hw_level} ({HardwareLevel(hw_level).name})')

    assert(len(rep) == len(pattern.replacement))
    pattern.replacement = rep
    return mod

########################################################################
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'camera_lib', type=argparse.FileType('rb'),
        help='Path of the 32-bit libexynoscamera3.so'
    )
    parser.add_argument(
        'camera_lib_64', type=argparse.FileType('rb'),
        help='Path of the 64-bit libexynoscamera3.so'
    )

    mod_options = parser.add_argument_group('Lib Modifications')
    mod_options.add_argument(
        '-hw', type=int,
        choices=list(HardwareLevel),
        help='The hardware level that will be set'
    )
    mod_options.add_argument(
        '-cap', type=int,
        choices=list(Capability), nargs='+',
        help='The capabilities that will be enabled, separated by spaces'
    )
    mod_options.add_argument(
        '--skip-depth', action='store_true',
        help=(
            'Skips modifications on cameras with the "Depth Output" capability. '
            'Recommended if your device has a depth camera since the lib can crash if you enable RAW on them, for example.'
        )
    )

    module_options = parser.add_argument_group(
        'Magisk Module',
        'If all these settings are provided, a Magisk module with both patched libs will be created'
    )
    module_options.add_argument(
        '--model', type=str,
        help='The device model (e.g. Galaxy A20)'
    )
    module_options.add_argument(
        '--android-version', type=int,
        help='The Android version (e.g. 11)'
    )
    module_options.add_argument(
        '--version', type=int,
        help='The module version (e.g. 1)'
    )

    return parser.parse_args()

def main():
    args = parse_args()
    if args.cap is None and args.hw is None:
        print('[!] No modifications specified')
        sys.exit(1)

    patched_lib = 'libexynoscamera3_patched.so'
    patched_lib_64 = 'libexynoscamera3_patched_64.so'
    lib_data = args.camera_lib.read()
    lib_data_len = len(lib_data)
    lib_data_64 = args.camera_lib_64.read()
    lib_data_64_len = len(lib_data_64)
    args.camera_lib.close()
    args.camera_lib_64.close()

    # Patch 32-bit lib
    print('[*] Patching 32-bit lib...')
    mod = build_sensor_info_struct_mod(
        lib_data, capabilities=args.cap, hw_level=args.hw,
        skip_depth_cameras=args.skip_depth
    )
    lib_data = apply_modification(lib_data, mod)
    with open(patched_lib, 'wb') as f:
        f.write(lib_data)
        print(f'[*] Patched lib saved as "{patched_lib}"')

    # Patch 64-bit lib
    print('\n[*] Patching 64-bit lib...')
    mod = build_sensor_info_struct_mod(
        lib_data_64, capabilities=args.cap, hw_level=args.hw,
        skip_depth_cameras=args.skip_depth
    )
    lib_data_64 = apply_modification(lib_data_64, mod)
    with open(patched_lib_64, 'wb') as f:
        f.write(lib_data_64)
        print(f'[*] Patched lib saved as "{patched_lib_64}"')

    # Ensure we didn't add nor remove instructions
    assert(len(lib_data) == lib_data_len)
    assert(len(lib_data_64) == lib_data_64_len)

    # Create Magisk module
    print()
    if (args.model is not None and args.android_version is not None and
            args.version is not None):
        modifications=''
        if args.cap is not None:
            modifications += (
                'enables ' + ', '.join([Capability(x).name for x in args.cap]) + ' capabilities'
            )
        if args.hw is not None:
            if len(modifications) > 0:
                modifications += ' and '
            modifications += f'sets the hardware level to {HardwareLevel(args.hw).name}'

        modifications = modifications[0].upper() + modifications[1:]

        create_magisk_module(
            patched_lib, patched_lib_64, args.model,
            str(args.android_version), str(args.version), modifications
        )        

def apply_modification(lib_data: bytes, mod: LibModification) -> bytes:
    patched_data = mod.try_patch(lib_data)
    if patched_data is None:
        print(f'[!] Could not apply "{mod.name}"')
        sys.exit(1)

    print(f'[+] Applied "{mod.name}"')
    return patched_data

def create_magisk_module(lib_path: str, lib_path_64: str,
                         model: str, android_version: str, version: str,
                         modifications: str):
    module_base_dir = os.path.join(os.getcwd(), 'ModuleBase')
    if not os.path.isdir(module_base_dir):
        print(f'"[!] {module_base_dir}" not found')
        sys.exit(1)

    tmp_dir = module_base_dir + 'Temp'
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir)
    shutil.copytree(module_base_dir, tmp_dir)

    dst_32 = os.path.join(tmp_dir, 'system/vendor/lib/libexynoscamera3.so')
    dst_64 = os.path.join(tmp_dir, 'system/vendor/lib64/libexynoscamera3.so')
    os.makedirs(os.path.dirname(dst_32), exist_ok=True)
    os.makedirs(os.path.dirname(dst_64), exist_ok=True)
    shutil.copy(lib_path, dst_32)
    shutil.copy(lib_path_64, dst_64)

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

if __name__ == '__main__':
    main()
