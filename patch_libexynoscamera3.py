#!/usr/bin/python3
import argparse
import enum
import math
import os
import re
from typing import Generator

import lief
from common.android_camera_metadata import SupportedHardwareLevel
from common.utils import abort, create_magisk_module
from common.patch_utils import *

class Capability(enum.IntEnum):
    MANUAL_SENSOR_AND_READ_SENSOR_SETTINGS = 2
    MANUAL_POST_PROCESSING = 4
    BURST_CAPTURE = 8
    RAW = 16
    ZSL_AND_PRIVATE_REPROCESSING = 32
    YUV_REPROCESSING = 64
    DEPTH_OUTPUT = 128
    CONSTRAINED_HIGH_SPEED_VIDEO = 256
    MOTION_TRACKING = 512
    LOGICAL_MULTI_CAMERA = 1024
    SECURE_IMAGE_DATA = 2048

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
        print(f'- Changing hardware level to {hw_level} ({SupportedHardwareLevel(hw_level).name})')

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
        choices=list(SupportedHardwareLevel),
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

        if lib is None:
            abort(f'Failed to parse "{file.name}" as an ELF binary')

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
            mods.append(f'enables ' + ', '.join([Capability(x).name for x in args.enable_cap]))
        if args.disable_cap is not None:
            mods.append(f'disables ' + ', '.join([Capability(x).name for x in args.disable_cap]))
        if args.hardware_level is not None:
            mods.append(f'sets hardware level to {SupportedHardwareLevel(args.hardware_level).name}')

        create_magisk_module(
            lib_name='libexynoscamera3.so',
            libs=out_libs,
            model=args.model, android_version=args.android_version,
            module_version=args.version, description=', '.join(mods)
        )

if __name__ == '__main__':
    main()