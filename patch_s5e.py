#!/usr/bin/python3
import argparse
import enum
import os
from typing import Generator

import lief
from common.utils import abort, create_magisk_module
from common.patch_utils import *

class Capability(enum.IntEnum):
    # BackwardCompatible = 1     - Always enabled, so no need to list it
    ManualSensor_ReadSensorSettings = 2
    ManualPostProcessing = 4
    RAW = 8
    PrivateReprocessing = 16
    BurstCapture = 32
    YUVReprocessing = 64
    MotionTracking = 128

    LogicalMultiCamera = 256
    SecureImageData = 512
    SystemCamera = 1024
    OfflineProcessing = 2048
    ControlZoom = 4096
    LensCal = 8192
    StreamUseCase = 16384
    DynamicRangeTenBit = 32768

    ColorSpaceProfiles = 65536

def capabilities_mod(lib: lief.ELF.Binary,
                     enable_capabilities: list[int]|None = None
    ) -> Generator[tuple[int, bytes], None, None]:
    aarch64 = True

    # CameraCapability::getValueStr takes a capabilities bitmask and a string buffer.
    # It then builds a string listing the enabled capabilities. We can initialize the buffer
    # to an empty string, return early and replace the following instructions with our mod.
    getValueStr_func = Function.from_name_single(
        lib, '^_ZNK16CameraCapability11getValueStrEv$'
    )
    print(f'[+] Found CameraCapability::getValueStr function')

    # Search for the empty string initialization at the start of getValueStr
    movs: dict[str, str] = {}
    empty_bytes_initialized: dict[str, int] = {}
    for ins in getValueStr_func.instructions(amount=20 * 4):
        if ins.mnemonic == 'mov':
            dst = reg_name(ins.operands[0].reg, aarch64)
            src = reg_name(ins.operands[1].reg, aarch64)
            movs[dst] = src
        
        elif ins.mnemonic == 'stp':
            src1 = reg_name(ins.operands[0].reg, aarch64)
            src2 = reg_name(ins.operands[1].reg, aarch64)
            if src1 != 'xzr' or src2 != 'xzr':
                continue

            dst = reg_name(ins.operands[2].reg, aarch64)
            offset = ins.operands[2].mem.disp
            if offset != 0 and offset != 8:
                abort(f'Unexpected offset {offset} in empty string initialization')

            empty_bytes_initialized.setdefault(dst, 0)
            empty_bytes_initialized[dst] += 8
        
        elif ins.mnemonic == 'str':
            src = reg_name(ins.operands[0].reg, aarch64)
            if src != 'xzr':
                continue

            dst = reg_name(ins.operands[1].reg, aarch64)
            offset = ins.operands[1].mem.disp
            if offset != 0 and offset != 16:
                abort(f'Unexpected offset {offset} in empty string initialization')

            empty_bytes_initialized.setdefault(dst, 0)
            empty_bytes_initialized[dst] += 4

    if len(empty_bytes_initialized) == 0:
        abort('Failed to find empty string initialization')
    if len(empty_bytes_initialized) > 1:
        abort('Multiple possible empty string initializations found')
    str_reg, initialized_bytes = next(iter(empty_bytes_initialized.items()))
    if initialized_bytes != 4 * 3:  # the empty string should have 3 null bytes
        abort(f'Unexpected number of initialized bytes ({initialized_bytes})')
    if str_reg in movs:
        str_reg = movs[str_reg]
        if str_reg in movs:
            abort(f'Too many movs to resolve register {str_reg}')

    print(f'[+] Found string register {str_reg}')
    first_instructions = list(getValueStr_func.instructions(amount=8))

    # Initialize empty string at the start of the function and return
    empty_string_initialization = bytes()
    has_paciasp = False
    if first_instructions[0].mnemonic == 'paciasp':
        # Preserve paciasp, otherwise lib will crash
        empty_string_initialization += getValueStr_func.bytes(amount=4)
        sp_reservation = first_instructions[1]
        has_paciasp = True

        print('[*] Lib has Pointer Authentication')
    else:
        sp_reservation = first_instructions[0]

    if (sp_reservation.mnemonic != 'sub'
        or reg_name(sp_reservation.operands[0].reg, aarch64) != 'sp'
        or reg_name(sp_reservation.operands[1].reg, aarch64) != 'sp'
    ):
        abort(f'Unexpected instruction "{sp_reservation.mnemonic} {sp_reservation.op_str}"')

    empty_string_initialization += asm([
        # empty string initialization
        f'STP XZR, XZR, [{str_reg}]',
        f'STR XZR, [{str_reg}, #16]',
    ], aarch64)
    if has_paciasp:
        empty_string_initialization += b'\xBF\x23\x03\xD5'  # AUTIASP
    empty_string_initialization += asm('RET', aarch64)

    yield getValueStr_func.address, empty_string_initialization

    # Prepare mod
    mod: list[bytes] = []
    mod_tail: list[bytes] = []
    mod_address = getValueStr_func.address + len(empty_string_initialization)

    # CameraCapability::init takes the hw level and the camera's capabilities bitmask,
    # then sets the hw level and adds more capabilities (or not) depending on its value.
    init_func = Function.from_name_single(
        lib, '^_ZN16CameraCapability4initEh29AvailableCameraCapabilityType$'
    )
    bitmask_reg = 'x2'
    print(f'[+] Found CameraCapability::init function')

    first_instructions: list[CsInsn] = list(init_func.instructions(amount=8))
    if first_instructions[0].mnemonic == 'bti':
        init_mov_ins = first_instructions[1]
        print('[*] Lib has Branch Target Identification')
    else:
        init_mov_ins = first_instructions[0]

    if init_mov_ins.mnemonic != 'mov':
        abort(f'Unexpected first instruction {init_mov_ins.mnemonic}')
    # MOV <reg>, #1   - We can consider reg free
    free_reg = reg_name(init_mov_ins.operands[0].reg, aarch64).replace('w', 'x')
    print(f'[+] Found free register {free_reg}')

    # Add the mov at the end of the mod
    mod_tail.append(init_mov_ins.bytes)
    # Replace init's mov with a branch to the mod
    branch_offset = mod_address - (init_func.address + init_mov_ins.address)
    yield init_func.address + init_mov_ins.address, asm(f'b #{branch_offset}', aarch64)

    ########################## MOD ##########################
    # When exiting the mod we want to execute whatever was after the MOV instruction
    exit_address = init_func.address + init_mov_ins.address + init_mov_ins.size

    # Enable capabilities (modify bitmask argument)
    if enable_capabilities is not None:
        value = 0
        for cap in enable_capabilities:
            value |= cap
        try:
            mod.append(
                asm(f'orr {bitmask_reg}, {bitmask_reg}, #{value}', aarch64)
            )
        except KsError:
            # ORR doesn't support the immediate value, so store it in a register
            mod.extend([
                asm(f'mov {free_reg}, #{value}', aarch64),
                asm(f'orr {bitmask_reg}, {bitmask_reg}, {free_reg}', aarch64)
            ])

        caps = ', '.join([Capability(x).name + f' ({x})' for x in enable_capabilities])
        print(f'- Enabling capabilities: {caps}')

    # Exit mod
    mod += mod_tail
    mod_size = sum(len(b) for b in mod)
    branch_offset = exit_address - (mod_address + mod_size)
    mod.append(asm(f'b #{branch_offset}', aarch64))

    mod = b''.join(mod)
    if len(mod) > getValueStr_func.size - (mod_address - getValueStr_func.address):
        abort('Mod doesn\'t fit in the available space')

    yield mod_address, mod

########################################################################
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'libs', type=argparse.FileType('rb'), nargs='+',
        help='Path(s) of the lib(s) that will be patched'
    )

    mod_options = parser.add_argument_group('Lib Modifications')
    capabilities_map = {
        name.lower(): cap.value for name, cap in Capability.__members__.items()
    }

    mod_options.add_argument(
        '--enable-cap',
        type=lambda v: capabilities_map.get(v.lower()) or abort(f'Invalid capability: {v}'),
        nargs='+',
        metavar='CAPABILITY',
        help='The capabilities that will be enabled, separated by space.'
    )

    module_options = parser.add_argument_group(
        'Magisk Module',
        'If all the following args are provided, a Magisk module with the patched lib(s) will be created'
    )
    module_options.add_argument(
        '--lib-name', type=str,
        help='The name of the lib (e.g. camera.s5e9925.so)'
    )
    module_options.add_argument(
        '--model', type=str,
        help='The device the lib comes from (e.g. Galaxy A54)'
    )
    module_options.add_argument(
        '--android-version', type=int,
        help='The Android version the lib comes from (e.g. 15)'
    )
    module_options.add_argument(
        '--version', type=int,
        help='The module version (e.g. 1)'
    )

    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = 'CAPABILITY can be:\n  ' + '\n  '.join([c.name for c in Capability])

    return parser.parse_args()

def main():
    args = parse_args()
    if args.enable_cap is None:
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
        if lib.header.machine_type != lief.ELF.ARCH.AARCH64:
            # So far I haven't found a 32-bit camera.s5eXXXX.so lib
            abort('32-bit libs are not supported')

        print(f'\n[*] Patching "{file.name}"...')
        for address, bytes in capabilities_mod(
            lib=lib,
            enable_capabilities=args.enable_cap,
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
        and args.lib_name is not None
    ):
        mods = []
        if args.enable_cap is not None:
            mods.append(f'enables ' + ', '.join([Capability(x).name for x in args.enable_cap]))

        create_magisk_module(
            lib_name='hw/' + args.lib_name,
            libs=out_libs,
            model=args.model, android_version=args.android_version,
            module_version=args.version, description=', '.join(mods)
        )

if __name__ == '__main__':
    main()