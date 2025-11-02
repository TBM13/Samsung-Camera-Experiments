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
    LensCA = 8192
    StreamUseCase = 16384
    DynamicRangeTenBit = 32768

def capabilities_mod(lib: lief.ELF.Binary,
                     enable_capabilities: list[int]
    ) -> Generator[tuple[int, bytes], None, None]:
    init_func = Function.from_name_single(
        lib, '^_ZN16CameraCapability4initEh29AvailableCameraCapabilityType$'
    )
    print(f'[+] Found CameraCapability::init function')

    # CameraCapability::init takes an int and the camera's capabilities bitmask
    # That int is presumably the hw level and depending on its value, extra capabilities are enabled:
    # 0 (LIMITED): BackwardCompatible
    # 1 (FULL)   : BackwardCompatible, ManualSensor_ReadSensorSettings, ManualPostProcessing, BurstCapture
    # 3 (LEVEL 3): BackwardCompatible, ManualSensor_ReadSensorSettings, ManualPostProcessing, BurstCapture, RAW, YUVReprocessing
    # We will add our capabilities to those three cases
    value = 1
    for cap in enable_capabilities:
        value |= cap

    caps = ', '.join([Capability(x).name + f' ({x})' for x in enable_capabilities])
    print(f'- Enabling capabilities: {caps}')

    mov_amount = 0
    register = None
    for ins in init_func.instructions():
        if ins.mnemonic != 'mov':
            continue

        mov_amount += 1
        reg_name = cs_aarch64.reg_name(ins.operands[0].reg)
        register = register or reg_name
        if reg_name != register:
            abort(f'Register {ins.operands[0].reg} does not match {register}')

        immediate = ins.operands[1].imm
        if immediate not in (1, 39, 111):
            abort(f'Unexpected immediate {immediate}')

        yield init_func.address + ins.address, asm(
            f'mov {register}, #{value | immediate}', True
        )

    if mov_amount != 3:
        abort(f'Unexpected number of mov instructions ({mov_amount})')

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