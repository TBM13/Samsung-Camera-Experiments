#!/usr/bin/python3
import argparse
import enum
import os

from capstone.arm64_const import ARM64_OP_IMM
from keystone import KsError

from common.android_camera_metadata import SupportedHardwareLevel
from common.patch_utils import *
from common.utils import abort, create_magisk_module, warn


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

def create_mod_cave(lib: Lib) -> Mod:
    # CameraCapability::getValueStr takes a capabilities bitmask and a string buffer.
    # It builds a string listing the enabled capabilities. We can initialize the
    # buffer to an empty string and return early so as to create a code cave
    function = lib.find_symbol('^_ZNK16CameraCapability11getValueStrEv$')
    if function is None:
        abort('Failed to find CameraCapability::getValueStr function')
    
    print('[+] Found CameraCapability::getValueStr function')
    func_start_addr = VirtualAddress(function.rebased_addr, True)
    func_start: Block = lib.project.factory.block(function.rebased_addr, size=20 * 4)
    func_start_insns: list[CsInsn] = func_start.capstone.insns

    # Search for the empty string initialization at the start of getValueStr
    # TODO: We should probably do a RDA here
    movs: dict[str, str] = {}
    empty_bytes_initialized: dict[str, int] = {}
    for ins in func_start_insns:
        ins: CsInsn = ins
        if ins.mnemonic == 'mov':
            dst = reg_name(ins.operands[0].reg, lib.is_aarch64)
            src = reg_name(ins.operands[1].reg, lib.is_aarch64)
            movs[dst] = src
        
        elif ins.mnemonic == 'stp':
            src1 = reg_name(ins.operands[0].reg, lib.is_aarch64)
            src2 = reg_name(ins.operands[1].reg, lib.is_aarch64)
            if src1 != 'xzr' or src2 != 'xzr':
                continue

            dst = reg_name(ins.operands[2].reg, lib.is_aarch64)
            offset = ins.operands[2].mem.disp
            if offset != 0 and offset != 8:
                abort(f'Unexpected offset {offset} in empty string initialization')

            empty_bytes_initialized.setdefault(dst, 0)
            empty_bytes_initialized[dst] += 8
        
        elif ins.mnemonic == 'str':
            src = reg_name(ins.operands[0].reg, lib.is_aarch64)
            if src != 'xzr':
                continue

            dst = reg_name(ins.operands[1].reg, lib.is_aarch64)
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

    # Initialize empty string at the start of the function and return
    empty_str_init = bytearray()
    has_paciasp = False
    if func_start_insns[0].mnemonic == 'paciasp':
        # Preserve paciasp, otherwise lib will crash
        empty_str_init += func_start_insns[0].bytes
        sp_reservation: CsInsn = func_start_insns[1]
        has_paciasp = True

        print('[*] Lib has Pointer Authentication')
    else:
        sp_reservation: CsInsn = func_start_insns[0]

    if (sp_reservation.mnemonic != 'sub'
        or reg_name(sp_reservation.operands[0].reg, lib.is_aarch64) != 'sp'
        or reg_name(sp_reservation.operands[1].reg, lib.is_aarch64) != 'sp'
    ):
        abort(f'Unexpected instruction "{sp_reservation.mnemonic} {sp_reservation.op_str}"')

    empty_str_init += asm([
        # empty string initialization
        f'STP XZR, XZR, [{str_reg}]',
        f'STR XZR, [{str_reg}, #16]',
    ], lib.is_aarch64)
    if has_paciasp:
        empty_str_init += b'\xBF\x23\x03\xD5'  # AUTIASP
    empty_str_init += asm('RET', lib.is_aarch64)

    # Apply empty string initialization
    lib.apply_patch(func_start_addr, empty_str_init)
    return Mod(
        start_addr=func_start_addr + len(empty_str_init),
        max_size=function.size - len(empty_str_init),
        is_aarch64=lib.is_aarch64
    )

def apply_capabilities_mod(
        lib: Lib, mod: Mod,
        hw_level: SupportedHardwareLevel|None = None, 
        enable_capabilities: list[Capability]|None = None
    ):
    # CameraCapability::init takes the hw level and the camera's capabilities bitmask,
    # then sets the hw level and adds more capabilities (or not) depending on its value.
    init = lib.find_symbol(r'^_ZN16CameraCapability4initEh29AvailableCameraCapabilityType$')
    if init is None:
        abort('Failed to find CameraCapability::init function')
    bitmask_reg = 'x2'
    print('[+] Found CameraCapability::init function')

    # find MOV <reg>, #1 instruction
    init_block: Block = lib.project.factory.block(init.rebased_addr, size=init.size)
    init_insns: list[CsInsn] = init_block.capstone.insns
    mov_candidates: list[CsInsn] = []
    for ins in init_insns:
        if ins.mnemonic == 'mov' and len(ins.operands) == 2:
            if ins.operands[1].type == ARM64_OP_IMM and ins.operands[1].imm == 1:
                mov_candidates.append(ins)
                continue

        if len(mov_candidates) == 0:
            # We are assuming the MOV is one of the first instructions of the function,
            # so lets ensure that previous instructions don't do anything fancy
            if ins.mnemonic in ['paciasp', 'bti']:
                continue
            if 'sp' in ins.op_str:
                continue

            ins = f"{ins.mnemonic} {ins.op_str}".strip()
            abort(f'Unexpected instruction "{ins}" before MOV instruction')

    if len(mov_candidates) == 0:
        abort('Failed to find MOV <reg>, #1 instruction')
    if len(mov_candidates) > 1:
        abort('Multiple MOV <reg>, #1 instructions found')
    init_mov_ins = mov_candidates[0]

    # Since we will move the MOV instruction to the end of the mod,
    # we can use its target register as a free register in the mod
    free_reg = reg_name(init_mov_ins.operands[0].reg, lib.is_aarch64).replace('w', 'x')
    print(f'[+] Found MOV instruction and free register {free_reg}')

    # Replace the MOV with a branch to the mod
    init_mov_ins_addr = VirtualAddress(init_mov_ins.address, True)
    lib.apply_patch(
        init_mov_ins_addr, mod.assemble_branch_to_mod(lib, init_mov_ins_addr)
    )

    # Add the MOV at the end of the mod
    mod.add_exit_instruction(init_mov_ins.bytes)

    ########################## MOD ##########################
    # Set hardware level (modify hw level argument)
    if hw_level is not None:
        mod.add_instruction(f'mov w1, #{hw_level.value}')
        print(f'- Changing hardware level to {hw_level.name}')

    # Enable capabilities (modify bitmask argument)
    if enable_capabilities is not None:
        value = 0
        for cap in enable_capabilities:
            value |= cap.value
        try:
            mod.add_instruction(f'orr {bitmask_reg}, {bitmask_reg}, #{value}')
        except KsError:
            # ORR doesn't support the immediate value, so store it in a register
            mod.add_instruction(f'mov {free_reg}, #{value}')
            mod.add_instruction(f'orr {bitmask_reg}, {bitmask_reg}, {free_reg}')

        cap = ', '.join([c.name for c in enable_capabilities])
        print(f'- Enabling capabilities: {cap}')

    # Exit mod (execute whatever was after the MOV instruction in init)
    exit_address: VirtualAddress = init_mov_ins_addr + init_mov_ins.size
    mod.add_exit_instruction(
        f'b 0x{exit_address.linked_addr(lib):x}'
    )

    lib.apply_patch(
        mod.start_addr, mod.assemble(lib)
    )

########################################################################
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'libs', type=argparse.FileType('rb'), nargs='+',
        help='Path(s) of the lib(s) that will be patched'
    )

    mod_options = parser.add_argument_group('Lib Modifications')
    hw_level_map = {
        name.lower(): level for name, level in SupportedHardwareLevel.__members__.items()
    }
    capabilities_map = {
        name.lower(): cap for name, cap in Capability.__members__.items()
    }

    mod_options.add_argument(
        '--hardware-level',
        type=lambda v: hw_level_map.get(v.lower()) or abort(f'Invalid hardware level: {v}'),
        metavar='HARDWARE_LEVEL',
        help='The hardware level that will be set'
    )
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
    parser.epilog = 'HARDWARE_LEVEL can be:\n  ' + '\n  '.join([lvl.name for lvl in SupportedHardwareLevel])
    parser.epilog += '\n\n'
    parser.epilog += 'CAPABILITY can be:\n  ' + '\n  '.join([c.name for c in Capability])

    return parser.parse_args()

def main():
    args = parse_args()
    if (args.hardware_level is None and
        args.enable_cap is None):
        abort('No modifications specified')

    out_libs: list[str] = []
    for file in args.libs:
        print(f'\n[*] Patching "{file.name}"...')
        lib = Lib(file.read())
        file.close()

        if 'libexynoscamera3.so' in lib.lib.deps:
            # Exynos 1280 devices include a camera.s5e8825.so lib
            # that is a wrapper for libexynoscamera3.so
            warn('The lib depends on libexynoscamera3.so. You should patch that one instead')

        if not lib.is_aarch64:
            # So far I haven't found any 32-bit camera.s5eXXXX.so lib
            abort('32-bit libs are not supported')

        mod = create_mod_cave(lib)
        apply_capabilities_mod(
            lib=lib, mod=mod,
            hw_level=args.hardware_level,
            enable_capabilities=args.enable_cap,
        )

        base, _ = os.path.splitext(file.name)
        output_path = f'{base}_patched.so'
        lib.write_to_file(output_path)

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
            mods.append('enables ' + ', '.join([x.name for x in args.enable_cap]))
        if args.hardware_level is not None:
            mods.append(f'sets hardware level to {args.hardware_level.name}')

        create_magisk_module(
            lib_name='hw/' + args.lib_name,
            libs=out_libs,
            model=args.model, android_version=args.android_version,
            module_version=args.version, description=', '.join(mods)
        )

if __name__ == '__main__':
    main()