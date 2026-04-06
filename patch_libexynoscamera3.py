#!/usr/bin/python3
import argparse
import enum
import logging
import math
import os
import re

# angr prints an error when it's imported and unicorn engine is not installed
logging.getLogger('angr').setLevel(logging.CRITICAL)

from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from claripy.ast.bv import BV
from keystone import KsError

from common.android_camera_metadata import CameraMetadataTag, SupportedHardwareLevel
from common.patch_utils import *
from common.utils import abort, create_magisk_module, warn


class Capability(enum.IntEnum):
    ManualSensor_ReadSensorSettings = 2
    ManualPostProcessing = 4
    BurstCapture = 8
    RAW = 16
    ZSL_PrivateReprocessing = 32
    YUVReprocessing = 64
    DepthOutput = 128
    ConstrainedHighSpeedVideo = 256
    MotionTracking = 512
    LogicalMultiCamera = 1024
    SecureImageData = 2048

class Lib3(Lib):
    def __init__(self, bytes: bytes):
        super().__init__(bytes)

        self._is_legacy = self.find_symbol(
            r'^_ZN7android\d\dExynosCameraMetadataConverter29m_createAvailableCapabilities.+'
        ) is None

        if self.is_legacy:
            abort('Legacy lib detected. Patching these libs is not supported yet')
            warn('Legacy lib detected. Patching these libs is highly experimental!')

    @property
    def is_legacy(self) -> bool:
        """If true, this is a legacy libexynoscamera3 lib (from
        devices that launched with Android 8 or earlier).
        
        The main difference is that the capabilities are stored as an
        array instead of a bitmask.
        """
        return self._is_legacy

def _find_capabilities_and_hwlevel_offsets(lib: Lib3) -> dict[CameraMetadataTag, int]:
    aarch64 = lib.is_aarch64
    func = lib.find_symbol(
        r'^_ZN7android\d\dExynosCamera3?MetadataConverter29m_createAvailableCapabilities.+'
    )
    if func is None:
        # this is normal on legacy libs
        if lib.is_legacy:
            return {}

        abort('Failed to find m_createAvailableCapabilities function')
    if 'ExynosCamera3' in func.name or lib.is_legacy:
        # this function should not be present on legacy libs
        abort('Failed to determine whether the lib is legacy or not')

    # The first arg of the function contains the camera config struct.
    # At the start there is an android_log_print call that logs the
    # hw level and the capabilities. We can grab the offsets there.
    block: Block = lib.project.factory.block(
        func.rebased_addr, size=min(func.size, 120 if aarch64 else 70)
    )

    expected_blocks = [
        InstructionsBlockPattern('Generic (32-bit)', False, [
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
        InstructionsBlockPattern('Generic (64-bit)', True, [
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
    matches = match_single_instruction_block(block.bytes, expected_blocks)
    hw_offset =  int(matches[2], 16)
    cap_offset = int(matches[4], 16)
    print(hex(hw_offset), hex(cap_offset))

    if hw_offset <= 0 or hw_offset >= 0x1000:
        abort(f'Invalid hardware level offset: {hex(hw_offset)}')
    if cap_offset <= 0 or cap_offset >= 0x1000:
        abort(f'Invalid capabilities offset: {hex(cap_offset)}')
    # Both offsets are usually close to each other
    if abs(cap_offset - hw_offset) > 8:
        warn('Abnormal offset difference, one or both may be wrong')
    if hw_offset == cap_offset:
        abort('Both offsets have the same value')

    return {
        CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL: hw_offset,
        CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES: cap_offset
    }

def find_struct_offsets(lib: Lib3, tags: list[CameraMetadataTag]) -> dict[CameraMetadataTag, int]:
    tag_offsets: dict[CameraMetadataTag, int] = {}

    # On non-legacy libexynoscamera3 libs we can get these two offsets directly
    # in ExynosCameraMetadataConverter::m_createAvailableCapabilities.
    # It's quicker and also a necessity if we want the capabilities offset
    # (it can't be obtained in constructStaticInfo).
    if (CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL in tags
        or CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES in tags):
        tag_offsets.update(
            _find_capabilities_and_hwlevel_offsets(lib)
        )

        # Return early if we found all the requested offsets
        if all(tag in tag_offsets for tag in tags):
            return tag_offsets
    
    construct_static_info = lib.find_symbol(
        r'^_ZN7android\d\dExynosCamera3?MetadataConverter19constructStaticInfo.+'
    )
    if construct_static_info is None:
        abort('Failed to find constructStaticInfo function')
    if 'ExynosCamera3' in construct_static_info.name and not lib.is_legacy:
        abort('Failed to determine whether the lib is legacy or not')

    print('[+] Found constructStaticInfo function, analyzing...')
    cfg = lib.project.analyses.CFGFast(
        normalize=True,

        # Only scan constructStaticInfo and all the functions it calls
        function_starts=[construct_static_info.rebased_addr],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        function_prologues=False,
        symbols=False,

        # Optimizations
        data_references=False,
    )

    # constructStaticInfo is filled with calls to CameraMetadata::update.
    # The second arg of these calls is the camera metadata tag and the third
    # arg is the value for that metadata.
    func = cfg.functions[construct_static_info.rebased_addr]
    # Find all the CameraMetadata::update calls
    update_calls: list[int] = list(
        ins.address for ins, f in get_called_functions(lib, func) if 'CameraMetadata6update' in f.name
    )
    if len(update_calls) == 0:
        abort('No CameraMetadata::update calls found')
    print(f'   + Found {len(update_calls)} CameraMetadata::update calls')

    # Lets find the values of r1 and r2 at each CameraMetadata::update call
    obs_points = [('insn', addr, OP_BEFORE) for addr in update_calls]
    rda = lib.project.analyses.ReachingDefinitions(
        subject=func,
        observation_points=obs_points,

        # Optimizations
        track_tmps=False,
        track_consts=False,
        track_liveness=False,
        max_iterations=2,
        dep_graph=None,
    )

    r1_offset, r1_size = lib.project.arch.registers['r1']
    r2_offset, r2_size = lib.project.arch.registers['r2']

    for call_addr in update_calls:
        defs = rda.get_reaching_definitions_by_insn(call_addr, OP_BEFORE)

        r1_values: list[tuple[int, set[BV]]] = list(defs.registers.load(r1_offset, r1_size).items())
        r2_values: list[tuple[int, set[BV]]] = list(defs.registers.load(r2_offset, r2_size).items())
        if len(r1_values) != 1 or len(r2_values) != 1:
            warn('Failed to resolve the arguments of a CameraMetadata::update call')
            continue

        r1_value = r1_values[0][1]
        r2_value = r2_values[0][1]
        if len(r1_value) != 1 or len(r2_value) != 1:
            warn('Failed to resolve the arguments of a CameraMetadata::update call')
            continue

        r1_value = r1_value.pop()
        r2_value = r2_value.pop()
        if r1_value.symbolic:
            warn(f'Failed to resolve camera metadata tag: {r1_value} {r2_value}')
            continue

        tag = r1_value.concrete_value
        if r2_value.concrete:
            offset = r2_value.concrete_value
            if offset <= 0:
                # The register likely contains a manipulated value
                # instead of something directly read from the struct
                continue
        else:
            r2_definitions = list(defs.extract_defs(r2_value))
            if len(r2_definitions) == 0:
                warn(f'Failed to find the definition of {r2_value} for tag {tag}')
                continue

            offset_candidates: set[int] = set()
            for definition in r2_definitions:
                def_ins_addr = definition.codeloc.ins_addr
                def_block = lib.project.factory.block(def_ins_addr, num_inst=1)
                def_insn = def_block.capstone.insns[0]
                offset = get_offset_from_symbolic_ast(
                    r2_value, lib.is_aarch64, def_insn
                )
                if offset is None: continue
                if offset is not None and offset <= 0:
                    # The register likely contains a manipulated value
                    # instead of something directly read from the struct
                    continue

                offset_candidates.add(offset)

            if len(offset_candidates) == 0:
                continue
            if len(offset_candidates) == 1:
                offset = offset_candidates.pop()
            elif len(offset_candidates) > 1:
                warn(f'Multiple offset candidates found for tag {tag}: {offset_candidates}')
                continue

        if tag in CameraMetadataTag:
            tag = CameraMetadataTag(tag)

            if (tag == CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES
                and offset is not None and not lib.is_legacy):
                # On non-legacy libs, it shouldn't be possible to obtain the
                # capabilities offset on constructStaticInfo
                abort('Failed to determine whether the lib is legacy or not')

            if tag in tag_offsets:
                if tag_offsets[tag] != offset:
                    abort(f'Multiple offsets found for {tag.name}: {hex(tag_offsets[tag])} and {hex(offset)}')
                
                continue
            
            if offset in tag_offsets.values():
                abort(f'Multiple tags have the same struct offset {hex(offset)}')
            if offset <= 0 or offset >= 0x1000:
                abort(f'The offset of {tag.name} is not valid: {hex(offset)}')

            tag_offsets[tag] = offset
            print(f'   + Found {tag.name} offset: {hex(offset)}')

    if not all(tag in tag_offsets for tag in tags):
        abort(f'Failed to find the struct offset of {tag.name}')

    return tag_offsets

def create_ExynosCameraSensorInfo_mod(
        lib: Lib3,
        enable_capabilities: list[Capability]|None = None,
        disable_capabilities: list[Capability]|None = None,
        hw_level: SupportedHardwareLevel|None = None,
        skip_depth_cameras: bool = False
    ):
    # Camera configs are created on 'createExynosCameraSensorInfo'.
    # The function calls different camera config struct constructors
    # (e.g. 'ExynosCameraSensorIMX754') depending on the camera,
    # and returns the config struct.

    # Many config constructors are included in the lib, but only
    # those called by 'createExynosCameraSensorInfo' are used.
    # This means we can safely replace one of the unused ones with our own
    # instructions and branch to it at the end of 'createExynosCameraSensorInfo'.

    # Find createExynosCameraSensorInfo function
    createExynosCameraSensorInfo = lib.find_symbol(
        r'^_ZN7android\d\dcreateExynosCamera3?SensorInfo.+'
    )
    if createExynosCameraSensorInfo is None:
        abort('Failed to find createExynosCameraSensorInfo function')
    if 'ExynosCamera3' in createExynosCameraSensorInfo.name:
        if not lib.is_legacy:
            abort('Failed to determine whether the lib is legacy or not')

        sensor_prefix = 'ExynosCamera3Sensor'
    else:
        sensor_prefix = 'ExynosCameraSensor'

    print('[+] Found createExynosCameraSensorInfo function, analyzing...')
    cfg = lib.project.analyses.CFGFast(
        normalize=True,

        # Only scan createExynosCameraSensorInfo and all the functions it calls
        function_starts=[createExynosCameraSensorInfo.rebased_addr],
        start_at_entry=False,
        force_complete_scan=False,
        force_smart_scan=False,
        function_prologues=False,
        symbols=False,

        # Optimizations
        data_references=False,
    )
    createExynosCameraSensorInfo = cfg.functions[createExynosCameraSensorInfo.rebased_addr]

    # Recursively find all the used constructors, example:
    # createExynosCameraSensorInfo -> ExynosCameraSensorIMX754
    #   -> ExynosCameraSensorIMX754Base -> ExynosCameraSensorInfoBase
    constructor_pattern = fr'^_ZN7android\d\d{sensor_prefix}(.+?)(Base)?(C1|C2|C3).+'
    constructors = {
        f.name : f for f in lib.find_symbols(constructor_pattern) 
    }
    used_cam_names: set[str] = set()
    called_functions = [createExynosCameraSensorInfo]
    for f in called_functions:
        called_functions.extend(
            func for _, func in get_called_functions(lib, f) if func not in called_functions
        )

        if f.name in constructors:
            cam_name = re.match(constructor_pattern, f.name).group(1)
            if cam_name in used_cam_names:
                continue

            if cam_name != 'Info':
                print(f'   + Constructor for {cam_name} is called')
            used_cam_names.add(cam_name)

            # On some libs a base constructor might be called (e.g. IMX754Base)
            # but not the normal constructor (IMX754). Lets remove both just in case.
            for cons_name in list(constructors.keys()):
                if cam_name.upper() in cons_name.upper():
                    constructors.pop(cons_name)

    if not any(f'{sensor_prefix}InfoBase' in f.name for f in called_functions):
        abort(f'{sensor_prefix}InfoBase constructor not called, this is unexpected')
    if len(used_cam_names) == 0:
        abort('No used camera config constructors found')
    if len(constructors) == 0:
        abort('No unused camera config constructors found')
    unused_constructor = constructors.popitem()[1]
    print('[+] Selected unused constructor:', unused_constructor.name)

    # Find createExynosCameraSensorInfo's return instruction
    if len(createExynosCameraSensorInfo.ret_sites) != 1:
        abort('Zero or multiple return sites found')
    return_node = createExynosCameraSensorInfo.ret_sites[0]
    return_block: Block = lib.project.factory.block(return_node.addr, size=return_node.size)
    return_ins: CsInsn = return_block.capstone.insns[-1]

    # Find struct offsets & build the mod
    struct_offsets = find_struct_offsets(lib, [
        CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
        CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL
    ])
    cap_offset = struct_offsets[CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES]
    hw_lvl_offset = struct_offsets[CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL]
    struct_reg = 'x0' if lib.is_aarch64 else 'r0'
    free_reg = 'w2' if lib.is_aarch64 else 'r2'
    free_reg2 = 'w3' if lib.is_aarch64 else 'r3'
    mod = Mod(
        start_addr=VirtualAddress(unused_constructor.rebased_addr, True),
        max_size=unused_constructor.size,
        is_aarch64=lib.is_aarch64
    )

    if (
        skip_depth_cameras or
        enable_capabilities is not None or
        disable_capabilities is not None
    ):
        # Read available capabilities
        mod.add_instruction(f'ldr {free_reg}, [{struct_reg}, #{cap_offset}]')

    # Skip cameras with depth output capability
    if skip_depth_cameras:
        if lib.is_aarch64:
            mod.add_instruction(
                f'tbnz {free_reg}, #{int(math.log2(Capability.DepthOutput))}, {mod.exit_label}'
            )
        else:
            mod.add_instruction(f'tst {free_reg}, {Capability.DepthOutput}')
            mod.add_instruction(f'bne {mod.exit_label}')

        print('- Depth cameras won\'t be modified')

    # Modify available capabilities value
    if enable_capabilities is not None:
        value = 0
        for cap in enable_capabilities:
            value |= cap.value

        try:
            mod.add_instruction(f'orr {free_reg}, {free_reg}, #{value}')
        except KsError:
            # ORR doesn't support the immediate value, so store it in a register
            mod.add_instruction(f'mov {free_reg2}, #{value}')
            mod.add_instruction(f'orr {free_reg}, {free_reg}, {free_reg2}')

        caps = ', '.join([x.name for x in enable_capabilities])
        print(f'- Enabling capabilities: {caps}')
    if disable_capabilities is not None:
        mask = 0xFFFF
        for cap in disable_capabilities:
            mask &= ~cap.value

        try:
            mod.add_instruction(f'and {free_reg}, {free_reg}, #{mask}')
        except KsError:
            # AND doesn't support the immediate value, so store it in a register
            mod.add_instruction(f'mov {free_reg2}, #{mask}')
            mod.add_instruction(f'and {free_reg}, {free_reg}, {free_reg2}')

        caps = ', '.join([x.name for x in disable_capabilities])
        print(f'- Disabling capabilities: {caps}')

    # Save available capabilities
    if enable_capabilities is not None or disable_capabilities is not None:
        mod.add_instruction(f'str {free_reg}, [{struct_reg}, #{cap_offset}]')

    # Set hardware level
    if hw_level is not None:
        mov = 'mov' if lib.is_aarch64 else 'movs'
        mod.add_instruction(f'{mov} {free_reg}, #{hw_level.value}')
        mod.add_instruction(f'strb {free_reg}, [{struct_reg}, #{hw_lvl_offset}]') 
        print(f'- Changing hardware level to {hw_level.name}')

    # Replace the selected constructor's instructions with ours
    mod.add_exit_instruction(return_ins.bytes)
    yield mod.start_addr, mod.assemble(lib)

    # Replace createExynosCameraSensorInfo's return instruction with a branch to the mod
    ret_ins_addr = VirtualAddress(return_ins.address, True)
    yield ret_ins_addr, mod.assemble_branch_to_mod(lib, ret_ins_addr)

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
    mod_options.add_argument(
        '--disable-cap',
        type=lambda v: capabilities_map.get(v.lower()) or abort(f'Invalid capability: {v}'),
        nargs='+',
        metavar='CAPABILITY',
        help='The capabilities that will be disabled, separated by space.'
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
        'If all the following args are provided, a Magisk module with the patched lib(s) will be created'
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

    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = 'HARDWARE_LEVEL can be:\n  ' + '\n  '.join([lvl.name for lvl in SupportedHardwareLevel])
    parser.epilog += '\n\n'
    parser.epilog += 'CAPABILITY can be:\n  ' + '\n  '.join([c.name for c in Capability])

    return parser.parse_args()

def main():
    args = parse_args()
    if (args.hardware_level is None and
        args.enable_cap is None and 
        args.disable_cap is None):
        abort('No modifications specified')

    out_libs: list[str] = []
    for file in args.libs:
        print(f'\n[*] Patching "{file.name}"...')
        lib = Lib3(file.read())
        file.close()

        for address, patch_bytes in create_ExynosCameraSensorInfo_mod(
            lib=lib,
            enable_capabilities=args.enable_cap,
            disable_capabilities=args.disable_cap,
            hw_level=args.hardware_level,
            skip_depth_cameras=args.skip_depth
        ):
            lib.apply_patch(address, patch_bytes)

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
    ):
        mods = []
        if args.enable_cap is not None:
            mods.append('enables ' + ', '.join([x.name for x in args.enable_cap]))
        if args.disable_cap is not None:
            mods.append('disables ' + ', '.join([x.name for x in args.disable_cap]))
        if args.hardware_level is not None:
            mods.append(f'sets hardware level to {args.hardware_level.name}')

        create_magisk_module(
            lib_name='libexynoscamera3.so',
            libs=out_libs,
            model=args.model, android_version=args.android_version,
            module_version=args.version, description=', '.join(mods)
        )

if __name__ == '__main__':
    main()