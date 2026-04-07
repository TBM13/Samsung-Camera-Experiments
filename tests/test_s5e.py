import multiprocessing
import sys

from common.capstone_utils import *
from tests.common import *


@dataclass
class LibData(BaseLibData):
    has_pointer_auth: bool
    """Whether the lib has pointer authentication
    (PACIASP/AUTIASP instructions).
    """
    str_reg: str
    """The register where `CameraCapability::getValueStr`
    writes the string to.
    """
    free_reg: str
    """The register used in the first `mov wX, #1`
    instruction in `CameraCapability::init`.
    """

LIBS_DATA = [
    # Exynos 2400e (S5E9945)
    LibData('s24fe_b.so', True, 'x8', 'w8'),
]

def create_mod_cave(lib: bytes, queue: multiprocessing.Queue):
    import common.patch_utils as putils
    import patch_s5e as s5e
    # Ensure that prints from this process are flushed immediately
    sys.stdout.reconfigure(line_buffering=True)

    lib: putils.Lib = putils.Lib(lib)
    mod = s5e.create_mod_cave(lib)
    queue.put((lib.applied_patches, mod.max_size))

def capabilities_mod(lib: bytes, queue: multiprocessing.Queue):
    import common.patch_utils as putils
    import patch_s5e as s5e
    # Ensure that prints from this process are flushed immediately
    sys.stdout.reconfigure(line_buffering=True)

    lib: putils.Lib = putils.Lib(lib)
    mod = putils.Mod(putils.VirtualAddress(0, False), 1000, lib.is_aarch64)
    s5e.apply_capabilities_mod(lib, mod)
    queue.put(lib.applied_patches)

class TestS5E(LibTestCase):
    zip_file_path = 'tests/s5e.zip'

    def test_mod_cave_creation(self):
        for lib_data in LIBS_DATA:
            applied_patches, mod_max_size = self.execute_test(lib_data, create_mod_cave)
            # At least 10 instructions should fit
            self.assertGreaterEqual(mod_max_size, 10 * 4)

            # Ensure getValueStr was properly patched
            self.assertEqual(len(applied_patches), 1)
            patch = applied_patches[0]
            if lib_data.has_pointer_auth:
                self.assertInstructionsStartWith(True, patch.original_bytes, [
                    r'paciasp',
                    r'sub sp, sp, #.+'
                ])

                self.assertInstructionsEqual(True, patch.patched_bytes, [
                    r'paciasp',
                    rf'stp xzr, xzr, \[{lib_data.str_reg}\]',
                    rf'str xzr, \[{lib_data.str_reg}, #0x10\]',
                    r'autiasp',
                    r'ret'
                ])
            else:
                self.assertInstructionsStartWith(True, patch.original_bytes, [
                    r'sub sp, sp, #.+'
                ])

                self.assertInstructionsEqual(True, patch.patched_bytes, [
                    rf'stp xzr, xzr, \[{lib_data.str_reg}\]',
                    rf'str xzr, \[{lib_data.str_reg}, #0x10\]',
                    r'ret'
                ])

    def test_capabilities_mod(self):
        for lib_data in LIBS_DATA:
            applied_patches = self.execute_test(lib_data, capabilities_mod)
            self.assertEqual(len(applied_patches), 2)

            # branch to mod on CameraCapability::init
            branch_to_mod = applied_patches[0]
            replaced_mov = self.assertInstructionsEqual(True, branch_to_mod.original_bytes, [
                f'(mov {lib_data.free_reg}, #1)'
            ])[0]
            self.assertInstructionsEqual(True, branch_to_mod.patched_bytes, [
                r'b #.+'
            ])

            # mod instructions on mod cave
            mod = applied_patches[1]
            self.assertEqual(mod.file_offset, 0)
            # since we didn't specify any modifications, the mod should
            # only have the mov we replaced and the exit branch
            self.assertInstructionsEqual(True, mod.patched_bytes, [
                replaced_mov,
                rf'b #{hex(branch_to_mod.file_offset + len(branch_to_mod.patched_bytes))}'
            ])