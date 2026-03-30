import io
import multiprocessing
import sys

from common.capstone_utils import *
from tests.common import *


class LibData(BaseLibData):
    def __init__(
            self, path: str,
            has_pointer_auth: bool,
            getValueStr_str_reg: str,
            free_reg: str,
            mod_exit_address: int
        ):
        self.has_pointer_auth = has_pointer_auth
        self.getValueStr_str_reg = getValueStr_str_reg
        self.free_reg = free_reg
        self.mod_exit_address = mod_exit_address

        super().__init__(path)

LIBS_DATA = [
    # Exynos 2400e (S5E9945)
    LibData('s24fe_b.so', True, 'x8', 'x8', 0x2DB348)
]

def capabilities_mod(lib: bytes, queue: multiprocessing.Queue):
    import common.patch_utils as putils
    import patch_s5e as s5e

    stdout_buffer = io.StringIO()
    sys.stdout = Tee(sys.stdout, stdout_buffer)

    lib = putils.Lib(lib)
    res = list(s5e.capabilities_mod(lib))
    _, getValueStr_replacement = res[0]
    init_mov_addr, _ = res[1]
    mod_start, mod_bytes = res[2]

    lines = stdout_buffer.getvalue().splitlines()
    queue.put((
        lines, getValueStr_replacement,
        init_mov_addr.linked_addr(lib),
        mod_start.linked_addr(lib), mod_bytes
    ))

class TestS5E(LibTestCase):
    zip_file_path = 'tests/s5e.zip'

    def test_capabilities_mod(self):
        for lib_data in LIBS_DATA:
            (
                lines, 
                getValueStr_replacement, 
                init_mov_addr, 
                mod_start, mod_bytes
            ) = self.execute_test(lib_data, capabilities_mod)

            self.assertIn(f'[+] Found string register {lib_data.getValueStr_str_reg}', lines)
            first_ins = next(disasm_lite(getValueStr_replacement[:4], True))
            penultimate_ins = next(disasm_lite(getValueStr_replacement[-8:-4], True))
            if lib_data.has_pointer_auth:
                self.assertEqual(first_ins[2], 'paciasp')
                self.assertEqual(penultimate_ins[2], 'autiasp')
            else:
                self.assertNotEqual(first_ins[2], 'paciasp')
                self.assertNotEqual(penultimate_ins[2], 'autiasp')

            self.assertIn(f'[+] Found free register {lib_data.free_reg}', lines)
            self.assertEqual(init_mov_addr, lib_data.mod_exit_address - 4)

            #last_ins = next(disasm_lite(mod_bytes[-4:], True))
            #exit_addr = last_ins.operands[0].imm + (mod_start + len(mod_bytes) - 4)
            #self.assertEqual(exit_addr, lib_data.mod_exit_address)
            