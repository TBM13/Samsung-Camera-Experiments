import unittest
import io
import zipfile
from unittest.mock import patch

import lief

from patch_s5e import *


class LibData:
    def __init__(
            self, path: str,
            has_pointer_auth: bool,
            getValueStr_str_reg: str,
            free_reg: str,
            mod_exit_address: int
        ):
        self.path = path

        self.has_pointer_auth = has_pointer_auth
        self.getValueStr_str_reg = getValueStr_str_reg
        self.free_reg = free_reg
        self.mod_exit_address = mod_exit_address

LIBS_DATA = [
    # Exynos 2400e (S5E9945)
    LibData('s24fe_b.so', True, 'x8', 'x8', 0x2DB348)
]

class TestS5E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zip = zipfile.ZipFile('tests/s5e.zip', 'r')
        cls._cache = {}

    @classmethod
    def tearDownClass(cls):
        cls.zip.close()

    def get_lib(self, path: str) -> lief.ELF.Binary:
        if path not in self._cache:
            with self.zip.open(path) as f:
                self._cache[path] = lief.parse(f.read())

        return self._cache[path]

    def test_capabilities_mod(self):
        for lib_data in LIBS_DATA:
            print('#### ' + lib_data.path + ' ####')

            lib = self.get_lib(lib_data.path)
            with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                mod = list(capabilities_mod(lib))
                out = mock_stdout.getvalue()
                lines = out.splitlines()

            print(out)
            self.assertIn(f'[+] Found string register {lib_data.getValueStr_str_reg}', lines)
            addr, getValueStr_replacement = mod[0]
            first_ins = next(disasm(getValueStr_replacement[:4], True))
            penultimate_ins = next(disasm(getValueStr_replacement[-8:-4], True))
            if lib_data.has_pointer_auth:
                self.assertEqual(first_ins.mnemonic, 'paciasp')
                self.assertEqual(penultimate_ins.mnemonic, 'autiasp')
            else:
                self.assertNotEqual(first_ins.mnemonic, 'paciasp')
                self.assertNotEqual(penultimate_ins.mnemonic, 'autiasp')

            self.assertIn(f'[+] Found free register {lib_data.free_reg}', lines)
            addr, branch_to_mod = mod[1]
            self.assertEqual(addr, lib_data.mod_exit_address - 4)

            addr, mod_bytes = mod[2]
            last_ins = next(disasm(mod_bytes[-4:], True))
            exit_addr = last_ins.operands[0].imm + (addr + len(mod_bytes) - 4)
            self.assertEqual(exit_addr, lib_data.mod_exit_address)
            