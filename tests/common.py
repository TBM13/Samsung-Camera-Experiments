import multiprocessing
import re
import unittest
import zipfile
from dataclasses import dataclass
from typing import Any, Callable

from common.capstone_utils import disasm_lite_to_str


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()

@dataclass
class BaseLibData:
    path: str

class LibTestCase(unittest.TestCase):
    zip_file_path: str|None = None

    @classmethod
    def setUpClass(cls):
        if cls.zip_file_path is None:
            raise ValueError('zip_file_path must be set in the subclass')

        cls.zip = zipfile.ZipFile(cls.zip_file_path, 'r')

    @classmethod
    def tearDownClass(cls):
        cls.zip.close()

    def read_lib(self, path: str) -> bytes:
        with self.zip.open(path) as f:
            return f.read()
        
    def execute_test(
            self, lib_data: BaseLibData,
            target: Callable[[bytes, multiprocessing.Queue], None]
        ) -> Any:
        """Executes the test in a separate process to prevent high memory usage,
           since angr never releases all the memory it allocates.
        """
        print('\n###### ' + lib_data.path + ' ######', flush=True)
        lib = self.read_lib(lib_data.path)

        queue = multiprocessing.Queue()
        p = multiprocessing.Process(
            target=target, args=(lib, queue),

        )
        p.start()
        p.join()

        return queue.get()
    
    def assertInstructionsEqual(
            self, aarch64: bool, actual: bytes, expected: list[str]
        ) -> list[str]:
        """Asserts that the given actual bytes, when disassembled, match the expected instructions.
        
        Regex is used. The captured groups are returned in a list.
        """
        actual = list(disasm_lite_to_str(actual, aarch64))
        self.assertEqual(
            len(actual), len(expected),
            f'Actual instructions amount ({len(actual)}) doesn\'t match expected (len(expected)).\n\nExpected:\n{expected}\n\nActual instructions:\n{actual}'
        )
        
        matches = []
        for actual_ins, expected_ins in zip(actual, expected):
            m: re.Match[str] = re.fullmatch(expected_ins, actual_ins)
            self.assertIsNotNone(
                m, f'Instruction "{actual_ins}" does not match expected "{expected_ins}".\n\nExpected:\n{expected}\n\nActual instructions:\n{actual}'
            )
            matches.extend(m.groups())

        return matches

    def assertInstructionsStartWith(
            self, aarch64: bool, actual: bytes, expected_start: list[str]
        ) -> list[str]:
        """Asserts that the given actual bytes, when disassembled, start with the expected instructions.
        
        Regex is used. The captured groups are returned in a list.
        """
        actual: list[str] = list(disasm_lite_to_str(actual, aarch64))
        self.assertGreaterEqual(
            len(actual), len(expected_start),
            f'Actual instructions are fewer than expected.\n\nExpected start:\n{expected_start}\n\nActual instructions:\n{actual}'
        )

        matches = []
        for actual_ins, expected_ins in zip(actual, expected_start):
            m: re.Match[str] = re.fullmatch(expected_ins, actual_ins)
            self.assertIsNotNone(
                m, f'Instruction "{actual_ins}" does not match expected "{expected_ins}".\n\nExpected start:\n{expected_start}\n\nActual instructions:\n{actual}'
            )
            matches.extend(m.groups())

        return matches