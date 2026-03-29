import multiprocessing
import unittest
import zipfile
from typing import Any, Callable


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

class BaseLibData:
    def __init__(self, path: str):
        self.path = path

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
        """Executes the test in a separate process since angr never releases
        the memory it uses.
        """
        print('###### ' + lib_data.path + ' ######', flush=True)
        lib = self.read_lib(lib_data.path)

        queue = multiprocessing.Queue()
        p = multiprocessing.Process(
            target=target, args=(lib, queue),

        )
        p.start()
        p.join()

        return queue.get()