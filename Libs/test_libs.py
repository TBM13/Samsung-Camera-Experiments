import unittest
from patch_lib import *

class LibData:
    def __init__(self, path: str,
                 hw_level_offset: int, available_cap_offset: int):
        self.path = path
        self.hw_level_offset = hw_level_offset
        self.available_cap_offset = available_cap_offset


        with open(path, "rb") as f:
            self.data = f.read()

LIBS = [
    # Exynos 850
    LibData("libs/a12-nacho_t.so", 0x648, 0x650),
    LibData("libs/a12-nacho_t_64.so", 0x79c, 0x7a0),
    LibData("libs/a13_u.so", 0x640, 0x648),
    # Exynos 990
    LibData("libs/note20ultra_u.so", 0x8c0, 0x8c8),
    LibData("libs/note20ultra_u_64.so", 0xa1c, 0xa20),
    LibData("libs/s20ultra_u.so", 0x8d0, 0x8d8),
    LibData("libs/s20ultra_u_64.so", 0xa2c, 0xa30),
    # Exynos 1280
    LibData("libs/a53_t.so", 0x8b8, 0x8c0),
    LibData("libs/a53_t_64.so", 0xa14, 0xa18),
    LibData("libs/m34_t.so", 0x8b8, 0x8c0),
    LibData("libs/m34_t_64.so", 0xa14, 0xa18),
    LibData("libs/a33_u.so", 0x8c0, 0x8c8),
    LibData("libs/a33_u_64.so", 0xa1c, 0xa20),
    # Exynos 7884/7904
    LibData("libs/a20_p.so", 0x594, 0x598),
    LibData("libs/a20_p_64.so", 0x6e8, 0x6f0),
    LibData("libs/a20_r.so", 0x630, 0x638),
    LibData("libs/a20_r_64.so", 0x784, 0x788),
    LibData("libs/a20e_r.so", 0x630, 0x638),
    LibData("libs/a30_p.so", 0x54c, 0x550),
    LibData("libs/a30_p_64.so", 0x6a0, 0x6a8),
    LibData("libs/a30_q.so", 0x5f0, 0x5f8),
    LibData("libs/a30_q_64.so", 0x73c, 0x740),
    LibData("libs/a30_r.so", 0x630, 0x638),
    LibData("libs/a30s_q.so", 0x5f0, 0x5f8),
    LibData("libs/a30s_q_64.so", 0x73c, 0x740),
    LibData("libs/a30s_r.so", 0x630, 0x638),
    LibData("libs/a40_r.so", 0x630, 0x638),
    LibData("libs/a40_r_64.so", 0x784, 0x788),
    # Exynos Exynos 9610/9611
    LibData("libs/a50_p.so", 0x54c, 0x550),
    LibData("libs/a50_p_64.so", 0x6a0, 0x6a8),
    LibData("libs/a50_q.so", 0x5f0, 0x5f8),
    LibData("libs/a50_q_64.so", 0x73c, 0x740),
    LibData("libs/a50s_r.so", 0x630, 0x638),
    LibData("libs/a51_r.so", 0x630, 0x638),
    LibData("libs/m30s_r.so", 0x5f8, 0x600),
    LibData("libs/m31_r.so", 0x630, 0x638),
    LibData("libs/m31s_s.so", 0x640, 0x648),
    LibData("libs/m31s_s_64.so", 0x794, 0x798),
    LibData("libs/tabs6lite_q.so", 0x600, 0x608),
    LibData("libs/tabs6lite_q_64.so", 0x74c, 0x750),
    LibData("libs/tabs6lite_t.so", 0x640, 0x648),
    LibData("libs/tabs6lite_t_64.so", 0x794, 0x798),
    # Exynos 9825
    LibData("libs/f62_r.so", 0x768, 0x770),
]

class TestLibs(unittest.TestCase):
    def test_find_capabilities_and_hw_level_offsets(self):
        for lib in LIBS:
            print(lib.path)

            self.assertEqual(
                find_capabilities_and_hw_level_offsets(lib.data),
                (lib.available_cap_offset, lib.hw_level_offset)
            )

    def test_build_sensor_info_struct_mod(self):
        for lib in LIBS:
            print(lib.path)

            # Ensure that at least one pattern matched the lib
            build_sensor_info_struct_mod(lib.data)