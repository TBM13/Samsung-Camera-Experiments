import io
import multiprocessing
import sys

from common.android_camera_metadata import *
from tests.common import *


class LibData(BaseLibData):
    def __init__(
            self, path: str,
            hw_level_offset: int, capabilities_offset: int,
            return_ins_address: int,
            used_camera_names: list[str]
        ):
        self.hw_level_offset = hw_level_offset
        self.available_cap_offset = capabilities_offset
        self.return_ins_address = return_ins_address
        self.used_camera_names = used_camera_names

        super().__init__(path)

LIBS_DATA = [
    # Exynos 850
    LibData("a12-nacho_t.so",    0x648, 0x650, 0xC2BCE, ["4HA", "GM2", "SR846", "GC5035", "GC02M1"]),
    LibData("a12-nacho_t_64.so", 0x79c, 0x7a0, 0xEC29C, ["4HA", "GM2", "SR846", "GC5035", "GC02M1"]),
    LibData("a13_u.so",          0x640, 0x648, 0xC231A, ["GC02M1", "GC08A3", "JN1", "GC5035"]),
    LibData("a21s_s.so",         0x640, 0x648, 0xC2A00, ["4HA", "GM2", "SR846", "HI1336", "GC02M1"]),
    LibData("a21s_s_64.so",      0x78c, 0x790, 0xEC394, ["4HA", "GM2", "SR846", "HI1336", "GC02M1"]),
    LibData("xcover5_u.so",      0x640, 0x648, 0xBB63E, ["GC5035", "2P6"]),
    LibData("xcover5_u_64.so",   0x78c, 0x790, 0xEF108, ["GC5035", "2P6"]),
    # Exynos 990
    LibData("note20ultra_u.so",    0x8c0, 0x8c8, 0xD3D50,  ["3M5", "HM1", "2L3", "3J1"]),
    LibData("note20ultra_u_64.so", 0xa1c, 0xa20, 0x1001B8, ["3M5", "HM1", "2L3", "3J1"]),
    LibData("s20_t.so",            0x8c0, 0x8c8, 0xD29CC,  ["GW2", "IMX516", "IMX518", "3J1", "2LD", "2LA"]),
    LibData("s20_t_64.so",         0xa1c, 0xa20, 0xFF260,  ["GW2", "IMX516", "IMX518", "3J1", "2LD", "2LA"]),
    LibData("s20ultra_u.so",       0x8d0, 0x8d8, 0xD6D1C,  ["IMX586", "IMX516", "IMX518", "2L3", "GH1", "HM1"]),
    LibData("s20ultra_u_64.so",    0xa2c, 0xa30, 0x104204, ["IMX586", "IMX516", "IMX518", "2L3", "GH1", "HM1"]),
    # Exynos 1280
    LibData("a53_t.so",    0x8b8, 0x8c0, 0xE40CE,  ["GW1", "GD2", "IMX258", "GC5035", "HI1336", "IMX616", "IMX682"]),
    LibData("a53_t_64.so", 0xa14, 0xa18, 0x11424C, ["GW1", "GD2", "IMX258", "GC5035", "HI1336", "IMX616", "IMX682"]),
    LibData("m34_t.so",    0x8b8, 0x8c0, 0xE6D74,  ["GC02M2", "HI1339", "4HA", "JN1"]),
    LibData("m34_t_64.so", 0xa14, 0xa18, 0x1183E0, ["GC02M2", "HI1339", "4HA", "JN1"]),
    LibData("a33_u.so",    0x8c0, 0x8c8, 0xE4746,  ["4HA", "3L6", "IMX258", "GC5035", "GC02M1", "IMX582", "IMX355"]),
    LibData("a33_u_64.so", 0xa1c, 0xa20, 0x11562C, ["4HA", "3L6", "IMX258", "GC5035", "GC02M1", "IMX582", "IMX355"]),
    # Exynos 2100
    LibData("s21fe_v.so",    0x8e0, 0x8e8, 0xE5ACA,  ["2LD", "IMX258", "IMX616", "HI1336", "HI847"]),
    LibData("s21fe_v_64.so", 0xa44, 0xa48, 0x1161E0, ["2LD", "IMX258", "IMX616", "HI1336", "HI847"]),
    # Exynos 2200
    LibData("s22ultra_v_64.so", 0xa4c, 0xa50, 0x132188, ["IMX563", "IMX754", "GH1", "HM3"]),
    # Exynos 7884/7904
    LibData("a20_p.so",     0x594, 0x598, 0x57D64, ["IMX258", "SR556", "4HA", "3L6"]),
    LibData("a20_p_64.so",  0x6e8, 0x6f0, 0x6B998, ["IMX258", "SR556", "4HA", "3L6"]),
    LibData("a20_r.so",     0x630, 0x638, 0x98004, ["IMX258", "SR556", "4HA", "3L6"]),
    LibData("a20_r_64.so",  0x784, 0x788, 0xBA4F0, ["IMX258", "SR556", "4HA", "3L6"]),
    LibData("a20e_r.so",    0x630, 0x638, 0x982E0, ["SR556", "3L6", "4HA",]),
    LibData("a30_p.so",     0x54c, 0x550, 0x59CDC, ["IMX471_3P8SP", "2P6", "5E9"]),
    LibData("a30_p_64.so",  0x6a0, 0x6a8, 0x6E378, ["IMX471_3P8SP", "2P6", "5E9"]),
    LibData("a30_q.so",     0x5f0, 0x5f8, 0xA2126, ["IMX471_3P8SP", "2P6", "5E9"]),
    LibData("a30_q_64.so",  0x73c, 0x740, 0xD2338, ["IMX471_3P8SP", "2P6", "5E9"]),
    LibData("a30_r.so",     0x630, 0x638, 0x9E116, ["IMX471_3P8SP", "2P6", "5E9"]),
    LibData("a30s_q.so",    0x5f0, 0x5f8, 0xB0126, ["GC5035", "HI1631", "4HA", "IMX576"]),
    LibData("a30s_q_64.so", 0x73c, 0x740, 0xE63C4, ["GC5035", "HI1631", "4HA", "IMX576"]),
    LibData("a30s_r.so",    0x630, 0x638, 0xAA646, ["GC5035", "HI1631", "4HA", "IMX576"]),
    LibData("a30s_r_64.so", 0x784, 0x788, 0xD03C8, ["GC5035", "HI1631", "4HA", "IMX576"]),
    LibData("a40_r.so",     0x630, 0x638, 0x9E0B2, ["5E9", "2X5", "2P6"]),
    LibData("a40_r_64.so",  0x784, 0x788, 0xC13F4, ["5E9", "2X5", "2P6"]),
    # Exynos 9610/9611
    LibData("a50_p.so",          0x54c, 0x550, 0x60606, ["4HA", "5E9", "2X5", "GC5035", "IMX576"]),
    LibData("a50_p_64.so",       0x6a0, 0x6a8, 0x77DE0, ["4HA", "5E9", "2X5", "GC5035", "IMX576"]),
    LibData("a50_q.so",          0x5f0, 0x5f8, 0xB012E, ["4HA", "5E9", "2X5", "GC5035", "IMX576"]),
    LibData("a50_q_64.so",       0x73c, 0x740, 0xE6430, ["4HA", "5E9", "2X5", "GC5035", "IMX576"]),
    LibData("a50s_r.so",         0x630, 0x638, 0xAA75C, ["IMX616", "GC5035", "IMX582", "4HA"]),
    LibData("a51_r.so",          0x630, 0x638, 0xAB52C, ["GC5035", "HI1336", "IMX616", "IMX582"]),
    LibData("m21_s.so",          0x640, 0x648, 0xAD5C4, ["GC5035", "HI2021", "4HA", "GM2"]),
    LibData("m21_s_64.so",       0x794, 0x798, 0xD4300, ["GC5035", "HI2021", "4HA", "GM2"]),
    LibData("m30s_r.so",         0x5f8, 0x600, 0xAD0E8, ["4HA", "IMX471_3P8SP", "HI1336", "GM2", "GC5035"]),
    LibData("m31_r.so",          0x630, 0x638, 0xAA5CC, ["IMX616", "GC5035", "GW1", "4HA"]),
    LibData("m31s_s.so",         0x640, 0x648, 0xAAC14, ["GC5035", "IMX682", "3L6", "IMX616"]),
    LibData("m31s_s_64.so",      0x794, 0x798, 0xD129C, ["GC5035", "IMX682", "3L6", "IMX616"]),
    LibData("tabs6lite_q.so",    0x600, 0x608, 0xA10DA, ["5E9", "4HA"]),
    LibData("tabs6lite_q_64.so", 0x74c, 0x750, 0xD2344, ["5E9", "4HA"]),
    LibData("tabs6lite_t.so",    0x640, 0x648, 0x9C954, ["5E9", "4HA"]),
    LibData("tabs6lite_t_64.so", 0x794, 0x798, 0xBF344, ["5E9", "4HA"]),
    # Exynos 9820
    LibData("s10_s.so",   0x8f0, 0x8f8, 0xAE058, ["3M3", "2L4", "3J1", "4HA", "3P9"]),
    # Exynos 9825
    LibData("f62_r.so",          0x768, 0x770, 0xABBAE, ["GC5035", "IMX682", "3L6", "IMX616"]),
    LibData("f62_t_64.so",       0x8cc, 0x8d0, 0xD21C8, ["GC5035", "IMX682", "3L6", "IMX616"]),
    LibData("note10plus5g_s.so", 0x900, 0x908, 0xB19FE, ["IMX516", "IMX316", "3M5", "2L4", "3J1", "3P9"])
]

def find_capabilities_and_hwlevel_offsets(lib: bytes, queue: multiprocessing.Queue):
    import patch_libexynoscamera3 as patch
    # Ensure that prints from this process are flushed immediately
    sys.stdout.reconfigure(line_buffering=True)

    lib = patch.Lib3(lib)
    res = patch._find_capabilities_and_hwlevel_offsets(lib)
    queue.put(res)

def find_struct_offsets(lib: bytes, queue: multiprocessing.Queue):
    import patch_libexynoscamera3 as patch
    # Ensure that prints from this process are flushed immediately
    sys.stdout.reconfigure(line_buffering=True)

    lib = patch.Lib3(lib)
    res = patch.find_struct_offsets(lib, tags=list(CameraMetadataTag))
    queue.put(res)

def create_ExynosCameraSensorInfo_mod(lib: bytes, queue: multiprocessing.Queue):
    import patch_libexynoscamera3 as patch

    stdout_buffer = io.StringIO()
    sys.stdout = Tee(sys.stdout, stdout_buffer)

    lib: patch.Lib3 = patch.Lib3(lib)
    mod = list(patch.create_ExynosCameraSensorInfo_mod(lib))
    unused_constructor_addr, _ = mod[0]
    return_addr, _ = mod[1]

    lines = stdout_buffer.getvalue().splitlines()
    return_addr = return_addr.linked_addr(lib)
    unused_constructor_name = lib.find_symbol(unused_constructor_addr).name
    queue.put((lines, return_addr, unused_constructor_name))

class TestLibexynoscamera3(LibTestCase):
    zip_file_path = 'tests/libexynoscamera3.zip'

    def test_find_capabilities_and_hw_level_offsets(self):
        for lib_data in LIBS_DATA:
            res: dict[CameraMetadataTag, int] = self.execute_test(
                lib_data, find_capabilities_and_hwlevel_offsets
            )

            self.assertEqual(
                res,
                {
                    CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES: lib_data.available_cap_offset,
                    CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL: lib_data.hw_level_offset
                }
            )

    def test_find_struct_offsets(self):
        for lib_data in LIBS_DATA:
            res: dict[CameraMetadataTag, int] = self.execute_test(
                lib_data, find_struct_offsets
            )

            # Check that all tags were found
            for tag in CameraMetadataTag:
                self.assertIn(tag, res)

            # Ensure capabilities and hw level offsets are correct
            self.assertEqual(res[CameraMetadataTag.ANDROID_REQUEST_AVAILABLE_CAPABILITIES], lib_data.available_cap_offset)
            self.assertEqual(res[CameraMetadataTag.ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL], lib_data.hw_level_offset)

    def test_sensor_info_struct_mod(self):
        for lib_data in LIBS_DATA:
            lines, return_addr, unused_constructor_name = self.execute_test(
                lib_data, create_ExynosCameraSensorInfo_mod
            )

            # Check that all used camera constructors were detected
            constructor_call_lines = [
                line for line in lines if line.startswith('   + Constructor for')
            ]
            for cam_name in lib_data.used_camera_names:
                self.assertIn(f'   + Constructor for {cam_name} is called', constructor_call_lines)
            self.assertEqual(len(constructor_call_lines), len(lib_data.used_camera_names))

            # Check return instruction address
            self.assertEqual(return_addr, lib_data.return_ins_address)

            # Check that the selected constructor isn't one of the used
            cons_name = unused_constructor_name.upper()
            self.assertNotIn("INFOBASE", cons_name)
            for cam_name in lib_data.used_camera_names:
                self.assertNotIn(cam_name.upper(), cons_name)