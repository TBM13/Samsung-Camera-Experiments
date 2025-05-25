import unittest

from patch_lib import *


class LibData:
    def __init__(
            self, path: str,
            hw_level_offset: int, available_cap_offset: int,
            modifiable_chunks: list[str]|None = None
        ):
        self.path = path
        self.hw_level_offset = hw_level_offset
        self.available_cap_offset = available_cap_offset

        modifiable_chunks = modifiable_chunks or []
        self.modifiable_chunks = [
            bytes.fromhex(chunk) for chunk in modifiable_chunks
        ]

        with open(path, "rb") as f:
            self.data = f.read()

LIBS = [
    # Exynos 850
    LibData("libs/a12-nacho_t.so",    0x648, 0x650, ["294940F21E20CDE9025823467944CDE9001004202549264A79447A4413F1A2E9"]),
    LibData("libs/a12-nacho_t_64.so", 0x79c, 0x7a0, ["A1FCFF9042FDFF90A4FDFFF021C0169142A0379184902591E703009180008052E303132AC5438052E603142A815D0694"]),
    LibData("libs/a13_u.so",          0x640, 0x648, ["274940F25520CDE9025823467944CDE9001004202349244A79447A4412F19CEF"]),
    LibData("libs/a21s_s.so",         0x640, 0x648, ["284940F23620CDE902584B467944CDE9001004202449254A79447A4414F19EEB"]),
    LibData("libs/a21s_s_64.so",      0x78c, 0x790, ["A1FCFF9042FDFF90A4FDFFF0213C0F91424C2E9184E01791E703009180008052C5468052E303132AE603142A0E460694"]),
    LibData("libs/xcover5_u.so",      0x640, 0x648, ["26494FF48370CDE9025823467944CDE9001004202249234A79447A4402F11AE8"]),
    LibData("libs/xcover5_u_64.so",   0x78c, 0x790, ["012ADD5022FCFF9042C02F91C4FCFFF084D83691E703009180008052E303132AC5208052E603142A85E10594"]),
    # Exynos 990
    LibData("libs/note20ultra_u.so",    0x8c0, 0x8c8, ["4FF492608DE8110104200F49104A104B79447A447B4438F136ED"]),
    LibData("libs/note20ultra_u_64.so", 0xa1c, 0xa20, ["41FCFFB0A2FDFFB083FDFF9021AC2F9142CC2C9163A81991E60300918000805204928052E503132AB0240794"]),
    LibData("libs/s20_t.so",            0x8c0, 0x8c8, ["40F299408DE8110104200F49104A104B79447A447B4434F160EB"]),
    LibData("libs/s20_t_64.so",         0xa1c, 0xa20, ["41FCFFB0A2FDFFB083FDFF902154389142382D9163941E91E60300918000805224938052E503152ABA090794"]),
    LibData("libs/s20ultra_u.so",       0x8d0, 0x8d8, ["40F26A408DE8110104200F49104A104B79447A447B443EF190E9"]),
    LibData("libs/s20ultra_u_64.so",    0xa2c, 0xa30, ["21FCFFF0A2FDFF9063FDFFD021C0149142F40C9163FC3191E603009180008052448D8052E503132A71400794"]),
    # Exynos 1280
    LibData("libs/a53_t.so",    0x8b8, 0x8c0, ["40F203408DE8110104201649164A174B79447A447B444EF130EB"]),
    LibData("libs/a53_t_64.so", 0xa14, 0xa18, ["01FCFFD082FDFF9043FDFFD021F82E914250229163AC3C9164808052E603009180008052E503132A8BC80794"]),
    LibData("libs/m34_t.so",    0x8b8, 0x8c0, ["40F2FA208DE8110104201349144A144B79447A447B4451F194EA"]),
    LibData("libs/m34_t_64.so", 0xa14, 0xa18, ["E1FBFFF062FDFFD043FDFFB0215C3C9142F0299163E00191445F8052E603009180008052E503142AFEDA0794"]),
    LibData("libs/a33_u.so",    0x8c0, 0x8c8, ["2A494FF43370CDE902584B467944CDE9001004202649264A79447A444FF10CEB"]),
    LibData("libs/a33_u_64.so", 0xa1c, 0xa20, ["01FCFFB0C2FCFFB044FDFFD0214C3A91424C0B9184D8129185598052E703009180008052E303132AE603142A50CD0794"]),
    # Exynos 7884/7904
    LibData("libs/a20_p.so",     0x594, 0x598, ["1749184A184B40F257108DE89100042079447A447B44B4F0C9FB"]),
    LibData("libs/a20_p_64.so",  0x6e8, 0x6f0, ["C10700D0C20700D0C30700D021403D9142F03F91636C3E91E0031E32E42A8052E6030091E503132AF4FAFF97"]),
    LibData("libs/a20_r.so",     0x630, 0x638, ["40F25F108DE8110104201349144A144B79447A447B44BDF0CCEF"]),
    LibData("libs/a20_r_64.so",  0x784, 0x788, ["61FDFF9042FEFFD023FEFFD02144169142501691633C3891E603009180008052E42B8052E503142AC6580494"]),
    LibData("libs/a20e_r.so",    0x630, 0x638, ["4FF4AD708DE8110104201249134A134B79447A447B44BDF0F6EF"]),
    LibData("libs/a30_p.so",     0x54c, 0x550, ["1749184A184B40F24F108DE89100042079447A447B44BDF047FC"]),
    LibData("libs/a30_p_64.so",  0x6a0, 0x6a8, ["210800D0220800D0230800D021803991423C3C9163AC3A91E0031E32E4298052E6030091E503132A04FBFF97"]),
    LibData("libs/a30_q.so",     0x5f0, 0x5f8, ["40F257108DE8110104201449144A154B79447A447B44C5F034EC"]),
    LibData("libs/a30_q_64.so",  0x73c, 0x740, ["41FDFFF042FEFFD023FEFFF021E815914224239163BC0291E6030091E0031E32E42A8052E503132AB87A0494"]),
    LibData("libs/a30_r.so",     0x630, 0x638, ["4FF4AC708DE8110104201449144A154B79447A447B44C8F06CE8"]),
    LibData("libs/a30s_q.so",    0x5f0, 0x5f8, ["4FF4FC708DE8110104201449144A154B79447A447B44E7F014EB"]),
    LibData("libs/a30s_q_64.so", 0x73c, 0x740, ["01FDFFD022FEFFB003FEFFB021F82E91424C1A9163081F91E6030091E0031E32E4171D32E503142A413D0594"]),
    LibData("libs/a30s_r.so",    0x630, 0x638, ["4FF4FC708DE8110104201449144A154B79447A447B44E7F06CED"]),
    LibData("libs/a30s_r_64.so", 0x784, 0x788, ["01FDFF9002FEFFF0E3FDFFF02174099142641C9163701891E603009180008052043F8052E503142A454D0594"]),
    LibData("libs/a40_r.so",     0x630, 0x638, ["4FF4BF708DE8110104201349134A144B79447A447B44CAF0AEEC"]),
    LibData("libs/a40_r_64.so",  0x784, 0x788, ["41FDFF9042FEFF9023FEFF90212C299142B81C9163C03591E603009180008052C42F8052E503142AE9A30494"]),
    # Exynos Exynos 9610/9611
    LibData("libs/a50_p.so",          0x54c, 0x550, ["4FF4F170CDE902582346019021482249224A7844009079447A440420E2F0BEF9"]),
    LibData("libs/a50_p_64.so",       0x6a0, 0x6a8, ["A10900D0A20900D0A40900D021102C9142D82E9184242D91E0031E32453C8052E7230091E303132AE603142AA1FAFF97"]),
    LibData("libs/a50_q.so",          0x5f0, 0x5f8, ["27494FF44B7043467944CDE900100420CDE902592349234A79447A44E9F020EE"]),
    LibData("libs/a50_q_64.so",       0x73c, 0x740, ["01FDFFD0A2FDFF9004FEFFB02160369142BC1591846C0B91E7030091E0031E3285658052E303132AE603142AD3460594"]),
    LibData("libs/a50s_r.so",         0x630, 0x638, ["27494FF4FF704B467944CDE900100420CDE902582349244A79447A44EAF088EA"]),
    LibData("libs/a51_r.so",          0x630, 0x638, ["274940F259204B467944CDE900100420CDE902582349244A79447A44EBF040EE"]),
    LibData("libs/m21_s.so",          0x640, 0x648, ["264940F23720CDE902584B467944CDE9001004202249234A79447A44EEF0B4EC"]),
    LibData("libs/m21_s_64.so",       0x794, 0x798, ["E1FCFFD082FDFF90E4FDFFB02164009142F81E9184083B91E703009180008052E5468052E303132AE603142A6B700594"]),
    LibData("libs/m30s_r.so",         0x5f8, 0x600, ["28494FF403704B467944CDE900100420CDE902582449254A79447A44EDF022EE"]),
    LibData("libs/m31_r.so",          0x630, 0x638, ["274940F25F204B467944CDE900100420CDE902582349244A79447A44E9F0C0EE"]),
    LibData("libs/m31s_s.so",         0x640, 0x648, ["274940F26320CDE902584B467944CDE9001004202349244A79447A44EAF0BCEB"]),
    LibData("libs/m31s_s_64.so",      0x794, 0x798, ["01FDFF9082FDFFB0E4FDFFF021B4029142403D9184DC0091E703009180008052654C8052E303132AE603142AD4570594"]),
    LibData("libs/tabs6lite_q.so",    0x600, 0x608, ["AA208DE8110104201149114A124B79447A447B44C2F01AEB"]),
    LibData("libs/tabs6lite_q_64.so", 0x74c, 0x750, ["61FDFFB042FEFFF023FEFFF021AC019142700B9163182C91E6030091E0031E3244158052E503142AB1710494"]),
    LibData("libs/tabs6lite_t.so",    0x640, 0x648, ["AC208DE8910004201249124A134B79447A447B44C4F010E8"]),
    LibData("libs/tabs6lite_t_64.so", 0x794, 0x798, ["41FDFFD042FEFFB023FEFFB021EC2891427C1F91635C3891E60300918000805284158052E503142AB9860494"]),
    # Exynos 9820
    LibData("libs/s10_s.so",   0x8f0, 0x8f8, ["40F2AB408DE8110104201449154A154B79447A447B44F3F09AED"]),
    # Exynos 9825
    LibData("libs/f62_r.so",    0x768, 0x770, ["40F206308DE8110104201449144A154B79447A447B44EDF0C8EB"]),
    LibData("libs/f62_t_64.so", 0x8cc, 0x8d0, ["E1FCFFF002FEFFF0E3FDFFD021A411914210029163043291C4608052E603009180008052E503132A2CB40594"]),
]

class TestLibs(unittest.TestCase):
    def test_find_capabilities_and_hw_level_offsets(self):
        for lib in LIBS:
            print(lib.path)

            self.assertEqual(
                find_capabilities_and_hw_level_offsets(lib.data),
                (lib.available_cap_offset, lib.hw_level_offset)
            )

    def test_sensor_info_struct_mod(self):
        for lib in LIBS:
            print(lib.path)

            mod = build_sensor_info_struct_mod(lib.data)
            pattern = mod.try_match(lib.data)[0]
            patched = mod.try_patch(lib.data)
            self.assertIsNotNone(patched)
            self.assertIsNotNone(pattern)
            self.assertEqual(len(patched), len(lib.data))

            if len(lib.modifiable_chunks) == 0:
                continue

            # Since we didn't pass any args to build_sensor_info_struct_mod,
            # the whole modifiable chunks should be replaced with NOPs
            nop = asm('nop', pattern.is_64bit)
            expected_nops = sum([len(chunk) for chunk in lib.modifiable_chunks]) / len(nop)

            found_nops = 0
            i = 0
            while i < len(patched):
                if patched[i] != lib.data[i]:
                    start = i
                    while i < len(patched):
                        if patched[i:(i + len(nop))] != nop:
                            break

                        i += len(nop)
                        found_nops += 1

                    chunk = lib.data[start:i]
                    for expected_chunk in lib.modifiable_chunks:
                        self.assertIn(expected_chunk, lib.data)
                        self.assertNotIn(expected_chunk, patched)
                        self.assertIn(chunk, expected_chunk)

                i += 1

            self.assertEqual(found_nops, expected_nops)