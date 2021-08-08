from unittest import TestCase

from lb1miner.miner import Job, Work, diff_to_target


class TestJob(TestCase):
    def test_from_stratum(self):
        stratum_params = ["a309", "5334d82d54583671aa7e8f9e5f482204d101e74104c8056af2280c7d2dffb941",
                          "b27a34586645220b88082e3f5520793bd01ff1ccce4d5c936d5b12802920c481",
                          "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2003fd380f04d01af56008",
                          "0d2f6e6f64655374726174756d2f00000000020000000000000000266a24aa21a9ed33fe741208823b47a170823b5d7c2d3367cccb5572c2ff3111c01551f9727e4116e13a07060000001976a914bf4881a63ce29d7370f633422e868c2005d751d188ac00000000",
                          ["6f1d8577d899831597c552ec0065a1cbbd25bc119ad8a04caf3d72af1016da03",
                           "0fb08b473071bdf8166248d5e692432007ff6ec0688a907454c4f10e1a4f2678",
                           "d0dc4ae212225f4ff187be665bce09146903a341508775d1900e0992592f14dc",
                           "394fb707a447461f4353b8a81d64ef3d48c9dccab2a8fa4bb80e7f84e40f679b",
                           "92d1b6b8bc05878f642e0132bda2582c4ff64eab9b857e11eea19d0245716e70"], "20000000", "1a015329",
                          "60f51ad0", True]
        job = Job.from_stratum(*stratum_params)
        target = diff_to_target(262144)
        work = Work.from_job(job, bytes.fromhex("485fd81a"), 4, target)
        self.assertEqual(list(work.data),
                         [198, 235, 217, 181, 111, 235, 14, 103, 49, 177, 124, 113, 23, 14, 36, 23, 185, 252, 100, 2,
                          90, 15, 83, 210, 183, 110, 65, 247, 129, 47, 243, 163, 112, 197, 250, 46, 88, 52, 122, 178,
                          11, 34, 69, 102, 63, 46, 8, 136, 59, 121, 32, 85, 204, 241, 31, 208, 147, 92, 77, 206, 128,
                          18, 91, 109, 129, 196, 32, 41, 208, 26, 245, 96, 41, 83, 1, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertFalse(work.check_nonce(bytes.fromhex('1e0cb44802000000')))
        work.target = bytes.fromhex('0000000033333333ffffffffffffffffffffffffffffffffffffffffffffffff')
        self.assertTrue(work.check_nonce(bytes.fromhex('1e0cb44802000000')))
