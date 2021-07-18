import unittest
from lb1miner.serialization import RXStatusPacket, RXNoncePacket


class SerializationTestCase(unittest.TestCase):
    def test_rx_status(self):
        packet = RXStatusPacket.unpack(
            bytes.fromhex('a53c9652101b000000087878203c00ae01ee02000000003f00000000fc0869c35a'))
        self.assertEqual(packet.length, 27)
        self.assertEqual(packet.chips, 8)
        self.assertEqual(packet.cores, 120)
        self.assertEqual(packet.good_cores, 120)
        self.assertEqual(packet.scanbits, 32)
        self.assertEqual(packet.scantime, 60)
        self.assertEqual(packet.voltage, 430)
        self.assertEqual(packet.freq, 750)
        self.assertEqual(packet.mode, 0)
        self.assertEqual(packet.temp, 63)
        self.assertEqual(packet.reboot_count, 0)
        self.assertEqual(packet.tempwarn, 0)
        self.assertEqual(packet.fanwarn, 0)
        self.assertEqual(packet.powerwarn, 0)
        self.assertEqual(packet.rpm, 2300)

    def test_rx_none(self):
        packet = RXNoncePacket.unpack(
            bytes.fromhex('a53c9651101200000011010511dba0d13a0000000069c35a'))
        print(packet)
        self.assertEqual(packet.length, 18)
        self.assertEqual(packet.job_id, 17)
        self.assertEqual(packet.chip_id, 1)
        self.assertEqual(packet.core_id, 5)
        self.assertEqual(packet.nonce, 252625083153)
        self.assertEqual(packet.has_hash, False)
        self.assertEqual(packet.hash, b'')




if __name__ == '__main__':
    unittest.main()
