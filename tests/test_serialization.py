import unittest
from lb1miner.serialization import RXStatusPacket, RXNoncePacket, RXJobResultPacket, TXJobDataPacket, \
    TXDeviceParametersPacket, TXQueryDeviceInformationPacket, RXDeviceInformationPacket, TXRestartPacket


class SerializationTestCase(unittest.TestCase):
    def test_rx_device_information(self):
        packet = RXDeviceInformationPacket.unpack(
            bytes.fromhex('a53c965410360000000d476f6c647368656c6c2d4c423100000005302e302e3100'
                          '00000f4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a00006d31000869c35a'))
        print(packet)
        self.assertEqual(packet.length, 54)
        self.assertEqual(packet.model_name_length, 13)
        self.assertEqual(packet.model_name, b'Goldshell-LB1\x00\x00\x00')
        self.assertEqual(packet.firmware_version_length, 5)
        self.assertEqual(packet.firmware_version, b'0.0.1\x00\x00\x00')
        self.assertEqual(packet.serial_number, b'\x0fJJJJJJJJJJJJJJJ\x00\x00m1\x00')
        self.assertEqual(packet.work_depth, 8)

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
        self.assertEqual(packet.length, 18)
        self.assertEqual(packet.job_id, 17)
        self.assertEqual(packet.chip_id, 1)
        self.assertEqual(packet.core_id, 5)
        self.assertEqual(packet.nonce, 252625083153)
        self.assertEqual(packet.has_hash, False)
        self.assertEqual(packet.hash, b'')

    def test_rx_job_result(self):
        packet = RXJobResultPacket.unpack(
            bytes.fromhex('a53c965510070000001569c35a'))
        self.assertEqual(packet.length, 7)
        self.assertEqual(packet.data, b'\x15')

    def test_tx_job_data(self):
        hex_packet = ('a53c96a110a800000033333333000000000000000000000000ffffffff000000000114d5'
                      'dd71f755c9c0b50797e00f79138988b3bcd9f30cbfde5b353e85ed4dce1619bbf591836c'
                      '15ea896f251a39ece0d590bede24d28c843b9d6d0db82346735ed0e98e4dd1b30aee60c3'
                      '7b011a000000000000000000000000000000000000000000000000000000000000000000'
                      '00000000000000000000000000000000000000000000000000000069c35a')
        packet = TXJobDataPacket.unpack(bytes.fromhex(hex_packet))
        self.assertEqual(packet.length, 168)
        self.assertEqual(packet.target, 858993459)
        self.assertEqual(packet.start_nonce, 0)
        self.assertEqual(packet.end_nonce, 4294967295)
        self.assertEqual(packet.job_num, 1)
        self.assertEqual(packet.job_id, 20)
        self.assertIn(packet.job_data.hex(), hex_packet)
        self.assertEqual(hex_packet, packet.pack().hex())
        packet.length = 0
        self.assertEqual(hex_packet, packet.pack().hex())

    def test_tx_device_parameters(self):
        hex_packet = 'a53c96a210070000005269c35a'
        packet = TXDeviceParametersPacket.unpack(bytes.fromhex(hex_packet))
        self.assertEqual(packet.length, 7)
        self.assertEqual(packet.flag, 0x52)
        self.assertEqual(packet.voltage, 0)
        self.assertEqual(packet.freq, 0)
        self.assertEqual(packet.mode, 0)
        self.assertEqual(packet.temp, 0)
        self.assertEqual(hex_packet, packet.pack().hex())
        packet.length = 0
        self.assertEqual(hex_packet, packet.pack().hex())

    def test_tx_device_parameters_full_flag(self):
        hex_packet = 'a53c96a21010000000a2ae01ee02000000005069c35a'
        packet = TXDeviceParametersPacket.unpack(bytes.fromhex(hex_packet))
        self.assertEqual(packet.length, 16)
        self.assertEqual(packet.flag, 0xA2)
        self.assertEqual(packet.voltage, 430)
        self.assertEqual(packet.freq, 750)
        self.assertEqual(packet.mode, 0)
        self.assertEqual(packet.temp, 80)
        self.assertEqual(hex_packet, packet.pack().hex())
        packet.length = 0
        self.assertEqual(hex_packet, packet.pack().hex())

    def test_tx_query_device_information(self):
        hex_packet = 'a53c96a4100600000069c35a'
        packet = TXQueryDeviceInformationPacket.unpack(bytes.fromhex(hex_packet))
        self.assertEqual(packet.length, 6)
        self.assertEqual(hex_packet, packet.pack().hex())
        self.assertEqual(hex_packet, TXQueryDeviceInformationPacket().pack().hex())

    def test_tx_restart(self):
        hex_packet = 'a53c96ac100600000069c35a'
        packet = TXRestartPacket.unpack(bytes.fromhex(hex_packet))
        self.assertEqual(packet.length, 6)
        self.assertEqual(hex_packet, packet.pack().hex())
        self.assertEqual(hex_packet, TXRestartPacket().pack().hex())


if __name__ == '__main__':
    unittest.main()
