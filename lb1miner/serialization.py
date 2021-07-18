from dataclasses import dataclass
from struct import Struct


@dataclass
class Packet:
    preamble = bytes.fromhex('A53C96')
    finalizer = bytes.fromhex('69C35A')
    type: int = 0x00

    @classmethod
    def unpack(cls, payload: bytes):
        pass

    def pack(self):
        pass


@dataclass
class RXStatusPacket(Packet):
    type: int = 0x52
    version: int = 0x10
    length: int = 0
    chips: int = 0
    cores: int = 0
    good_cores: int = 0
    scanbits: int = 0
    scantime: int = 0
    voltage: int = 0
    freq: int = 0
    mode: int = 0
    temp: int = 0
    reboot_count: int = 0
    tempwarn: int = 0
    fanwarn: int = 0
    powerwarn: int = 0
    rpm: int = 0
    parser = Struct('<IBBBBHHHIBBBBBH')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        packet = cls()
        (packet.length, packet.chips, packet.cores, packet.good_cores, packet.scanbits, packet.scantime, packet.voltage,
         packet.freq, packet.mode, packet.temp, packet.reboot_count, packet.tempwarn, packet.fanwarn, packet.powerwarn,
         packet.rpm) = cls.parser.unpack(payload[5:-3])
        return packet

    def pack(self):
        raise NotImplemented("this packet comes from the device, packing not supported")


@dataclass
class RXNoncePacket(Packet):
    type: int = 0x51
    version: int = 0x10
    length: int = 0
    job_id: int = 0
    chip_id: int = 0
    core_id: int = 0
    nonce: int = 0
    has_hash: bool = False
    hash: bytes = b''
    parser = Struct('<IBBBQ')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        packet = cls()
        if payload[20] == 0:
            packet.has_hash = False
            (packet.length, packet.job_id, packet.chip_id, packet.core_id, packet.nonce) = cls.parser.unpack(payload[5:20])
        return packet

    def pack(self):
        raise NotImplemented("this packet comes from the device, packing not supported")
