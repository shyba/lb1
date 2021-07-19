from dataclasses import dataclass
from struct import Struct


def deserialize_packet(payload: bytes):
    assert payload[3] in DESERIALIZERS, f"{hex(payload[3])} is not a known type. payload: {payload.hex()}"
    return DESERIALIZERS[payload[3]].unpack(payload)


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
        return cls(cls.type, cls.version, *cls.parser.unpack(payload[5:-3]))

    def pack(self):
        raise NotImplemented("this packet comes from the device, packing not supported")


@dataclass
class RXDeviceInformationPacket(Packet):
    type: int = 0x54
    version: int = 0x10
    length: int = 0
    model_name_length: int = 0
    model_name: bytes = b''
    firmware_version_length: int = 0
    firmware_version: bytes = b''
    serial_number: bytes = b''
    work_depth: int = 0
    parser = Struct('<BBIB16sB8s21sB')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        return cls(*cls.parser.unpack(payload[3:-3]))
        offset = 10 + packet.model_name_length
        packet.model_name = payload[10:offset]
        packet.firmware_version_length = payload[offset + 1]
        packet.firmware_version = payload[(offset+1):(offset+packet.firmware_version_length)]
        offset += payload[offset]
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
        if payload[20] == 0:
            return cls(0x51, 0x10, *cls.parser.unpack(payload[5:20]), has_hash=False)
        else:
            raise NotImplemented('need a sample')
        return packet

    def pack(self):
        raise NotImplemented("this packet comes from the device, packing not supported")


@dataclass
class RXJobResultPacket(Packet):
    type: int = 0x55
    version: int = 0x10
    length: int = 0
    job_id: int = 0
    parser = Struct('<IB')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        return cls(0x55, 0x10, *cls.parser.unpack(payload[5:10]))

    def pack(self):
        raise NotImplemented("this packet comes from the device, packing not supported")


@dataclass
class TXJobDataPacket(Packet):
    type: int = 0xA1
    version: int = 0x10
    length: int = 0
    target: int = 0
    start_nonce: int = 0
    end_nonce: int = 0
    job_num: int = 0
    job_id: int = 0
    job_data: bytes = b''
    parser = Struct('<BBIQQQBB')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        return cls(*cls.parser.unpack(payload[3:35]), job_data=payload[35:-3])

    def pack(self):
        self.length = len(self.job_data) + 32
        return b''.join(
            [self.preamble,
             self.parser.pack(self.type, self.version, self.length, self.target, self.start_nonce, self.end_nonce,
                              self.job_num, self.job_id),
             self.job_data,
             self.finalizer])


@dataclass
class TXDeviceParametersPacket(Packet):
    type: int = 0xA2
    version: int = 0x10
    length: int = 0
    flag: int = 0
    voltage: int = 0
    freq: int = 0
    mode: int = 0
    temp: int = 0
    parser = Struct('<BBIBHHIB')
    QUERY = 0x52
    SET = 0xA2

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        if payload[9] == cls.QUERY:
            return cls(cls.type, cls.version, int.from_bytes(payload[5:8], 'little', signed=False), 0x52)
        elif payload[9] == cls.SET:
            return cls(*cls.parser.unpack(payload[3:-3]))
        else:
            raise NotImplemented(f'{hex(payload[9])} is not a known flag')

    def pack(self):
        if self.flag == self.QUERY:
            self.length = 7
            return b''.join(
                [self.preamble,
                 self.parser.pack(self.type, self.version, self.length, self.flag, self.voltage, self.freq, self.mode,
                                  self.temp)[:7],
                 self.finalizer])
        elif self.flag == self.SET:
            self.length = 16
            return b''.join(
                [self.preamble,
                 self.parser.pack(self.type, self.version, self.length, self.flag, self.voltage, self.freq, self.mode,
                                  self.temp),
                 self.finalizer])
        else:
            raise Exception(f'unknown flag {hex(self.flag)}')


@dataclass
class TXQueryDeviceInformationPacket(Packet):
    type: int = 0xA4
    version: int = 0x10
    length: int = 6
    parser = Struct('<BBI')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        return cls(*cls.parser.unpack(payload[3:-3]))

    def pack(self):
        self.length = self.length or 6
        return b''.join([self.preamble, self.parser.pack(self.type, self.version, self.length), self.finalizer])


@dataclass
class TXRestartPacket(Packet):
    type: int = 0xAC
    version: int = 0x10
    length: int = 6
    parser = Struct('<BBI')

    @classmethod
    def unpack(cls, payload: bytes):
        assert payload[:3] == cls.preamble
        assert payload[-3:] == cls.finalizer
        assert payload[3] == cls.type
        assert payload[4] == cls.version
        return cls(*cls.parser.unpack(payload[3:-3]))

    def pack(self):
        self.length = self.length or 6
        return b''.join([self.preamble, self.parser.pack(self.type, self.version, self.length), self.finalizer])


DESERIALIZERS = {
    RXStatusPacket.type: RXStatusPacket,
    RXNoncePacket.type: RXNoncePacket,
    RXJobResultPacket.type: RXJobResultPacket,
    RXDeviceInformationPacket.type: RXDeviceInformationPacket,
    TXJobDataPacket.type: TXJobDataPacket,
    TXDeviceParametersPacket.type: TXDeviceParametersPacket,
    TXQueryDeviceInformationPacket.type: TXQueryDeviceInformationPacket,
    TXRestartPacket.type: TXRestartPacket
}