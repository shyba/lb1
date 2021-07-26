import math
import time
from dataclasses import dataclass
import hashlib

from lb1ext.lb1ext import py_sha256_transform


def sha256d(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


@dataclass
class Job:
    job_id: bytes
    previous_hash: bytes
    trie_hash: bytes
    coinbase1: bytes
    coinbase2: bytes
    merkle_root: [bytes]
    encoded_version: bytes
    encoded_nbit: bytes
    encoded_time: bytes
    clean: bool = True

    @classmethod
    def from_stratum(cls, job_id, previous_hash, trie_hash, coinb1, coinb2,
                     merkle_root, version, bit, time, clean=True):
        convert = bytes.fromhex
        return cls(convert(job_id), convert(previous_hash), convert(trie_hash), convert(coinb1), convert(coinb2),
                   [convert(branch) for branch in merkle_root], convert(version), convert(bit), convert(time), clean)


@dataclass
class Work:
    job_id: bytes
    nonce: int
    target: bytes
    hardware_target: bytes
    hardware_difficulty: int
    data: bytes
    raw_data: bytes
    time: int
    clean: bool

    @classmethod
    def from_job(cls, job: Job, extra_nonce1: bytes, extra_nonce2_size: int, target):
        coinbase = sha256d(job.coinbase1 + extra_nonce1 + (b'\x00' * extra_nonce2_size) + job.coinbase2)
        merkle_root = coinbase
        for branch in job.merkle_root:
            merkle_root = sha256d(merkle_root + branch)
        trie_hash = job.trie_hash
        # trie_hash = b''.join([trie_hash[i:i+4][::-1] for i in range(0, len(trie_hash), 4)])
        merkle_root = b''.join([merkle_root[i:i+4][::-1] for i in range(0, len(merkle_root), 4)])
        data = (job.encoded_version + job.previous_hash + merkle_root +
                trie_hash + job.encoded_time + job.encoded_nbit + b'\x00\x00\x00\x00')
        data = b''.join([data[i:i+4][::-1] for i in range(0, len(data), 4)])
        prehash = bytes(py_sha256_transform(data[:64]))
        final = (prehash + data[64:])
        final = final + bytes([0] * (136 - len(final)))
        return cls(job.job_id, extra_nonce1, target, 0, None, final, data, time.time(), job.clean)


def diff_to_target(difficulty: int):
    temp = hex(math.floor(0xffffffff / difficulty))[2:]
    return bytes.fromhex(f"{''.join(['0' * (16 - len(temp))])}{temp}{''.join(['f'] * 48)}")