from dataclasses import dataclass
import hashlib


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
        convert = bytes.fromhex()
        return cls(convert(job_id), convert(previous_hash), convert(trie_hash), convert(coinb1), convert(coinb2),
                   [convert(branch) for branch in merkle_root], convert(version), convert(bit), convert(time), clean)


@dataclass
class Work:
    job_id: bytes
    nonce: int
    extra_nonce: int
    difficulty: int
    target: bytes
    hardware_target: bytes
    hardware_difficulty: int
    data: bytes
    coinbase: bytes
    time: int
    clean: bool

    @classmethod
    def from_job(cls, job: Job, extra_nonce1: bytes, extra_nonce2_size: int):
        coinbase = sha256d(job.coinbase1 + extra_nonce1 + (b'\x00' * extra_nonce2_size) + job.coinbase2)
        merkle_root = coinbase
        for branch in job.merkle_root:
            merkle_root = sha256d(merkle_root + branch)
        data = (job.encoded_version + job.previous_hash + merkle_root[::-1] +
                job.trie_hash + job.encoded_time + job.encoded_nbit)

        pass

