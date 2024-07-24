import struct
import functools
import operator
import os
from typing import Sequence

DELTA = 0x9E3779B9
NUM_ROUNDS = 32
MASK32 = 0xFFFFFFFF
EMPTY_KEY = "00000000000000000000000000000000"

TXT_KEY = struct.unpack("<4I", bytes.fromhex(os.getenv("TXT_KEY", EMPTY_KEY)))
CFG_KEY = struct.unpack("<4I", bytes.fromhex(os.getenv("CFG_KEY", EMPTY_KEY)))
HDR_KEY = struct.unpack("<4I", bytes.fromhex(os.getenv("HDR_KEY", EMPTY_KEY)))

assert functools.reduce(operator.xor, TXT_KEY) == 0x15DF2980, "invalid TXT_KEY"
assert functools.reduce(operator.xor, CFG_KEY) == 0x0759C1F6, "invalid CFG_KEY"
assert functools.reduce(operator.xor, HDR_KEY) == 0xBEB76320, "invalid HDR_KEY"


def decrypt(ciphertext: bytes, offset: int, key: Sequence[int]) -> bytes:
    plaintext = []
    for i in range(0, len(ciphertext), 8):
        v0, v1 = struct.unpack("<2I", ciphertext[i : i + 8])
        sum = (DELTA * NUM_ROUNDS) & MASK32
        for _ in range(NUM_ROUNDS):
            v1 -= (
                (((v0 << 4) ^ (v0 >> 5)) + v0)
                ^ (sum + key[(sum >> 11) & 3] + offset + i)
            ) & MASK32
            v1 += MASK32 + 1 if v1 < 0 else 0
            sum -= DELTA
            sum += MASK32 + 1 if sum < 0 else 0
            v0 -= (
                (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3] + offset + i)
            ) & MASK32
            v0 += MASK32 + 1 if v0 < 0 else 0
        plaintext.append(struct.pack("<2I", v0, v1))
    return b"".join(plaintext)


def encrypt(plaintext: bytes, offset: int, key: Sequence[int]) -> bytes:
    ciphertext = []
    for i in range(0, len(plaintext), 8):
        v0, v1 = struct.unpack("<2I", plaintext[i : i + 8])
        sum = 0
        for _ in range(NUM_ROUNDS):
            v0 = (
                v0
                + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3] + offset + i))
            ) & MASK32
            sum = (sum + DELTA) & MASK32
            v1 = (
                v1
                + (
                    (((v0 << 4) ^ (v0 >> 5)) + v0)
                    ^ (sum + key[(sum >> 11) & 3] + offset + i)
                )
            ) & MASK32
        ciphertext.append(struct.pack("<2I", v0, v1))
    return b"".join(ciphertext)


def deframe(buff: bytes) -> bytes:
    _buff = b""
    for i in range(0, len(buff), 8):
        _buff += buff[i + 2 : i + 8]
    return _buff


def frame(buff: bytes) -> bytes:
    # TODO implement
    return b""
