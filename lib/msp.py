from enum import Enum
import serial
import struct
import functools
import time
import operator
import logging


class MspCmd(Enum):
    MSP_API_VERSION = 1
    MSP_FC_VARIANT = 2
    MSP_FC_VERSION = 3
    MSP_BOARD_INFO = 4
    MSP_BUILD_INFO = 5
    MSP_SET_PASSTHROUGH = 245


class MspInterface:
    def __init__(self, serial_port: serial.Serial):
        self._serial = serial_port
        self._logger = logging.getLogger(self.__class__.__name__)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def cmd(self, cmd: MspCmd, payload: bytes = b"") -> bytes:
        self._send(cmd, payload)
        return self._recv(cmd)

    def _checksum(self, buff: bytes) -> bytes:
        return struct.pack("B", functools.reduce(operator.xor, buff))

    def _read_bytes(self, size: int, timeout: int = 30) -> bytes:
        buff = b""
        deadline = time.monotonic() + timeout
        while len(buff) < size and time.monotonic() < deadline:
            buff += self._serial.read(size - len(buff))
        assert len(buff) == size
        return buff

    def _send(self, cmd: MspCmd, payload: bytes = b"") -> None:
        buff = struct.pack("2sc2B", b"$M", b"<", len(payload), cmd.value)
        buff += payload
        buff += self._checksum(buff[3:])
        self._logger.debug(f"_send() {cmd=!r} {payload=!r} {buff=!r}")
        x = self._serial.write(buff)
        assert x == len(buff)

    def _recv(self, cmd: MspCmd) -> bytes:
        header = self._read_bytes(5)
        magic, dir, size, _cmd = struct.unpack("2sc2B", header)
        self._logger.debug(f"_recv() {magic=!r} {dir=!r} {size=!r} {_cmd=:#04x}")
        assert magic == b"$M"
        assert dir == b">"
        assert _cmd == cmd.value

        payload = self._read_bytes(size)
        self._logger.debug(f"_recv() {payload=!r}")

        checksum = self._read_bytes(1)
        _checksum = self._checksum(header[3:] + payload)
        self._logger.debug(f"_recv() {checksum=!r} {_checksum=!r}")
        assert _checksum == checksum

        return payload
