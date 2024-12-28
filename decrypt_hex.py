#!/usr/bin/env python3

import sys
import io
import struct
import argparse
import logging
from lib.crypto import decrypt, deframe, TXT_KEY, CFG_KEY


def to_file(chunks):
    fh = io.BytesIO()
    for offset, buff in chunks:
        fh.seek(offset)
        fh.write(buff)
    return fh.getvalue()


def handle_chunk(offset, ciphertext):
    if offset < 0x7C00:
        plaintext = decrypt(ciphertext, offset, TXT_KEY)
    elif offset < 0x8000:
        plaintext = decrypt(ciphertext, offset, CFG_KEY)
        # throw away the first two bytes of every eight byte block
        plaintext = deframe(plaintext)
        # fix offset to account for four missing bytes in every 16 byte block
        assert offset & 0xf == 0
        offset -= (offset - 0x7c00) >> 2
    else:
        raise Exception()
    return offset, plaintext


def parse_hexfile(lines):
    decrypt_probably_ok = False

    for line in lines:
        if not line.startswith(":"):
            continue

        buff = bytes.fromhex(line[1:])
        size, offset, typ = struct.unpack(">BHB", buff[:4])

        if typ != 0:
            continue

        payload = buff[4 : 4 + size]
        assert len(payload) == size

        check = buff[4 + size]
        check_ = (((sum(buff[:-1]) & 0xFF) ^ 0xFF) + 1) & 0xFF
        assert check == check_

        offset, plaintext = handle_chunk(offset, payload)

        if not decrypt_probably_ok and plaintext in (b"\x00" * 16, b"\xff" * 16):
            decrypt_probably_ok = True

        yield offset, plaintext

    assert decrypt_probably_ok


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt one or multiple hex files",
    )

    parser.add_argument("hexfile", nargs="+")
    args = parser.parse_args(sys.argv[1:])

    logging.basicConfig(level=logging.INFO)

    for fname in args.hexfile:
        outname = fname + ".decrypted"
        try:
            with open(fname, "r") as fh:
                lines = fh.readlines()
            chunks = list(parse_hexfile(lines))
            buff = to_file(chunks)
            with open(outname, "wb") as fh:
                fh.write(buff)
            logging.info(f"Decrypted {fname!r} to {outname!r}")
        except Exception:
            logging.exception(f"Failed to process {fname!r}")


if __name__ == "__main__":
    main()
