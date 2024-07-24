#!/usr/bin/env python3

from lib.msp import MspInterface, MspCmd
from lib.fway import FWayInterface, FWayCmd
import logging
import json
import time
import struct
import random
import serial
import sys
import argparse
from lib.crypto import encrypt, TXT_KEY


guess_strategy = {}
with open("guess.json", "r") as fh:
    guess_strategy = json.loads(fh.read())


def get_guesses(buff):
    guesses = []
    k = buff[-2:].hex()
    if k in guess_strategy:
        guesses.extend(bytes.fromhex(guess_strategy[k]))
    _guesses = list(range(0x100))
    random.shuffle(_guesses)
    for i in _guesses:
        if i not in guesses:
            guesses.append(i)
    return guesses


def main():
    parser = argparse.ArgumentParser(
        description="Dump ESC flash contents by guessing byte values using the 'verify' command",
    )

    parser.add_argument(
        "-p", "--port", help="define serial port to use", default="/dev/ttyACM0"
    )
    parser.add_argument(
        "-n", "--esc-id", help="number of ESC to use", default=0, type=int
    )
    parser.add_argument(
        "-v", "--verbose", help="verbose log output", action="store_true"
    )
    parser.add_argument(
        "-o", "--offset", help="offset to start at", default=8090, type=int
    )
    parser.add_argument(
        "-l", "--length", help="number of bytes to dump", default=1024, type=int
    )
    parser.add_argument(
        "-w",
        "--write-to",
        help="number of bytes to dump",
        default="./dump.txt",
        type=str,
    )

    args = parser.parse_args(sys.argv[1:])

    logging.basicConfig(level=logging.INFO if not args.verbose else logging.DEBUG)
    esc_id = struct.pack("B", args.esc_id)

    with serial.Serial(args.port) as ser:
        with MspInterface(ser) as msp:
            api_version = struct.unpack("3B", msp.cmd(MspCmd.MSP_API_VERSION))
            fc_variant = msp.cmd(MspCmd.MSP_FC_VARIANT).decode()
            fc_version = struct.unpack("3B", msp.cmd(MspCmd.MSP_FC_VERSION))

            logging.debug(f"{api_version=!r} {fc_variant=!r} {fc_version=!r}")

            assert api_version >= (0, 1, 41)
            assert fc_variant == "BTFL"
            assert fc_version >= (4, 0, 0)

            logging.info(f"Connected to FC: {fc_variant} {fc_version}")

            with FWayInterface(msp) as fway:
                proto_version = struct.unpack(
                    "B", fway.cmd(FWayCmd.PROTOCOL_GET_VERSION)
                )[0]
                if_name = fway.cmd(FWayCmd.INTERFACE_GET_NAME).decode()
                if_version = struct.unpack(
                    "2B", fway.cmd(FWayCmd.INTERFACE_GET_VERSION)
                )

                logging.debug(f"{proto_version=!r} {if_name=!r} {if_version=!r}")

                assert proto_version >= 107
                assert if_name == "m4wFCIntf"
                assert if_version >= (200, 6)

                logging.info(f"Connected to 4way interface {if_name} {if_version}")

                assert fway.cmd(FWayCmd.DEVICE_SET_MODE, b"\x04") == b"\x00"
                time.sleep(0.1)

                logging.info(f"Resetting ESC {args.esc_id} ...")
                assert fway.cmd(FWayCmd.DEVICE_RESET, esc_id) == b"\x00"
                time.sleep(5)

                assert (
                    fway.cmd(FWayCmd.DEVICE_INIT_FLASH, esc_id) == b"\x06\x33\x6a\x04"
                )
                time.sleep(0.3)

                logging.info(f"Connected to ESC {args.esc_id} ...")

                addr = args.offset
                end_addr = args.offset + args.length
                # TODO be smarter about initial buffer: automatically find a near offset with 00s or FFs
                buff = b"\xff" * 7

                with open(args.write_to, "w") as ofh:
                    while addr < end_addr:
                        found = False
                        for x in get_guesses(buff):
                            _buff = buff + bytes([x])

                            sys.stdout.write(f"\r{hex(addr)} {_buff.hex()}")
                            sys.stdout.flush()

                            vbuff = encrypt(_buff, addr, TXT_KEY)
                            ack = fway.cmd(
                                FWayCmd.DEVICE_VERIFY, vbuff, addr, return_ack=True
                            )

                            if ack == b"\x00":
                                real_addr = addr + len(buff) - 1
                                ofh.write(f"{real_addr:#x}: {x:#x}\n")

                                buff = buff[1:] + bytes([x])
                                addr += 1

                                sys.stdout.write("\n")
                                sys.stdout.flush()

                                found = True
                                break
                        assert found

                assert fway.cmd(FWayCmd.DEVICE_RESET, esc_id) == b"\x00"
                time.sleep(0.1)


if __name__ == "__main__":
    main()
