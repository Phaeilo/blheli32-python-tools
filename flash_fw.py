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
from lib.crypto import encrypt, deframe, decrypt, frame, TXT_KEY, CFG_KEY, HDR_KEY


def main():
    parser = argparse.ArgumentParser(
        description="Flash new firmware to an ESC with an erase, flash, verify cycle.",
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
    # TODO make input file configurable

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

                serial_num = fway.cmd(FWayCmd.DEVICE_READ, b"\x10", 0xF7AC)
                print(f"{serial_num=!r}")
                print(f"{serial_num.hex()=!r}")

                # FIXME replace hard-coded path
                fname = "../hakrc_35A_dump.bin"
                with open(fname, "rb") as fh:
                    # erase flash
                    for offset in range(0x2000, 0x7c00, 0x400):
                        fway.cmd(FWayCmd.DEVICE_ERASE_PAGE, struct.pack("B", offset >> 10), addr=0)
                        print("erased", hex(offset))

                    time.sleep(0.25)

                    # write firmware
                    for offset in range(0x2000, 0x7c00, 0x400):
                        for _offset in range(0, 0x400, 0x40):
                            if offset + _offset == 0x2000:
                                continue

                            fh.seek(offset + _offset)
                            buff = fh.read(0x40)
                            assert len(buff) == 0x40

                            buff = encrypt(buff, offset + _offset, TXT_KEY)
                            fway.cmd(FWayCmd.DEVICE_WRITE, buff, offset + _offset)
                            print("written", hex(offset + _offset))

                    # verify firmware
                    for offset in range(0x2000, 0x7c00, 0x400):
                        for _offset in range(0, 0x400, 0x40):
                            if offset + _offset == 0x2000:
                                continue

                            fh.seek(offset + _offset)
                            buff = fh.read(0x40)
                            assert len(buff) == 0x40

                            buff = encrypt(buff, offset + _offset, TXT_KEY)
                            a = fway.cmd(FWayCmd.DEVICE_VERIFY, buff, offset + _offset, return_ack=True)
                            print(hex(offset + _offset), "OK" if a == b"\x00" else "NOT OK!!!")

                    fh.seek(0x7c00)
                    buff = fh.read(192)
                    assert len(buff) == 192

                    # write config
                    print(buff)
                    buff = frame(buff)
                    buff = encrypt(buff, 0x7c00, CFG_KEY)
                    fway.cmd(FWayCmd.DEVICE_ERASE_PAGE, struct.pack("B", 0x7c00 >> 10), addr=0)
                    time.sleep(0.1)
                    fway.cmd(FWayCmd.DEVICE_WRITE, buff, 0x7c00)
                    time.sleep(0.1)

                    # read config
                    cfg = fway.cmd(FWayCmd.DEVICE_READ, b"\x00", 0x7C00)
                    cfg = deframe(decrypt(cfg, 0x7C00, CFG_KEY))
                    print(f"{cfg=!r}")

                    # build header (license?)
                    hdr = (b"\x00" * 8) + serial_num
                    hdr += b"\xff" * (66 - len(hdr))

                    # write header
                    buff = encrypt(frame(hdr), 0x8000, HDR_KEY)
                    fway.cmd(FWayCmd.DEVICE_WRITE, buff, 0x8000)
                    time.sleep(0.1)

                    # read header
                    _hdr = fway.cmd(FWayCmd.DEVICE_READ, b"\x40", 0x8000)
                    _hdr = decrypt(_hdr, 0x8000, HDR_KEY)
                    print(f"{_hdr=!r}")

                assert fway.cmd(FWayCmd.DEVICE_RESET, esc_id) == b"\x00"
                time.sleep(0.1)



if __name__ == "__main__":
    main()
