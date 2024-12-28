#!/usr/bin/env python3

from lib.msp import MspInterface, MspCmd
from lib.fway import FWayInterface, FWayCmd
import logging
import time
import struct
import serial
import sys
import argparse
from lib.crypto import decrypt, CFG_KEY, HDR_KEY, deframe


def main():
    parser = argparse.ArgumentParser(
        description="Read the ESC configuration",
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
                # TODO determine if we can minimize this delay
                time.sleep(5)

                ifl = fway.cmd(FWayCmd.DEVICE_INIT_FLASH, esc_id)
                assert ifl[0] == 6 and ifl[3] == 4
                time.sleep(0.3)

                logging.info("Reading ESC {args.esc_id} ...")

                cfg = b""
                for _ in range(5):
                    cfg = fway.cmd(FWayCmd.DEVICE_READ, b"\x00", 0x7C00)
                    if len(cfg) == 0x100:
                        break
                    time.sleep(1)
                assert len(cfg) == 0x100
                cfg = deframe(decrypt(cfg, 0x7C00, CFG_KEY))
                print(f"{cfg=!r}")

                # TODO parse config contents into json/ini
                # see https://elmagnifico.tech/2021/07/20/BLHeliSuite32-Reverse3/

                eb = fway.cmd(FWayCmd.DEVICE_READ, b"\x10", 0xEB00)
                print(f"{eb=!r}")
                # TODO ReacActivationStat

                serial_num = fway.cmd(FWayCmd.DEVICE_READ, b"\x10", 0xF7AC)
                print(f"{serial_num=!r}")
                print(f"{serial_num.hex()=!r}")

                # TODO figure out how to read/pick the correct serial
                serial_num2 = fway.cmd(FWayCmd.DEVICE_READ, b"\x10", 0xF7E8)
                print(f"{serial_num2=!r}")
                print(f"{serial_num2.hex()=!r}")

                hdr = fway.cmd(FWayCmd.DEVICE_READ, b"\x40", 0x8000)
                hdr = decrypt(hdr, 0x8000, HDR_KEY)
                print(f"{hdr=!r}")
                # TODO what is the purpose of this "header" anyways?

                assert fway.cmd(FWayCmd.DEVICE_RESET, esc_id) == b"\x00"
                time.sleep(0.1)


if __name__ == "__main__":
    main()
