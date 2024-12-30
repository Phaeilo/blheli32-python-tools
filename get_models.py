#!/usr/bin/env python3


with open("BLHeli32DefaultsX.cfg", "rb") as fh:
    fh.seek(0x12)
    while True:
        x = fh.read(1)
        if len(x) == 0:
            break
        x = x[0]
        #if x == 0xff:
        #    continue
        #if x == 0:
        #    fh.seek(1, 1)
        #    continue
        l = x
        name = fh.read(l)
        fh.seek(10, 1)
        assert len(name) == l
        print(name.decode())


