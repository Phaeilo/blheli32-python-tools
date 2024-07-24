#!/usr/bin/env python3

import sys
import operator
import json

prev = (0, 0)
hist = {}

while True:
    x = sys.stdin.buffer.read(1)
    if len(x) == 0:
        break
    x = x[0]
    if prev not in hist:
        hist[prev] = {}
    if x not in hist[prev]:
        hist[prev][x] = 0
    hist[prev][x] += 1
    prev = (prev[1], x)


_hist = {}
for p, h in hist.items():
    tmp = list(sorted(h.items(), key=operator.itemgetter(1), reverse=True))
    tmp = tmp[:16]
    tmp = [x[0] for x in tmp]
    tmp = bytes(tmp).hex()
    _p = bytes(p).hex()
    _hist[_p] = tmp


print(json.dumps(_hist, indent=2))
