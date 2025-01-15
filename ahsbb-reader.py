#!/usr/bin/env python3

import sys
from ahsbb import Ahsbb
from stop import UnknownMagic

with open(sys.argv[1], "rb") as io:
    try:
        bb = Ahsbb.from_io(io)
    except UnknownMagic as e:
        print("Unknown Magic", hex(e._io.read_u2le()), "at", hex(e._io.pos()))

# while not bb._io.is_eof():
#     print("Test")
#     try:
#         record = Ahsbb.Record(bb._io)
#         record._read()
#     except UnknownMagic:
#         print(hex(record.magic))
#         print(hex(record._io.pos()))
#         continue
#     if isinstance(record.body, Ahsbb.Type1) or isinstance(record.body, Ahsbb.Type3):
#         print(record.body.body)
