#!/usr/bin/env python3

import sys
from ahsbb import Ahsbb
from stop import UnknownMagic

with open(sys.argv[1], "rb") as io:
    bb = Ahsbb.from_io(io)
    try:
        while not bb._io.is_eof():
            record = Ahsbb.Record(bb._io)
            record._read()
            if isinstance(record.body, Ahsbb.Type1) or isinstance(record.body, Ahsbb.Type3) or isinstance(record.body, Ahsbb.Type23) or isinstance(record.body, Ahsbb.Type11):
                print(hex(record.magic), record.body.body)
            else:
                print(hex(record.magic))
    except UnknownMagic:
        print("Unknown Magic", hex(bb._io.read_u2le()), "at", hex(bb._io.pos()))

