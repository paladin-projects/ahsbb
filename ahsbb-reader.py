#!/usr/bin/env python3

import sys
from ahsbb import Ahsbb

bb = Ahsbb.from_file(sys.argv[1])

# for record in  bb.records:
#     if isinstance(record.body, Ahsbb.Type1) or isinstance(record.body, Ahsbb.Type3):
#         print(record.body.body)

while not bb._io.is_eof():
    try:
        record = Ahsbb.Record(bb._io)
        record._read()
    except:
        print("***** broken record")
        print(hex(record.magic))
        print(hex(record._io.pos()))
        continue
    if isinstance(record.body, Ahsbb.Type1) or isinstance(record.body, Ahsbb.Type3):
        print(record.body.body)
