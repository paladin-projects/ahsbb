meta:
  id: ahsbb
  title: HPE Active Health System Log Black Box file
  file-extension: bb
  license: GPL-3.0-or-later
  encoding: ASCII
  endian: le

doc: |
  HPE Active Health System is an application running on Integrated Lights-Out
  Board Management Processor of ProLiant and Apollo servers starting from
  Generation 8.

seq:
  - id: records
    type: record
    repeat: eos

types:
  record:
    seq:
      - id: magic
        type: u2
      - id: body
        type:
          switch-on: magic
          cases:
            0x0002: type18
            0x000a: type6
            0x002a: type22
            0x003a: type10
            0x005a: type16
            0x006a: type9
            0x0128: type11
            0x0138: type11
            0x0184: type1
            0x0188: type1
            0x018c: type1
            0x018d: type7
            0x0202: type4
            0x0204: type17
            0x0208: type15
            0x0284: type1
            0x0286: type3
            0x0288: type1
            0x028c: type1
            0x028e: type3
            0x0384: type1
            0x0388: type1
            0x038c: type1
            0x0484: type1
            0x0488: type1
            0x048c: type1
            0x0584: type1
            0x0586: type3
            0x0588: type1
            0x058c: type1
            0x062c: type12
            0x0684: type1
            0x0688: type1
            0x068c: type1
            0x0884: type1
            0x0886: type3
            0x0888: type1
            0x088c: type1
            0x088e: type3
            0x0984: type1
            0x0988: type1
            0x098c: type1
            0x0c84: type1
            0x0c86: type23
            0x0c88: type1
            0x0c8c: type1
            0x0c8e: type23
            0x0d18: type15
            0x0d84: type1
            0x0d88: type1
            0x0d8c: type1
            0x0e84: type1
            0x0e88: type1
            0x0e8c: type1
            0x0f84: type1
            0x0f88: type1
            0x0f8c: type1
            0x1084: type1
            0x1088: type1
            0x108c: type1
            0x1148: type8
            0x1184: type1
            0x1188: type1
            0x118c: type1
            0x1384: type1
            0x1386: type3
            0x1388: type1
            0x138c: type1
            0x138e: type3
            0x1392: type3
            0x13a2: type3
            0x1584: type1
            0x1588: type1
            0x158c: type1
            0x1708: type13
            0x1784: type1
            0x1788: type1
            0x178c: type1
            0x1884: type1
            0x1888: type1
            0x188c: type1
            0x1984: type1
            0x1988: type1
            0x198c: type1
            0x1a08: type21
            0x1a84: type1
            0x1a88: type1
            0x1a8c: type1
            0x1b84: type1
            0x1b88: type1
            0x1b8c: type1
            0x1c84: type1
            0x1c88: type1
            0x1c8c: type1
            0x1d08: type2
            0x1d84: type1
            0x1d88: type1
            0x1d8c: type1
            0x1e84: type1
            0x1e88: type1
            0x1e8c: type1
            0x1f84: type1
            0x1f88: type1
            0x1f8c: type1
            0x2084: type1
            0x2088: type1
            0x208c: type1
            0x2184: type1
            0x2188: type1
            0x218c: type1
            0x2284: type1
            0x2288: type1
            0x228c: type1
            0x2484: type1
            0x2488: type1
            0x2584: type1
            0x2588: type1
            0x258c: type1
            0x2684: type1
            0x2688: type1
            0x268c: type1
            0x2a00: type20
            0x2a29: type11
            0x2a84: type1
            0x2a88: type1
            0x2a8c: type1
            0x2e84: type1
            0x2e88: type1
            0x2e8c: type1
            0x3084: type1
            0x3086: type3
            0x3088: type1
            0x308c: type1
            0x308e: type3
            0x3186: type3
            0x3188: type1
            0x318e: type3
            0x3192: type3
            0x31a2: type3
            0x3286: type23 # 44 bytes
            0x3288: type1 # 96 bytes 
            0x3384: type1
            0x3388: type1
            0x3784: type1
            0x3788: type1
            0x3802: type11
            0x3886: type3
            0x3888: type1
            0x388e: type3
            0x3892: type3
            0x3984: type1
            0x3988: type1
            0x398c: type1
            0x3b08: type5
            0x3b84: type1
            0x3b88: type1
            0x3e84: type1
            0x3e88: type1
            0x3f84: type1
            0x3f88: type1
            0x4084: type1
            0x4088: type1 # 96 bytes
            0x408c: type1
            0x4286: type23
            0x4288: type1
            0x428e: type23
            0x4384: type1
            0x4386: type23
            0x4388: type1
            0x438c: type1
            0x438e: type23
            0x4484: type1
            0x4486: type23
            0x4488: type1
            0x448c: type1
            0x448e: type23
            0x4492: type3
            0x4584: type1
            0x4586: type23 # 44 bytes
            0x4588: type1
            0x458e: type23
            0x4784: type1
            0x4788: type1
            0x4884: type1
            0x4888: type1
            0x488c: type1
            0x4b84: type1
            0x4b88: type1
            0x4c86: type23
            0x4c88: type1
            0x4c8e: type23
            0x5584: type1
            0x5588: type1
            0x5684: type1
            0x5688: type1
            0x6286: type3
            0x628e: type3
            0x6292: type3
            0x62a2: type3
            0x6384: type1
            0x6386: type3
            0x6388: type1
            0x638c: type1
            0xe184: type1
            0xe188: type1
            0xe18c: type1
            0xe284: type1
            0xe288: type1
            0xe28c: type1
            _: failback
  type1:
    seq:
      - id: unknown1
        type: u2
      - id: unknown2
        type: u4
      - id: body
        type: strz
        size: 88
  type2:
    seq:
      - id: unknown1
        type: u2
      - id: unknown2
        type: u2
  type3:
    seq:
      - id: unknown1
        type: u2
      - id: unknown2
        type: u4
      - id: unknown3
        type: u4
      - id: body
        type: strz
        size: 32
  type4:
    seq:
      - id: unknown1
        size: 12
  type5:
    seq:
      - id: unknown1
        type: u2
      - id: unknown2
        type: u4
      - id: body
        size: 61
  type6:
    seq:
      - id: unknown1
        size: 21
  type7:
    seq:
      - id: unknown1
        size: 238
  type8:
    seq:
      - id: unknown1
        type: u4
      - id: unknown2
        type: u4
      - id: body
        type: strz
        size: 48
  type9:
    seq:
      - id: unknown1
        size: 18
  type10:
    seq:
      - id: unknown1
        size: 13
  type11:
    seq:
      - id: unknown1
        size: 5
      - id: reclen
        type: u2
      - id: body
        type: str
        terminator: 0x0a
        size: reclen
  type12:
    seq:
      - id: unknown1
        size: 7
  type13:
    seq:
      - id: unknown1
        size: 23
  type14:
    seq:
      - id: unknown1
        size: 11
  type15:
    seq:
      - id: unknown1
        size: 1
      - id: reclen
        type: u2
      - id: body
        type: strz
        size: reclen
  type16:
    seq:
      - id: unknown1
        size: 4
      - id: reclen
        type: u2
      - id: body
        type: strz
        size: reclen
  type17:
    seq:
      - id: unknown1
        size: 15
      - id: body
        type: strz
        size: 48
  type18:
    seq:
      - id: unknown1
        size: 18
  type19:
    seq:
      - id: unknown1
        size: 16
  type20:
    seq:
      - id: unknown1
        size: 14
  type21:
    seq:
      - id: unknown1
        size: 5
  type22:
    seq:
      - id: unknown1
        size: 17
  type23:
    seq:
      - id: unknown1
        type: u2
      - id: unknown2
        type: u4
      - id: body
        type: strz
        size: 36
  failback:
    seq:
      - id: unknown1
        size: 1
        process: stop(_io)
