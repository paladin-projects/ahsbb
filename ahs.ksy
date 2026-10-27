meta:
  id: ahs
  title: HPE Active Health System (AHS) Log
  file-extension: ahs
  license: GPL-3.0-or-later
  endian: le
  encoding: ASCII
doc: |
  AHS log container: a flat sequence of "ABJR" file records. Each record
  carries one embedded file (name + payload). Files named "bcert.pkg" and
  "*.zbb" are gzip-compressed; every other payload is stored raw.

  Kaitai Struct has no built-in gzip process, so compressed payloads are
  exposed as raw bytes. Gunzip them first, then parse the result with the
  matching top-level type (bb, bcert_xml) via a new stream.

  Structure derived from https://github.com/tzong/ahs-extract (ahs-extract.js)
  and checked against a real iLO 5 and iLO 7 logs.

seq:
  - id: files
    type: file
    repeat: eos

types:
  file:
    seq:
      - id: magic
        contents: 'ABJR'
      - id: version
        type: u4
        doc: |
          Container version
      - id: len_data
        type: u4
        doc: Size of the (possibly compressed) payload in bytes
      - id: pad2
        contents: [0, 0, 0, 0]
      - id: entry_type
        type: u1
        doc: |
          0x21 numbered black box log (*.zbb), 0x01 dictionary
          (*_boot_support.zbb), 0x02 metadata file (CUST_INFO.DAT, file.pkg,
          clist.pkg, bcert.pkg). Other bits unknown.
      - id: bits_reserved
        size: 2
        doc: Zero in all entries seen
      - id: role
        type: u1
        enum: role
        doc: 0x80 ordinary entry, 0x81 iLO dictionary, 0x82 system dictionary
      - id: name
        type: str
        size: 32
        terminator: 0
        doc: Zero-terminated file name in a fixed 32-byte field
      - id: range_start
        type: date
        doc: Start of the period covered by the log
      - id: range_end
        type: date
        doc: End of the period covered by the log
      - id: file_no
        type: u4
        doc: |
          Number of the black box file (0x511 = 1297 for 0001297-...zbb),
          0xeeeeeeee for ilo_boot_support, 0xeeeeeeed for sys_boot_support,
          0 for metadata files
      - id: reserved
        size: 48
        doc: Zero in all entries seen
      - id: checksum
        type: u4
        doc: |
          Internal checksum of the decompressed data (algorithm not
          determined; the original script tries FNV32 variants, Fletcher32,
          CRC32 and Adler32 for comparison)
      - id: data
        size: len_data
        type: file_body(name, is_compressed)
    enums:
      role:
        0x80: ordinary
        0x81: ilo_dictionary
        0x82: sys_dictionary
    instances:
      is_compressed:
        value: >-
          name == "bcert.pkg" or
          (name.length >= 4 and name.substring(name.length - 4, name.length) == ".zbb")
        doc: Payload is gzip-compressed

  date:
    seq:
      - id: year
        type: u2
      - id: month
        type: u1
      - id: day
        type: u1

  file_body:
    params:
      - id: name
        type: str
      - id: is_compressed
        type: bool
    seq:
      - id: body
        size-eos: true
        type:
          switch-on: kind
          cases:
            'body_kind::clist': clist
            'body_kind::cust_info': cust_info
            'body_kind::counters': counters
            'body_kind::bb': bb
            'body_kind::text': text_blob
            _: raw_blob
    instances:
      is_bb:
        value: name.length >= 3 and name.substring(name.length - 3, name.length) == ".bb"
      kind:
        value: >-
          is_compressed ? body_kind::raw :
          name == "clist.pkg" ? body_kind::clist :
          name == "CUST_INFO.DAT" ? body_kind::cust_info :
          name == "counters.pkg" ? body_kind::counters :
          name == "file.pkg" ? body_kind::text :
          is_bb ? body_kind::bb :
          body_kind::raw
    enums:
      body_kind:
        0: raw
        1: clist
        2: cust_info
        3: counters
        4: bb
        5: text

  raw_blob:
    seq:
      - id: data
        size-eos: true

  text_blob:
    doc: Plain text (file.pkg / file.pkg.txt)
    seq:
      - id: text
        type: str
        size-eos: true
        encoding: UTF-8

  # ---- clist.pkg -------------------------------------------------------
  clist:
    seq:
      - id: files
        type: clist_entry
        repeat: eos

  clist_entry:
    doc: |
      52-byte item. The list names every file the iLO stores, including
      files that are not part of this log.
    seq:
      - id: magic
        contents: [0x01, 0x34, 0x00, 0x00]
      - id: padding1
        contents: [0, 0]
      - id: flags
        type: u2
      - id: padding2
        size: 12
      - id: name
        type: str
        size: 32
        terminator: 0

  # ---- counters.pkg ----------------------------------------------------
  counters:
    seq:
      - id: magic
        contents: [0x05, 0x00, 0x00, 0x00]
      - id: padding
        size: 28
      - id: counter
        type: counter_item
        repeat: expr
        repeat-expr: 6

  counter_item:
    seq:
      - id: id
        type: u2
      - id: unknown
        type: u2
      - id: bits
        size: 2
      - id: padding1
        size: 6
      - id: value
        type: u4
      - id: padding2
        size: 4
      - id: name
        type: str
        size: 64
        terminator: 0

  # ---- CUST_INFO.DAT ---------------------------------------------------
  cust_info:
    doc: 823 bytes of zero-padded text fields; all zero when no data was entered
    seq:
      - id: hp_support_case_number
        type: str
        size: 15
        terminator: 0
      - id: contact_name
        type: str
        size: 256
        terminator: 0
      - id: phone_number
        type: str
        size: 40
        terminator: 0
      - id: email
        type: str
        size: 256
        terminator: 0
      - id: company_name
        type: str
        size: 256
        terminator: 0

  # ---- decompressed *.bb (from *.zbb) ----------------------------------
  bb:
    doc: |
      Decompressed .zbb payload.
    seq:
      - id: item
        type: u4

  # ---- decompressed bcert.pkg (-> bcert.pkg.xml) -----------------------
  bcert_xml:
    seq:
      - id: xml
        type: str
        size-eos: true
        encoding: UTF-8
