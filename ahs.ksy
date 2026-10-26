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

seq:
  - id: files
    type: file
    repeat: eos

types:
  file:
    seq:
      - id: magic
        contents: 'ABJR'
      - id: pad1
        size: 4
      - id: size
        type: u4
        doc: Size of the (possibly compressed) payload in bytes
      - id: pad2
        size: 4
      - id: bits
        size: 4
        doc: Unknown flag bytes
      - id: name
        type: str
        size: 32
        terminator: 0
        doc: Zero-terminated file name in a fixed 32-byte field
      - id: large
        size: 60
        doc: Unknown 60-byte block
      - id: checksum
        type: u4
        doc: |
          Internal checksum of the decompressed data (algorithm not
          determined; the original script tries FNV32 variants, Fletcher32,
          CRC32 and Adler32 for comparison)
      - id: data
        size: size
        type: file_body(name, is_compressed)
    instances:
      is_compressed:
        value: >-
          name == "bcert.pkg" or
          (name.length >= 4 and name.substring(name.length - 4, name.length) == ".zbb")
        doc: Payload is gzip-compressed

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
    seq:
      - id: magic
        contents: [0x01, 0x34, 0x00, 0x00]
      - id: padding1
        contents: [0, 0]
      - id: bits
        size: 2
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
    seq:
      - id: hp_support_case_number
        type: strz
        size: 15
      - id: contact_name
        type: strz
        size: 256
      - id: phone_number
        type: strz
        size: 40
      - id: email
        type: strz
        size: 256
      - id: company_name
        type: strz
        size: 256

  # ---- decompressed *.bb (from *.zbb) ----------------------------------
  bb:
    doc: |
      Decompressed .zbb payload. The original script only reads a single
      uint32 from it (the rest is left as an opaque blob).
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
