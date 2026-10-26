meta:
  id: ahsbb
  title: HPE Active Health System Log Black Box file
  file-extension: bb
  license: GPL-3.0-or-later
  encoding: UTF-8
  endian: le

doc: |
  HPE Active Health System is an application running on Integrated Lights-Out
  Board Management Controller of ProLiant and Apollo servers starting from
  Generation 8.

  Decompressed *.zbb black-box file. Two kinds of files exist:

  * ilo_boot_support.bb / sys_boot_support.bb: schema dictionaries made only of
    fixed-size definition records (service names, struct names, field names,
    field types and sizes).
  * numbered files (e.g. 0000206-2025-12-01.bb): data records. The record names
    and payload sizes come from the dictionaries.

  There are no fixed magic numbers. Every record starts with a flag byte
  ("kind") that tells which optional header fields follow:

    0x80  definition record (dictionary files). 0x84/0x88/0x8c = 96 bytes,
          0x86/0x8e/0x92/0xa2 = 44 bytes (kind and service byte included)
    0x40  1-byte instance number
    0x20  4-byte Unix timestamp (UTC seconds)
    0x04  1-byte l1f (level-1 field)
    0x02  2-byte xflags before class / code (0, except 0x0100 on seven
          class 1 code 0x14 records; no extra byte follows in data records)
    order: [xflags u2] class u1, code u1, [l1f] [instance]
           [tick u4], u2 payload length, payload

  Terminology comes from the iLO 5 firmware (module blackbox.elf, src/blackbox.c,
  decoder "bb fview"): a record is identified by a Class (this file's service
  id) and a Code (struct id), optionally refined by field levels l1f/l2f/l3f
  and an instance number. Bit meanings of the flag byte confirmed in the
  decoder: 0x80 descriptor, 0x40 instance, 0x20 tick, 0x04 l1f present,
  0x02 xflags u2 present. In the firmware decoder xflags bits 0x100/0x200 mean
  an l2f/l3f byte; the data files here have no such byte, so data records
  do not parse it.
  Bits 0x08 and 0x10 are not tested by the decoder; the writer sets 0x08
  in blackbox_log() and 0x48 in blackbox_log_instance().

  Two wrappers start with 0x46: kind 0x46 + service 01 (n46) and 0x46 +
  service 03 (w46); they carry their length at a different offset.

  Payload types are known for the records listed in the "payload_type" switch,
  everything else is exposed as raw bytes.

seq:
  - id: records
    type: record
    repeat: eos

types:
  record:
    seq:
      - id: body
        type:
          switch-on: family
          cases:
            'family::data': data_record
            'family::def96': def96
            'family::def44': def44
            'family::n46': n46_record
            'family::w46': w46_record
    instances:
      k:
        pos: _io.pos
        type: u1
      s:
        pos: _io.pos + 1
        type: u1
      family:
        value: >-
          k >= 0x80 ? ((k == 0x84 or k == 0x88 or k == 0x8c) ? 1 : 2) :
          ((k == 0x46 and s == 1) ? 3 : ((k == 0x46 and s == 3) ? 4 : 0))
        enum: family
    enums:
      family:
        0: data
        1: def96
        2: def44
        3: n46
        4: w46

  def96:
    doc: |
      Dictionary record of 96 bytes (Descriptor). kind 0x88 = class name,
      0x84 = code name, 0x8c = field name.
    seq:
      - id: kind
        type: u1
      - id: class_id
        type: u1
      - id: code
        type: u1
      - id: index
        type: u1
      - id: field_type
        type: u1
      - id: size
        type: u1
      - id: reserved
        size: 2
      - id: name
        type: strz
        size: 88

  def44:
    doc: |
      Dictionary record of 44 bytes (xDescriptor). By the firmware strings:
      0x86 = code, 0x8e = level-1 field, 0x92 = level-2 field,
      0xa2 = level-3 field (confirmed by the l2f/l3f bytes in the data and
      the firmware's "Set Level 2/3 Field xDescriptor" messages).
    seq:
      - id: kind
        type: u1
      - id: class_id
        type: u1
      - id: code
        type: u1
      - id: l1f
        type: u1
        doc: level-1 field index (0 for the 0x86 code record itself)
      - id: l2f
        type: u1
        doc: level-2 field index (kinds 0x92 and 0xa2)
      - id: l3f
        type: u1
        doc: level-3 field index (kind 0xa2)
      - id: reserved
        size: 2
      - id: field_type
        type: u1
        doc: 0x24 counter, 0x25 hex, 0x34/0x35 signed, 0x64 raw, 0x15 string
      - id: size
        type: u1
        doc: field (or struct) size in bytes
      - id: reserved2
        size: 2
      - id: name
        type: strz
        size: 32

  data_record:
    seq:
      - id: kind
        type: u1
      - id: xflags
        type: u2
        if: (kind & 0x02) != 0
      - id: class_id
        type: u1
      - id: code
        type: u1
      - id: l1f
        type: u1
        if: (kind & 0x04) != 0
        doc: level-1 field index (blackbox_log_field style records)
      - id: instance
        type: u1
        if: (kind & 0x40) != 0
      - id: timestamp
        type: u4
        if: (kind & 0x20) != 0
        doc: Unix time, UTC
      - id: len_payload
        type: u2
      - id: payload
        size: len_payload
        type:
          switch-on: payload_type
          cases:
            0x0103: heartbeat
            0x0303: memory_state
            0x0c06: platdef_c06
            0x0c07: platdef_c07
            0x0d04: bios_variable
            0x0d0c: bios_event
            0x1101: evt_record
            0x3901: rest_text
            0x4c01: rde_text
            0x4d01: redfish_json
            0x0202: dict_gpi_scan_chain
            0x0203: dict_gpo_scan_chain
            0x020f: dict_peci_g8_stats
            0x0c04: dict_platdef_sensor_state
            0x0c08: dict_platdef_redundancy_state
            0x0c3c: dict_platdef_health_panel
            0x1001: dict_vsp_information
            0x13f0: dict_status_code_information
            0x1504: dict_embedded_media_metrics
            0x1701: dict_dvi_information
            0x1901: dict_statistic_fields
            0x1a01: dict_secmgr_statistics
            0x1d01: dict_idle_seconds_in_the_last_minute
            0x1f01: dict_ilo_kbbx_cpu
            0x1f04: dict_ilo_kbbx_network
            0x1f05: dict_ilo_kbbx_interrupt
            0x4301: dict_i2c_engine_statistics
            0x4302: dict_i2c_overall_statistics
            0x4303: dict_i2c_cobourg_statistics
            0x4304: dict_i2c_sna_statistics
            0x4505: dict_transmit_statistics
            0x4506: dict_receive_statistics
            0x4801: dict_state_count
            _: raw_payload
    instances:
      class_:
        value: class_id
        enum: bb_class
      payload_key:
        value: (class_id << 8) | code
      size_matches:
        value: >-
          payload_key == 0x0103 ? len_payload ==8 : payload_key == 0x0202 ? len_payload ==8 : payload_key == 0x0203 ? len_payload ==64 : payload_key == 0x020f ? len_payload ==88 : payload_key == 0x0303 ? len_payload ==18 : payload_key == 0x0c04 ? len_payload ==54 : payload_key == 0x0c06 ? len_payload >=2 : payload_key == 0x0c07 ? len_payload ==8 : payload_key == 0x0c08 ? len_payload ==6 : payload_key == 0x0c3c ? len_payload ==6 : payload_key == 0x0d0c ? len_payload >=18 : payload_key == 0x1001 ? len_payload ==32 : payload_key == 0x1101 ? len_payload ==52 : payload_key == 0x13f0 ? len_payload ==8 : payload_key == 0x1504 ? len_payload ==332 : payload_key == 0x1701 ? len_payload ==28 : payload_key == 0x1901 ? len_payload ==192 : payload_key == 0x1a01 ? len_payload ==2 : payload_key == 0x1d01 ? len_payload ==1 : payload_key == 0x1f01 ? len_payload ==16 : payload_key == 0x1f04 ? len_payload ==388 : payload_key == 0x1f05 ? len_payload ==256 : payload_key == 0x4301 ? len_payload ==372 : payload_key == 0x4302 ? len_payload ==40 : payload_key == 0x4303 ? len_payload ==76 : payload_key == 0x4304 ? len_payload ==8 : payload_key == 0x4505 ? len_payload ==44 : payload_key == 0x4506 ? len_payload ==48 : payload_key == 0x4801 ? len_payload ==20 : true
        doc: |
          Typed payload structs have a fixed size that comes from the
          dictionary of one firmware generation (iLO 5). Newer firmware
          (iLO 7) can change a size, then the payload stays raw.
      payload_type:
        value: 'size_matches ? payload_key : 0'

  n46_record:
    seq:
      - id: kind
        type: u1
      - id: class_id
        type: u1
      - id: b2
        type: u1
      - id: b3
        type: u1
      - id: flags
        type: u1
      - id: var
        type: u1
      - id: index
        type: u2
      - id: len_payload
        type: u2
      - id: payload
        size: len_payload

  w46_record:
    seq:
      - id: kind
        type: u1
      - id: class_id
        type: u1
      - id: b2
        type: u1
      - id: b3
        type: u1
      - id: flags
        type: u1
      - id: var
        type: u1
      - id: item_id
        type: u2
      - id: sub
        type: u1
      - id: len_payload
        type: u2
      - id: payload
        size: len_payload

  raw_payload:
    seq:
      - id: data
        size-eos: true

  text_payload:
    seq:
      - id: text
        type: strz
        size-eos: true

  rest_text:
    seq:
      - id: text
        type: strz
        size-eos: true

  rde_text:
    seq:
      - id: text
        type: strz
        size-eos: true

  redfish_json:
    doc: Redfish resource snapshot as JSON text
    seq:
      - id: text
        type: str
        size-eos: true

  heartbeat:
    doc: Service 01 struct 03, one per ~5 s; gives a monotonic clock
    seq:
      - id: unix_time
        type: u4
      - id: reserved
        type: u4

  memory_state:
    seq:
      - id: item_id
        type: u2
      - id: unix_time
        type: u4
      - id: reserved
        type: u4
      - id: values
        type: u2
        repeat: expr
        repeat-expr: 4

  platdef_c06:
    seq:
      - id: record_id
        type: u2
      - id: rest
        size-eos: true

  platdef_c07:
    seq:
      - id: values
        type: u2
        repeat: expr
        repeat-expr: 4

  bios_variable:
    doc: UEFI/BIOS variable snapshot (CQH/CQS prefix) name + raw value
    seq:
      - id: name
        type: str
        terminator: 0
        eos-error: false
      - id: value
        size-eos: true

  bios_event:
    doc: Text event with date string and message
    seq:
      - id: header
        size: 18
      - id: date_text
        type: str
        terminator: 0
        eos-error: false
      - id: code_text
        type: str
        terminator: 0
        eos-error: false
      - id: message
        type: str
        terminator: 0
        eos-error: false
      - id: tail
        size-eos: true

  evt_record:
    seq:
      - id: event_id
        type: u4
      - id: name
        type: str
        size: 32
        terminator: 0
      - id: args
        type: u4
        repeat: expr
        repeat-expr: 4

  dict_gpi_scan_chain:
    doc: "Dictionary struct 02/02 'GPI scan chain' (8 bytes), field layout from the boot_support dictionary"
    seq:
      - id: serial_data_in_bytes_0_3
        type: u4
        doc: "Serial Data In (bytes 0-3)"
      - id: serial_data_in_bytes_4_7
        type: u4
        doc: "Serial Data In (bytes 4-7)"

  dict_gpo_scan_chain:
    doc: "Dictionary struct 02/03 'GPO scan chain' (64 bytes), field layout from the boot_support dictionary"
    seq:
      - id: serialout_bytes_0_3
        type: u4
        doc: "SerialOut (bytes 0-3)"
      - id: serialout_bytes_4_7
        type: u4
        doc: "SerialOut (bytes 4-7)"
      - id: serialout_bytes_8_11
        type: u4
        doc: "SerialOut (bytes 8-11)"
      - id: serialout_bytes_12_15
        type: u4
        doc: "SerialOut (bytes 12-15)"
      - id: serialin_irq_bytes_0_3
        type: u4
        doc: "SerialIn IRQ (bytes 0-3)"
      - id: serialin_irq_bytes_4_7
        type: u4
        doc: "SerialIn IRQ (bytes 4-7)"
      - id: serialin_irq_bytes_8_11
        type: u4
        doc: "SerialIn IRQ (bytes 8-11)"
      - id: serialin_irq_bytes_12_15
        type: u4
        doc: "SerialIn IRQ (bytes 12-15)"
      - id: serialout_ownership_bytes_0_3
        type: u4
        doc: "SerialOut Ownership (bytes 0-3)"
      - id: serialout_ownership_bts_4_7
        type: u4
        doc: "SerialOut Ownership (bts 4-7)"
      - id: serialout_ownership_bts_8_11
        type: u4
        doc: "SerialOut Ownership (bts 8-11)"
      - id: serialout_ownership_bts_12_15
        type: u4
        doc: "SerialOut Ownership (bts 12-15)"
      - id: serialout_rset_domain_bts_0_3
        type: u4
        doc: "SerialOut Rset Domain (bts 0-3)"
      - id: serialout_rset_domain_bts_4_7
        type: u4
        doc: "SerialOut Rset Domain (bts 4-7)"
      - id: serialout_rset_domain_b_8_11
        type: u4
        doc: "SerialOut Rset Domain (b 8-11)"
      - id: serialout_rset_domain_b_12_15
        type: u4
        doc: "SerialOut Rset Domain (b 12-15)"

  dict_peci_g8_stats:
    doc: "Dictionary struct 02/0f 'PECI G8 stats' (88 bytes), field layout from the boot_support dictionary"
    seq:
      - id: cstate_80
        type: u4
        doc: "cstate_80"
      - id: cstate_81
        type: u4
        doc: "cstate_81"
      - id: smbus_init_80
        type: u4
        doc: "smbus_init_80"
      - id: smbus_init_81
        type: u4
        doc: "smbus_init_81"
      - id: smbus_init_fail
        type: u4
        doc: "smbus_init_fail"
      - id: smbus_init_ok
        type: u4
        doc: "smbus_init_ok"
      - id: smbus_start_80
        type: u4
        doc: "smbus_start_80"
      - id: smbus_start_81
        type: u4
        doc: "smbus_start_81"
      - id: smbus_start_fail
        type: u4
        doc: "smbus_start_fail"
      - id: smbus_start_ok
        type: u4
        doc: "smbus_start_ok"
      - id: smbus_harvest_80
        type: u4
        doc: "smbus_harvest_80"
      - id: smbus_harvest_81
        type: u4
        doc: "smbus_harvest_81"
      - id: smbus_harvest_82
        type: u4
        doc: "smbus_harvest_82"
      - id: smbus_harvest_fail
        type: u4
        doc: "smbus_harvest_fail"
      - id: smbus_harvest_ok
        type: u4
        doc: "smbus_harvest_ok"
      - id: smbus_retries_max
        type: u4
        doc: "smbus_retries_max"
      - id: smbus_spd_read
        type: u4
        doc: "smbus_spd_read"
      - id: smbus_spd_read_retries
        type: u4
        doc: "smbus_spd_read_retries"
      - id: smbus_spd_read_errors
        type: u4
        doc: "smbus_spd_read_errors"
      - id: smbus_spd_write
        type: u4
        doc: "smbus_spd_write"
      - id: smbus_spd_write_retries
        type: u4
        doc: "smbus_spd_write_retries"
      - id: smbus_spd_write_errors
        type: u4
        doc: "smbus_spd_write_errors"

  dict_platdef_sensor_state:
    doc: "Dictionary struct 0c/04 'PlatDef Sensor State' (54 bytes), field layout from the boot_support dictionary"
    seq:
      - id: record_id
        type: u2
        doc: "Record ID"
      - id: state
        type: u1
        doc: "State"
      - id: initialized
        type: u1
        doc: "Initialized?"
      - id: error
        type: s4
        doc: "Error"
      - id: sensor_data_reading
        type: s4
        doc: "Sensor Data (reading)"
      - id: fail_iml_event_id
        type: u4
        doc: "Fail IML Event ID"
      - id: degrade_iml_entry_id
        type: u4
        doc: "Degrade IML Entry ID"
      - id: eh_rctn_iml_entry_id
        type: u4
        doc: "EH Rctn IML Entry ID"
      - id: active_reactions
        type: u2
        doc: "Active Reactions"
      - id: debug_monitor
        type: u1
        doc: "DEBUG Monitor"
      - id: debug_detect
        type: u1
        doc: "DEBUG Detect"
      - id: active_reactions_count
        size: 16
        doc: "Active Reactions Count"
      - id: evaluate_redundancy
        type: u1
        doc: "Evaluate Redundancy"
      - id: positive_redundancy
        type: u1
        doc: "Positive Redundancy"
      - id: group_redundant
        type: u1
        doc: "Group Redundant"
      - id: container_record
        type: u1
        doc: "Container Record"
      - id: monitor
        type: u1
        doc: "Monitor"
      - id: detect
        type: u1
        doc: "Detect"
      - id: monitor_count
        type: u1
        doc: "Monitor Count"
      - id: failure_type
        type: u1
        doc: "Failure Type"
      - id: optional_desc_param
        type: u2
        doc: "Optional Desc Param"

  dict_platdef_redundancy_state:
    doc: "Dictionary struct 0c/08 'PlatDef Redundancy State' (6 bytes), field layout from the boot_support dictionary"
    seq:
      - id: record_id
        type: u2
        doc: "Record ID"
      - id: state
        type: u1
        doc: "State"
      - id: status
        type: u1
        doc: "Status"
      - id: active_reactions
        type: u2
        doc: "Active Reactions"

  dict_platdef_health_panel:
    doc: "Dictionary struct 0c/3c 'PlatDef Health Panel' (6 bytes), field layout from the boot_support dictionary"
    seq:
      - id: fan_status
        type: u1
        doc: "Fan Status"
      - id: psu_status
        type: u1
        doc: "PSU Status"
      - id: storage_status
        type: u1
        doc: "Storage Status"
      - id: network_status
        type: u1
        doc: "Network Status"
      - id: cpu_status
        type: u1
        doc: "CPU Status"
      - id: memory_status
        type: u1
        doc: "Memory Status"

  dict_vsp_information:
    doc: "Dictionary struct 10/01 'VSP Information' (32 bytes), field layout from the boot_support dictionary"
    seq:
      - id: vsp_state
        type: u4
        doc: "VSP state"
      - id: vuart_output_bytes_count
        type: u4
        doc: "VUART output bytes count"
      - id: vuart_input_bytes_count
        type: u4
        doc: "VUART input bytes count"
      - id: flow_control_kick_count
        type: u4
        doc: "Flow control kick count"
      - id: network_output_bytes_count
        type: u4
        doc: "Network output bytes count"
      - id: network_input_bytes_count
        type: u4
        doc: "Network input bytes count"
      - id: vuart_interrupt_count
        type: u4
        doc: "VUART interrupt count"
      - id: vuart_status_register
        type: u4
        doc: "VUART status register"

  dict_status_code_information:
    doc: "Dictionary struct 13/f0 'Status Code Information' (8 bytes), field layout from the boot_support dictionary"
    seq:
      - id: status_code_number
        type: u4
        doc: "Status Code Number"
      - id: status_code_type
        type: u4
        doc: "Status Code Type"

  dict_embedded_media_metrics:
    doc: "Dictionary struct 15/04 'Embedded Media Metrics' (332 bytes), field layout from the boot_support dictionary"
    seq:
      - id: f_1_sector_reads
        type: u4
        doc: "1 sector reads"
      - id: f_2_sector_reads
        type: u4
        doc: "2 sector reads"
      - id: f_3_4_sector_reads
        type: u4
        doc: "3-4 sector reads"
      - id: f_5_8_sector_reads
        type: u4
        doc: "5-8 sector reads"
      - id: f_9_16_sector_reads
        type: u4
        doc: "9-16 sector reads"
      - id: f_17_32_sector_reads
        type: u4
        doc: "17-32 sector reads"
      - id: f_32_sector_reads
        type: u4
        doc: ">32 sector reads"
      - id: f_0_499_us_reads
        type: u4
        doc: "0-499 us reads"
      - id: f_500_999_us_reads
        type: u4
        doc: "500-999 us reads"
      - id: f_1000_1499_us_reads
        type: u4
        doc: "1000-1499 us reads"
      - id: f_1500_1999_us_reads
        type: u4
        doc: "1500-1999 us reads"
      - id: f_2000_2499_us_reads
        type: u4
        doc: "2000-2499 us reads"
      - id: f_2500_2999_us_reads
        type: u4
        doc: "2500-2999 us reads"
      - id: f_3000_3499_us_reads
        type: u4
        doc: "3000-3499 us reads"
      - id: f_3500_3999_us_reads
        type: u4
        doc: "3500-3999 us reads"
      - id: f_4000_4499_us_reads
        type: u4
        doc: "4000-4499 us reads"
      - id: f_4500_4999_us_reads
        type: u4
        doc: "4500-4999 us reads"
      - id: f_5000_5499_us_reads
        type: u4
        doc: "5000-5499 us reads"
      - id: f_5500_5999_us_reads
        type: u4
        doc: "5500-5999 us reads"
      - id: f_6000_6499_us_reads
        type: u4
        doc: "6000-6499 us reads"
      - id: f_6500_6999_us_reads
        type: u4
        doc: "6500-6999 us reads"
      - id: f_7000_7499_us_reads
        type: u4
        doc: "7000-7499 us reads"
      - id: f_7500_7999_us_reads
        type: u4
        doc: "7500-7999 us reads"
      - id: f_8000_8499_us_reads
        type: u4
        doc: "8000-8499 us reads"
      - id: f_8500_8999_us_reads
        type: u4
        doc: "8500-8999 us reads"
      - id: f_9000_9499_us_reads
        type: u4
        doc: "9000-9499 us reads"
      - id: f_9500_9999_us_reads
        type: u4
        doc: "9500-9999 us reads"
      - id: f_10000_10499_us_reads
        type: u4
        doc: "10000-10499 us reads"
      - id: f_10500_10999_us_reads
        type: u4
        doc: "10500-10999 us reads"
      - id: f_11000_11499_us_reads
        type: u4
        doc: "11000-11499 us reads"
      - id: f_11500_us_reads
        type: u4
        doc: ">11500 us reads"
      - id: read_error_timeout
        type: u4
        doc: "Read error TIMEOUT"
      - id: read_error_media_not_present
        type: u4
        doc: "Read error MEDIA_NOT_PRESENT"
      - id: read_error_media_error
        type: u4
        doc: "Read error MEDIA_ERROR"
      - id: read_error_post_buffer_fail
        type: u4
        doc: "Read error POST_BUFFER_FAIL"
      - id: read_error_aborted
        type: u4
        doc: "Read error ABORTED"
      - id: read_error_exception
        type: u4
        doc: "Read error EXCEPTION"
      - id: read_error_unexpected
        type: u4
        doc: "Read error UNEXPECTED"
      - id: read_error_stack_exception
        type: u4
        doc: "Read error STACK_EXCEPTION"
      - id: first_read_error
        type: u4
        doc: "first read error"
      - id: f_1_sector_writes
        type: u4
        doc: "1 sector writes"
      - id: f_2_sector_writes
        type: u4
        doc: "2 sector writes"
      - id: f_3_4_sector_writes
        type: u4
        doc: "3-4 sector writes"
      - id: f_5_8_sector_writes
        type: u4
        doc: "5-8 sector writes"
      - id: f_9_16_sector_writes
        type: u4
        doc: "9-16 sector writes"
      - id: f_17_32_sector_writes
        type: u4
        doc: "17-32 sector writes"
      - id: f_32_sector_writes
        type: u4
        doc: ">32 sector writes"
      - id: f_0_499_us_writes
        type: u4
        doc: "0-499 us writes"
      - id: f_500_999_us_writes
        type: u4
        doc: "500-999 us writes"
      - id: f_1000_1499_us_writes
        type: u4
        doc: "1000-1499 us writes"
      - id: f_1500_1999_us_writes
        type: u4
        doc: "1500-1999 us writes"
      - id: f_2000_2499_us_writes
        type: u4
        doc: "2000-2499 us writes"
      - id: f_2500_2999_us_writes
        type: u4
        doc: "2500-2999 us writes"
      - id: f_3000_3499_us_writes
        type: u4
        doc: "3000-3499 us writes"
      - id: f_3500_3999_us_writes
        type: u4
        doc: "3500-3999 us writes"
      - id: f_4000_4499_us_writes
        type: u4
        doc: "4000-4499 us writes"
      - id: f_4500_4999_us_writes
        type: u4
        doc: "4500-4999 us writes"
      - id: f_5000_5499_us_writes
        type: u4
        doc: "5000-5499 us writes"
      - id: f_5500_5999_us_writes
        type: u4
        doc: "5500-5999 us writes"
      - id: f_6000_6499_us_writes
        type: u4
        doc: "6000-6499 us writes"
      - id: f_6500_6999_us_writes
        type: u4
        doc: "6500-6999 us writes"
      - id: f_7000_7499_us_writes
        type: u4
        doc: "7000-7499 us writes"
      - id: f_7500_7999_us_writes
        type: u4
        doc: "7500-7999 us writes"
      - id: f_8000_8499_us_writes
        type: u4
        doc: "8000-8499 us writes"
      - id: f_8500_8999_us_writes
        type: u4
        doc: "8500-8999 us writes"
      - id: f_9000_9499_us_writes
        type: u4
        doc: "9000-9499 us writes"
      - id: f_9500_9999_us_writes
        type: u4
        doc: "9500-9999 us writes"
      - id: f_10000_10499_us_writes
        type: u4
        doc: "10000-10499 us writes"
      - id: f_10500_10999_us_writes
        type: u4
        doc: "10500-10999 us writes"
      - id: f_11000_11499_us_writes
        type: u4
        doc: "11000-11499 us writes"
      - id: f_11500_us_writes
        type: u4
        doc: ">11500 us writes"
      - id: write_error_timeout
        type: u4
        doc: "Write error TIMEOUT"
      - id: write_error_media_not_present
        type: u4
        doc: "Write error MEDIA_NOT_PRESENT"
      - id: write_error_media_error
        type: u4
        doc: "Write error MEDIA_ERROR"
      - id: write_error_post_buffer_fail
        type: u4
        doc: "Write error POST_BUFFER_FAIL"
      - id: write_error_aborted
        type: u4
        doc: "Write error ABORTED"
      - id: write_error_exception
        type: u4
        doc: "Write error EXCEPTION"
      - id: write_error_unexpected
        type: u4
        doc: "Write error UNEXPECTED"
      - id: write_error_stack_exception
        type: u4
        doc: "Write error STACK_EXCEPTION"
      - id: first_write_error
        type: u4
        doc: "first write error"
      - id: interrupt_count
        type: u4
        doc: "interrupt count"
      - id: media_0_write_count
        type: u4
        doc: "Media 0 write count"
      - id: media_1_write_count
        type: u4
        doc: "Media 1 write count"

  dict_dvi_information:
    doc: "Dictionary struct 17/01 'DVI Information' (28 bytes), field layout from the boot_support dictionary"
    seq:
      - id: client_connected
        type: u4
        doc: "Client Connected"
      - id: encryption_type
        type: u4
        doc: "Encryption Type"
      - id: total_buffers_sent
        type: u4
        doc: "Total Buffers Sent"
      - id: total_send_faults
        type: u4
        doc: "Total Send Faults"
      - id: irc_commands_sent
        type: u4
        doc: "IRC Commands Sent"
      - id: dvc_commands_received
        type: u4
        doc: "DVC Commands Received"
      - id: irc_commands_received
        type: u4
        doc: "IRC Commands Received"

  dict_statistic_fields:
    doc: "Dictionary struct 19/01 'Statistic Fields' (192 bytes), field layout from the boot_support dictionary"
    seq:
      - id: interface
        type: u8
        doc: "Interface"
      - id: bytes_received
        type: u8
        doc: "Bytes received"
      - id: packets_received
        type: u8
        doc: "Packets received"
      - id: received_packets_dropped
        type: u8
        doc: "Received packets dropped"
      - id: broadcast_packets_received
        type: u8
        doc: "Broadcast packets received"
      - id: multicast_packets_received
        type: u8
        doc: "Multicast packets received"
      - id: zero_length_packets_received
        type: u8
        doc: "Zero length packets received"
      - id: receive_packet_framing_errors
        type: u8
        doc: "Receive packet framing errors"
      - id: receive_packet_crc_errors
        type: u8
        doc: "Receive packet CRC errors"
      - id: receive_packet_length_errors
        type: u8
        doc: "Receive packet length errors"
      - id: receive_packet_overrun
        type: u8
        doc: "Receive packet overrun"
      - id: receive_packet_bad_symbols
        type: u8
        doc: "Receive packet bad symbols"
      - id: received_packet_carrier_extention_errors
        type: u8
        doc: "Received packet carrier extention errors"
      - id: no_rx_descriptors
        type: u8
        doc: "No RX descriptors"
      - id: receive_dma_length_error
        type: u8
        doc: "Receive DMA length error"
      - id: bytes_transmitted
        type: u8
        doc: "Bytes transmitted"
      - id: packets_transmitted
        type: u8
        doc: "Packets transmitted"
      - id: transmit_packets_dropped
        type: u8
        doc: "Transmit packets dropped"
      - id: broadcast_packets_transmitted
        type: u8
        doc: "Broadcast packets transmitted"
      - id: multicast_packets_transmitted
        type: u8
        doc: "Multicast packets transmitted"
      - id: transmit_packet_collisions
        type: u8
        doc: "Transmit packet collisions"
      - id: transmit_packet_late_collisions
        type: u8
        doc: "Transmit packet late collisions"
      - id: transmit_packet_lost_carrier
        type: u8
        doc: "Transmit packet lost carrier"
      - id: no_tx_descriptors
        type: u8
        doc: "No TX descriptors"

  dict_secmgr_statistics:
    doc: "Dictionary struct 1a/01 'secmgr statistics' (2 bytes), field layout from the boot_support dictionary"
    seq:
      - id: active_sessions
        type: u1
        doc: "active sessions"
      - id: settings
        type: u1
        doc: "settings"

  dict_idle_seconds_in_the_last_minute:
    doc: "Dictionary struct 1d/01 'Idle seconds in the last minute' (1 bytes), field layout from the boot_support dictionary"
    seq:
      - id: idle_seconds_in_the_last_minute
        type: u1
        doc: "Idle seconds in the last minute"

  dict_ilo_kbbx_cpu:
    doc: "Dictionary struct 1f/01 'iLO KBBX CPU' (16 bytes), field layout from the boot_support dictionary"
    seq:
      - id: up_time
        type: u8
        doc: "Up time"
      - id: sleep_time
        type: u8
        doc: "Sleep time"

  dict_ilo_kbbx_network:
    doc: "Dictionary struct 1f/04 'iLO KBBX Network' (388 bytes), field layout from the boot_support dictionary"
    seq:
      - id: max_sockets
        type: u4
        doc: "Max sockets"
      - id: open_sockets
        type: u4
        doc: "Open sockets"
      - id: tcp_open_sockets
        type: u4
        doc: "TCP open sockets"
      - id: counted_sockets
        type: u4
        doc: "Counted sockets"
      - id: counted_tcp_sockets
        type: u4
        doc: "Counted TCP sockets"
      - id: counted_udp_sockets
        type: u4
        doc: "Counted UDP sockets"
      - id: counted_udp_proxy
        type: u4
        doc: "Counted UDP proxy"
      - id: counted_udp_proxy_max
        type: u4
        doc: "Counted UDP proxy max"
      - id: counted_udp_proxy_max_owner_0
        type: u4
        doc: "Counted UDP proxy max Owner 0"
      - id: counted_udp_proxy_max_owner_1
        type: u4
        doc: "Counted UDP proxy max Owner 1"
      - id: counted_udp_proxy_max_owner_2
        type: u4
        doc: "Counted UDP proxy max Owner 2"
      - id: counted_udp_proxy_max_owner_3
        type: u4
        doc: "Counted UDP proxy max Owner 3"
      - id: counted_udp_proxy_unread
        type: u4
        doc: "Counted UDP proxy unread"
      - id: counted_udp_proxy_unread_max
        type: u4
        doc: "Counted UDP proxy unread max"
      - id: counted_udp_proxy_unread_max_owner_0
        type: u4
        doc: "Counted UDP proxy unread max Owner 0"
      - id: counted_udp_proxy_unread_max_owner_1
        type: u4
        doc: "Counted UDP proxy unread max Owner 1"
      - id: counted_udp_proxy_unread_max_owner_2
        type: u4
        doc: "Counted UDP proxy unread max Owner 2"
      - id: counted_udp_proxy_unread_max_owner_3
        type: u4
        doc: "Counted UDP proxy unread max Owner 3"
      - id: counted_tcp_proxy
        type: u4
        doc: "Counted TCP proxy"
      - id: counted_tcp_proxy_max
        type: u4
        doc: "Counted TCP proxy max"
      - id: counted_tcp_proxy_max_owner_0
        type: u4
        doc: "Counted TCP proxy max Owner 0"
      - id: counted_tcp_proxy_max_owner_1
        type: u4
        doc: "Counted TCP proxy max Owner 1"
      - id: counted_tcp_proxy_max_owner_2
        type: u4
        doc: "Counted TCP proxy max Owner 2"
      - id: counted_tcp_proxy_max_owner_3
        type: u4
        doc: "Counted TCP proxy max Owner 3"
      - id: counted_tcp_proxy_unread
        type: u4
        doc: "Counted TCP proxy unread"
      - id: counted_tcp_proxy_unread_max
        type: u4
        doc: "Counted TCP proxy unread max"
      - id: counted_tcp_proxy_unread_max_owner_0
        type: u4
        doc: "Counted TCP proxy unread max Owner 0"
      - id: counted_tcp_proxy_unread_max_owner_1
        type: u4
        doc: "Counted TCP proxy unread max Owner 1"
      - id: counted_tcp_proxy_unread_max_owner_2
        type: u4
        doc: "Counted TCP proxy unread max Owner 2"
      - id: counted_tcp_proxy_unread_max_owner_3
        type: u4
        doc: "Counted TCP proxy unread max Owner 3"
      - id: counted_proxy
        type: u4
        doc: "Counted proxy"
      - id: counted_proxy_max
        type: u4
        doc: "Counted proxy max"
      - id: counted_proxy_max_owner_0
        type: u4
        doc: "Counted proxy max Owner 0"
      - id: counted_proxy_max_owner_1
        type: u4
        doc: "Counted proxy max Owner 1"
      - id: counted_proxy_max_owner_2
        type: u4
        doc: "Counted proxy max Owner 2"
      - id: counted_proxy_max_owner_3
        type: u4
        doc: "Counted proxy max Owner 3"
      - id: memory_pool0_size
        type: u4
        doc: "Memory pool0 size"
      - id: memory_pool0_total
        type: u4
        doc: "Memory pool0 total"
      - id: memory_pool0_free
        type: u4
        doc: "Memory pool0 free"
      - id: memory_pool1_size
        type: u4
        doc: "Memory pool1 size"
      - id: memory_pool1_total
        type: u4
        doc: "Memory pool1 total"
      - id: memory_pool1_free
        type: u4
        doc: "Memory pool1 free"
      - id: memory_pool2_size
        type: u4
        doc: "Memory pool2 size"
      - id: memory_pool2_total
        type: u4
        doc: "Memory pool2 total"
      - id: memory_pool2_free
        type: u4
        doc: "Memory pool2 free"
      - id: memory_pool3_size
        type: u4
        doc: "Memory pool3 size"
      - id: memory_pool3_total
        type: u4
        doc: "Memory pool3 total"
      - id: memory_pool3_free
        type: u4
        doc: "Memory pool3 free"
      - id: memory_pool4_size
        type: u4
        doc: "Memory pool4 size"
      - id: memory_pool4_total
        type: u4
        doc: "Memory pool4 total"
      - id: memory_pool4_free
        type: u4
        doc: "Memory pool4 free"
      - id: memory_pool5_size
        type: u4
        doc: "Memory pool5 size"
      - id: memory_pool5_total
        type: u4
        doc: "Memory pool5 total"
      - id: memory_pool5_free
        type: u4
        doc: "Memory pool5 free"
      - id: memory_pool6_size
        type: u4
        doc: "Memory pool6 size"
      - id: memory_pool6_total
        type: u4
        doc: "Memory pool6 total"
      - id: memory_pool6_free
        type: u4
        doc: "Memory pool6 free"
      - id: memory_pool7_size
        type: u4
        doc: "Memory pool7 size"
      - id: memory_pool7_total
        type: u4
        doc: "Memory pool7 total"
      - id: memory_pool7_free
        type: u4
        doc: "Memory pool7 free"
      - id: memory_pool8_size
        type: u4
        doc: "Memory pool8 size"
      - id: memory_pool8_total
        type: u4
        doc: "Memory pool8 total"
      - id: memory_pool8_free
        type: u4
        doc: "Memory pool8 free"
      - id: memory_pool9_size
        type: u4
        doc: "Memory pool9 size"
      - id: memory_pool9_total
        type: u4
        doc: "Memory pool9 total"
      - id: memory_pool9_free
        type: u4
        doc: "Memory pool9 free"
      - id: memory_poola_size
        type: u4
        doc: "Memory poola size"
      - id: memory_poola_total
        type: u4
        doc: "Memory poola total"
      - id: memory_poola_free
        type: u4
        doc: "Memory poola free"
      - id: memory_poolb_size
        type: u4
        doc: "Memory poolb size"
      - id: memory_poolb_total
        type: u4
        doc: "Memory poolb total"
      - id: memory_poolb_free
        type: u4
        doc: "Memory poolb free"
      - id: memory_poolc_size
        type: u4
        doc: "Memory poolc size"
      - id: memory_poolc_total
        type: u4
        doc: "Memory poolc total"
      - id: memory_poolc_free
        type: u4
        doc: "Memory poolc free"
      - id: memory_poold_size
        type: u4
        doc: "Memory poold size"
      - id: memory_poold_total
        type: u4
        doc: "Memory poold total"
      - id: memory_poold_free
        type: u4
        doc: "Memory poold free"
      - id: memory_poole_size
        type: u4
        doc: "Memory poole size"
      - id: memory_poole_total
        type: u4
        doc: "Memory poole total"
      - id: memory_poole_free
        type: u4
        doc: "Memory poole free"
      - id: memory_poolf_size
        type: u4
        doc: "Memory poolf size"
      - id: memory_poolf_total
        type: u4
        doc: "Memory poolf total"
      - id: memory_poolf_free
        type: u4
        doc: "Memory poolf free"
      - id: contexts_in_use
        type: u4
        doc: "Contexts in use"
      - id: contexts_max
        type: u4
        doc: "Contexts max"
      - id: as_count
        type: u4
        doc: "AS count"
      - id: as_count_max
        type: u4
        doc: "AS count max"
      - id: as_proxy_limit
        type: u4
        doc: "AS proxy limit"
      - id: link_changes
        type: u4
        doc: "Link changes"
      - id: dhcp_completions
        type: u4
        doc: "DHCP completions"
      - id: dhcp_renewals
        type: u4
        doc: "DHCP renewals"
      - id: dhcp_renew_fails
        type: u4
        doc: "DHCP renew fails"
      - id: client_calls
        type: u4
        doc: "Client calls"
      - id: socket_create_refusals
        type: u4
        doc: "Socket create refusals"
      - id: context_create_refusals
        type: u4
        doc: "Context create refusals"
      - id: malloc_failures
        type: u4
        doc: "Malloc failures"

  dict_ilo_kbbx_interrupt:
    doc: "Dictionary struct 1f/05 'iLO KBBX Interrupt' (256 bytes), field layout from the boot_support dictionary"
    seq:
      - id: timer0
        type: u4
        doc: "Timer0"
      - id: timer1
        type: u4
        doc: "Timer1"
      - id: a9_l2
        type: u4
        doc: "A9 L2"
      - id: a9_pmu
        type: u4
        doc: "A9 PMU"
      - id: ap_messaging
        type: u4
        doc: "AP Messaging"
      - id: unusedi5
        type: u4
        doc: "unusedI5"
      - id: ohci
        type: u4
        doc: "OHCI"
      - id: ehci
        type: u4
        doc: "EHCI"
      - id: fan
        type: u4
        doc: "Fan"
      - id: i2c
        type: u4
        doc: "I2C"
      - id: mac0
        type: u4
        doc: "MAC0"
      - id: mac1
        type: u4
        doc: "MAC1"
      - id: sgmii_phy_a
        type: u4
        doc: "SGMII PHY A"
      - id: sgmii_phy_b
        type: u4
        doc: "SGMII PHY B"
      - id: iop_display
        type: u4
        doc: "IOP Display"
      - id: dvc
        type: u4
        doc: "DVC"
      - id: can
        type: u4
        doc: "CAN"
      - id: uarta
        type: u4
        doc: "UARTA"
      - id: uartb
        type: u4
        doc: "UARTB"
      - id: uartc
        type: u4
        doc: "UARTC"
      - id: spi0
        type: u4
        doc: "SPI0"
      - id: spi1
        type: u4
        doc: "SPI1"
      - id: spi2
        type: u4
        doc: "SPI2"
      - id: unusedi23
        type: u4
        doc: "unusedI23"
      - id: cif
        type: u4
        doc: "CIF"
      - id: pwrmgr
        type: u4
        doc: "PWRMGR"
      - id: auxint0
        type: u4
        doc: "AUXINT0"
      - id: auxint1
        type: u4
        doc: "AUXINT1"
      - id: auxint2
        type: u4
        doc: "AUXINT2"
      - id: auxint3
        type: u4
        doc: "AUXINT3"
      - id: iopsrc30
        type: u4
        doc: "IOPSRC30"
      - id: iop_fault
        type: u4
        doc: "IOP fault"
      - id: system_event_status
        type: u4
        doc: "System Event Status"
      - id: f_8042
        type: u4
        doc: "8042"
      - id: lpc_com_a
        type: u4
        doc: "LPC COM A"
      - id: lpc_com_b
        type: u4
        doc: "LPC COM B"
      - id: lpc_com_c
        type: u4
        doc: "LPC COM C"
      - id: pci_com
        type: u4
        doc: "PCI COM"
      - id: legacy_kcs
        type: u4
        doc: "Legacy KCS"
      - id: unusedh7
        type: u4
        doc: "unusedH7"
      - id: pci_kcs
        type: u4
        doc: "PCI KCS"
      - id: legacy_bt
        type: u4
        doc: "Legacy BT"
      - id: dpt
        type: u4
        doc: "DPT"
      - id: sigp
        type: u4
        doc: "SIGP"
      - id: doorbell
        type: u4
        doc: "DOORBELL"
      - id: vehci
        type: u4
        doc: "VEHCI"
      - id: unusedh14
        type: u4
        doc: "unusedH14"
      - id: espi
        type: u4
        doc: "ESPI"
      - id: unusedh16
        type: u4
        doc: "unusedH16"
      - id: unusedh17
        type: u4
        doc: "unusedH17"
      - id: pci_e_error
        type: u4
        doc: "PCI-E error"
      - id: irc
        type: u4
        doc: "IRC"
      - id: pci_bt
        type: u4
        doc: "PCI BT"
      - id: host_i2c
        type: u4
        doc: "HOST i2c"
      - id: peci
        type: u4
        doc: "PECI"
      - id: host_display
        type: u4
        doc: "Host Display"
      - id: mctp
        type: u4
        doc: "MCTP"
      - id: storage_assist
        type: u4
        doc: "Storage Assist"
      - id: unusedh26
        type: u4
        doc: "unusedH26"
      - id: unusedh27
        type: u4
        doc: "unusedH27"
      - id: unusedh28
        type: u4
        doc: "unusedH28"
      - id: unusedh29
        type: u4
        doc: "unusedH29"
      - id: unusedh30
        type: u4
        doc: "unusedH30"
      - id: host_fault
        type: u4
        doc: "Host Fault"

  dict_i2c_engine_statistics:
    doc: "Dictionary struct 43/01 'I2C Engine Statistics' (372 bytes), field layout from the boot_support dictionary"
    seq:
      - id: transactions
        type: u4
        doc: "Transactions"
      - id: error_state_handler_entered
        type: u4
        doc: "Error state handler entered"
      - id: transactions_started
        type: u4
        doc: "Transactions started"
      - id: mux_transactions
        type: u4
        doc: "Mux transactions"
      - id: waiting_for_a_reply
        type: u4
        doc: "Waiting for a reply"
      - id: driver_alerts_generated
        type: u4
        doc: "Driver alerts generated"
      - id: received_driver_alerts
        type: u4
        doc: "Received driver alerts"
      - id: unhandled_errors
        type: u4
        doc: "Unhandled errors"
      - id: spurious_interrupts
        type: u4
        doc: "Spurious Interrupts"
      - id: bte_address_nacks
        type: u4
        doc: "BTE Address Nacks"
      - id: bte_data_nacks
        type: u4
        doc: "BTE Data Nacks"
      - id: bte_address_nacks_2_interrupts
        type: u4
        doc: "BTE Address Nacks 2 Interrupts"
      - id: char_address_nacks
        type: u4
        doc: "Char Address Nacks"
      - id: bus_timeouts
        type: u4
        doc: "Bus timeouts"
      - id: max_cycle_timeouts
        type: u4
        doc: "Max cycle timeouts"
      - id: bus_protocol
        type: u4
        doc: "Bus protocol"
      - id: error_requires_bte_complete
        type: u4
        doc: "Error requires bte complete"
      - id: slave_while_master
        type: u4
        doc: "Slave while master"
      - id: not_idle_errors_returned
        type: u4
        doc: "Not idle errors returned"
      - id: not_idle_from_interrupt_state
        type: u4
        doc: "Not idle from interrupt state"
      - id: not_idle_before_reset
        type: u4
        doc: "Not idle before reset"
      - id: no_apml_phase_one_permission
        type: u4
        doc: "No APML phase one permission"
      - id: engine_locked
        type: u4
        doc: "Engine locked"
      - id: engine_not_locked_errors
        type: u4
        doc: "Engine not locked errors"
      - id: need_topology_update_errors
        type: u4
        doc: "Need topology update errors"
      - id: engine_disabled_on_aux_errors
        type: u4
        doc: "Engine disabled on aux errors"
      - id: segment_does_not_exist
        type: u4
        doc: "Segment does not exist"
      - id: bad_topology
        type: u4
        doc: "Bad topology"
      - id: segment_hung_errors_returned
        type: u4
        doc: "Segment hung errors returned"
      - id: segments_hung
        type: u4
        doc: "Segments hung"
      - id: segment_request_wrong_engine
        type: u4
        doc: "Segment request wrong engine"
      - id: fill_cbte_too_large
        type: u4
        doc: "Fill cbte too large"
      - id: fill_cbte_null_buffer
        type: u4
        doc: "Fill cbte null buffer"
      - id: read_cbte_too_large
        type: u4
        doc: "Read cbte too large"
      - id: read_cbte_null_buffer
        type: u4
        doc: "Read cbte null buffer"
      - id: read_cbte_zero_count
        type: u4
        doc: "Read cbte zero count"
      - id: lost_arbitration
        type: u4
        doc: "Lost arbitration"
      - id: unsupported_transaction_type
        type: u4
        doc: "Unsupported Transaction type"
      - id: unsupported_transaction_mode
        type: u4
        doc: "Unsupported transaction mode"
      - id: bad_status_returning_to_vas
        type: u4
        doc: "Bad status returning to VAS"
      - id: unsupported_mux_type
        type: u4
        doc: "Unsupported mux type"
      - id: interrupt_already_enabled
        type: u4
        doc: "Interrupt already enabled"
      - id: interrupt_already_disabled
        type: u4
        doc: "Interrupt already disabled"
      - id: mctp_slave_and_master
        type: u4
        doc: "MCTP slave and master"
      - id: mctp_timeout
        type: u4
        doc: "MCTP timeout"
      - id: mctp_timeout_from_error_state
        type: u4
        doc: "MCTP timeout from error state"
      - id: recovery_threads_started
        type: u4
        doc: "Recovery threads started"
      - id: recovery_threads_from_service
        type: u4
        doc: "Recovery threads from service"
      - id: end_of_message_non_mctpcobourg
        type: u4
        doc: "End of message non mctpcobourg"
      - id: serv_thread_not_recv_prev_send
        type: u4
        doc: "Serv thread not recv prev send"
      - id: intrupt_resp_activity_bad_stat
        type: u4
        doc: "Intrupt Resp activity bad stat"
      - id: bad_slave_mode
        type: u4
        doc: "Bad slave mode"
      - id: interrupt_timeout
        type: u4
        doc: "Interrupt timeout"
      - id: read_buffer_overflows
        type: u4
        doc: "Read buffer overflows"
      - id: engine_hung_count
        type: u4
        doc: "Engine hung count"
      - id: engine_hung_returned
        type: u4
        doc: "Engine hung returned"
      - id: bad_master_mode
        type: u4
        doc: "Bad master mode"
      - id: bad_master_transaction_state
        type: u4
        doc: "Bad master transaction state"
      - id: bad_transtate_update_pkt_ptrs
        type: u4
        doc: "Bad tranState update pkt ptrs"
      - id: no_master_or_slave
        type: u4
        doc: "No master or slave"
      - id: mctp_send_bad_trans_mode
        type: u4
        doc: "MCTP send bad trans mode"
      - id: unhandled_transtate_end_state
        type: u4
        doc: "Unhandled tranState end state"
      - id: intruptrecov_state_stathandlr
        type: u4
        doc: "IntruptRecov state stathandlr"
      - id: handle_int_stat_invalid_state
        type: u4
        doc: "handle int stat invalid state"
      - id: large_send_buffer_uses
        type: u4
        doc: "Large send buffer uses"
      - id: failed_to_get_large_send_buff
        type: u4
        doc: "Failed to get large send buff"
      - id: intrupt_w_out_intrupt_state
        type: u4
        doc: "Intrupt w/out intrupt state"
      - id: failed_test_transactions
        type: u4
        doc: "Failed test transactions"
      - id: invalid_object_error_code
        type: u4
        doc: "Invalid object error code"
      - id: cbte_master_write_not_complete
        type: u4
        doc: "Cbte master write not complete"
      - id: cbte_master_write_too_much
        type: u4
        doc: "Cbte master write too much"
      - id: cbte_master_read_not_complete
        type: u4
        doc: "Cbte master read not complete"
      - id: cbte_master_read_too_much
        type: u4
        doc: "Cbte master read too much"
      - id: bad_slave_read_engine
        type: u4
        doc: "Bad slave read engine"
      - id: bad_slave_write_no_state
        type: u4
        doc: "Bad slave write no state"
      - id: bad_slave_write_state
        type: u4
        doc: "Bad slave write state"
      - id: slave_read_no_event
        type: u4
        doc: "Slave read no event"
      - id: bad_service_activity_status
        type: u4
        doc: "Bad service activity status"
      - id: continue_activity_recoverable
        type: u4
        doc: "Continue activity recoverable"
      - id: continue_activity_fatal
        type: u4
        doc: "Continue activity fatal"
      - id: asynchronous_receive_failed
        type: u4
        doc: "asynchronous receive failed"
      - id: asynch_recv_failed_after_reset
        type: u4
        doc: "asynch recv failed after reset"
      - id: mux_address_nacks
        type: u4
        doc: "mux address nacks"
      - id: slave_events_in_write_state
        type: u4
        doc: "slave events in write state"
      - id: ilo_does_not_own_bus_returned
        type: u4
        doc: "iLO does not own bus returned"
      - id: consecutive_read_no_buffer
        type: u4
        doc: "Consecutive read no buffer"
      - id: arb_get
        type: u4
        doc: "Arb get"
      - id: arb_get_failed
        type: u4
        doc: "Arb get failed"
      - id: arb_put
        type: u4
        doc: "Arb put"
      - id: arb_put_failed
        type: u4
        doc: "Arb put failed"
      - id: gnt_wait_max_us
        type: u4
        doc: "Gnt wait max (uS)"
      - id: gnt_hold_max_us
        type: u4
        doc: "Gnt hold max (uS)"
      - id: gnt_not_asserted_on_release
        type: u4
        doc: "Gnt not asserted on release"

  dict_i2c_overall_statistics:
    doc: "Dictionary struct 43/02 'I2C Overall Statistics' (40 bytes), field layout from the boot_support dictionary"
    seq:
      - id: select_engine_errors
        type: u4
        doc: "select engine errors"
      - id: select_engine_errors2
        type: u4
        doc: "select engine errors2"
      - id: bad_engine_is_engine_idle
        type: u4
        doc: "bad engine is engine idle"
      - id: bad_engine_check_engine_idle
        type: u4
        doc: "bad engine check engine idle"
      - id: bad_engine_is_trans_snooped
        type: u4
        doc: "bad engine is trans_snooped"
      - id: bad_engine_print_transaction
        type: u4
        doc: "bad engine print transaction"
      - id: interrupt_activity_bad_status
        type: u4
        doc: "interrupt activity bad status"
      - id: total_apml_updates_started
        type: u4
        doc: "total apml updates started"
      - id: average_apml_update_us
        type: u4
        doc: "average apml update us"
      - id: longest_apml_update_us
        type: u4
        doc: "longest apml update us"

  dict_i2c_cobourg_statistics:
    doc: "Dictionary struct 43/03 'I2C Cobourg Statistics' (76 bytes), field layout from the boot_support dictionary"
    seq:
      - id: writes_started
        type: u4
        doc: "writes started"
      - id: reads_started
        type: u4
        doc: "reads started"
      - id: incomplete_receives
        type: u4
        doc: "incomplete_receives"
      - id: incomplete_sends
        type: u4
        doc: "incomplete_sends"
      - id: wait_for_reply_set
        type: u4
        doc: "wait for reply set"
      - id: read_too_much
        type: u4
        doc: "read too much"
      - id: incorrect_read_size
        type: u4
        doc: "incorrect read size"
      - id: response_buffer_not_free
        type: u4
        doc: "response buffer not free"
      - id: mux_reset_called
        type: u4
        doc: "mux reset called"
      - id: bad_activit_status_on_send
        type: u4
        doc: "bad activit status on send"
      - id: send_on_system_without_cobourg
        type: u4
        doc: "send on system without cobourg"
      - id: recovery_thread_started
        type: u4
        doc: "recovery thread started"
      - id: bad_transaction_state
        type: u4
        doc: "bad transaction state"
      - id: ilo_asic_engine_hung
        type: u4
        doc: "iLO ASIC engine hung"
      - id: gpio_longest_activate_us
        type: u4
        doc: "gpio longest activate us"
      - id: gpio_longest_deactivate_us
        type: u4
        doc: "gpio longest deactivate us"
      - id: gpio_waits_over_5ms_activate
        type: u4
        doc: "gpio waits over 5ms activate"
      - id: gpio_waits_over_5ms_deactivate
        type: u4
        doc: "gpio waits over 5ms deactivate"
      - id: read_no_buffer
        type: u4
        doc: "read no buffer"

  dict_i2c_sna_statistics:
    doc: "Dictionary struct 43/04 'I2C SNA Statistics' (8 bytes), field layout from the boot_support dictionary"
    seq:
      - id: mux_reset_called
        type: u4
        doc: "mux reset called"
      - id: bad_synch_receives
        type: u4
        doc: "bad synch receives"

  dict_transmit_statistics:
    doc: "Dictionary struct 45/05 'Transmit Statistics' (44 bytes), field layout from the boot_support dictionary"
    seq:
      - id: last_error_code
        type: u4
        doc: "last_error_code"
      - id: total_transmit
        type: u4
        doc: "total_transmit"
      - id: total_failures
        type: u4
        doc: "total_failures"
      - id: total_timeout
        type: u4
        doc: "total_timeout"
      - id: total_err_bus
        type: u4
        doc: "total_err_bus"
      - id: total_err_config
        type: u4
        doc: "total_err_config"
      - id: total_err_tmo
        type: u4
        doc: "total_err_tmo"
      - id: total_err_link_na
        type: u4
        doc: "total_err_link_na"
      - id: total_err_link_rst
        type: u4
        doc: "total_err_link_rst"
      - id: total_err_shutdown
        type: u4
        doc: "total_err_shutdown"
      - id: total_bus_busy
        type: u4
        doc: "total_bus_busy"

  dict_receive_statistics:
    doc: "Dictionary struct 45/06 'Receive Statistics' (48 bytes), field layout from the boot_support dictionary"
    seq:
      - id: last_error_code
        type: u4
        doc: "last_error_code"
      - id: last_rcv_buffer
        type: u4
        doc: "last_rcv_buffer"
      - id: total_receive
        type: u4
        doc: "total_receive"
      - id: total_failures
        type: u4
        doc: "total_failures"
      - id: total_err_msg_over
        type: u4
        doc: "total_err_msg_over"
      - id: total_err_sequence
        type: u4
        doc: "total_err_sequence"
      - id: total_err_tu_size
        type: u4
        doc: "total_err_tu_size"
      - id: total_err_tmo
        type: u4
        doc: "total_err_tmo"
      - id: total_err_start
        type: u4
        doc: "total_err_start"
      - id: total_err_link_rst
        type: u4
        doc: "total_err_link_rst"
      - id: total_err_shutdown
        type: u4
        doc: "total_err_shutdown"
      - id: total_err_no_act
        type: u4
        doc: "total_err_no_act"

  dict_state_count:
    doc: "Dictionary struct 48/01 'State count:' (20 bytes), field layout from the boot_support dictionary"
    seq:
      - id: iter
        type: u4
        doc: "iter"
      - id: term
        type: u4
        doc: "term"
      - id: cable
        type: u4
        doc: "cable"
      - id: volt
        type: u4
        doc: "volt"
      - id: auto
        type: u4
        doc: "auto"

enums:
  bb_class:
      1: ahs_data
      2: platform_hardware
      3: memory
      5: smbios
      6: ilo_power_manager
      12: ilo_health_subsystem
      14: ilo_power_manager_14
      16: ilo_virtual_devices
      19: romchf_data
      21: embedded_media
      23: dvi
      25: ilo_nic_stats
      26: ilo_security_manager
      29: idletask
      31: ilo_kernel
      36: pjfs
      42: firmware_flash
      50: diagnostics
      55: secure_start
      57: rest_server
      63: rest_directory
      64: plat_inv_data
      66: dvrespi_statistics_data
      67: i2c_driver_data
      68: ilo_configuration
      69: pcie_vdm_driver
      71: rest_tasks
      72: vpd_fw_controlled
      75: ilo_backup_restore
      76: rde_data
      85: svcs_ilo
      86: evs
