# Active Health System Logs
HP/HPE ProLiant and Apollo servers starting from Generation 8 (Gen8) have introduced Active Health System which writes all events and logs of running server and its Board Management Controller "iLO" into a "black box". This AHS Log can be requested and downloaded from iLO, but its structure is binary and not documented. There were no publicly available tools to see the contents of the file. First published attempt to decode AHS Logs was from Mark Honeychurch (see [this blog](https://mark.honeychurch.org/blog/projects/ahs/)), he published JavaScript code on Github ([markhoney/ahs](https://github.com/markhoney/ahs)). Unfortunately, the work was not finished, and original code was only able to extract files from AHS container, but not decipher the contents of black box files.

With recent attempt to decode AHS Logs with Claude, we were able to decode the contents of black box files and retrive their contents. Claude was able to find that sys_boot_support.bb and ilo_boot_support.bb files are actually dictionaries to all other numbered bb files.

In this repo you will find Kaitai Struct definitions for the AHS Log file (having .ahs suffix) and Black Box files (having .zbb or .bb suffix).

## Usage
You can generate parser for .ahs and .bb files for your preferred language. For example, compile Python parser with Kaitai Struct Compiler:

`ksc -t python ahs.ksy`
`ksc -t python ahsbb.ksy`

This will generate `ahs.py` and `ahsbb.py` modules that you can import and work through ahs and bb file contents. Use [Kaitai Web IDE](https://ide.kaitai.io/), if you want to see the contents interactively.

## Dependencies
* Kaitai Struct Compiler <https://kaitai.io/>.
* Kaitai Struct Python run-time library (python3-kaitaistruct package in Ubuntu) for further development.
