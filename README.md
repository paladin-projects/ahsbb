# Parsing Black Box Files from Acitve Health Check Logs (AHS)
This repo contains an attempt to parse AHS BB files. BB file is a binary log containing records with variable length, prefixed by a marker. Kaitai Struct file tries to capture all possible markers to split BB file into records. The contents and meaning of records is highly unknown at the moment. Generated parser is able to parse some of the BB files, but not all of them due to missing markers and understanding of all possible records structure.

# Usage
* Process AHS Log with AHS Extract utility :

`node [path to ahs-extract]/ahs-extract -e [AHS Log].ahs`

* Compile Python parser with Kiatai Struct Compiler:

`ksc -t python --no-auto-read ahsbb.ksy`

* Process selected BB file with ahsbb-reader.py:

`./ahsbb-reader.py [your BB file].bb`

# Dependencies
* Node.js (for AHS Extract utility)
* AHS Extract utility <https://github.com/tzong/ahs-extract>
* Kaitai Struct Compiler <https://kaitai.io/>
* Kaitai Struct Python run-time library (python3-kaitaistruct package in Ubuntu)
