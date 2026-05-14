# Intel DPTF DataVault Parser

A Python utility to parse and decode Intel DPTF (Dynamic Platform and Thermal Framework) DataVault (.dv) files.

## Overview

Intel DPTF uses DataVault files to store configuration data for thermal management policies. These binary files contain key-value pairs that define thermal zones, passive cooling policies, power limits, and other platform-specific thermal parameters.

This parser decodes these files and presents the data in human-readable formats.

## Features

- Parses standard DataVault (.dv) files, legacy V1 format, and repository format
- Automatically decompresses zlib/deflate compressed payloads
- Decodes ESIF data types including integers, strings, GUIDs, temperatures, and binary tables
- Formats DPTF-specific tables (PSVT, PPCC) with named fields
- Converts temperatures from deciKelvin to Celsius
- Outputs in text, CSV, or JSON format

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Usage

```
./dv_parser.py [options] <file(s)>
```

### Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable debug output showing parsing details |
| `-f, --format` | Output format: `text` (default), `csv`, or `json` |

### Examples

Parse a single file:
```bash
./dv_parser.py DPTF.dv
```

Parse with verbose debug output:
```bash
./dv_parser.py -v dptf.dv
```

Export to JSON:
```bash
./dv_parser.py -f json dptf.dv > output.json
```

Export multiple files to CSV:
```bash
./dv_parser.py -f csv *.dv > output.csv
```

## Output Formats

### Text (default)

Human-readable output with decoded values and field names for known table types:

```
[0] Key: /shared/tables/psvt/PSVT
    Size: 156 bytes
    Table (rev=2, rows=1):
      Source: TCPU
      Target: TCPU
      PassiveTemp(dK): 3630 (89.9°C)
      ...
```

### JSON

Structured output suitable for programmatic processing:

```json
[
  {
    "key": "/shared/tables/psvt/PSVT",
    "type": "BINARY",
    "type_id": 11,
    "flags": 1,
    "size": 156,
    "value": {...}
  }
]
```

### CSV

Tabular output for spreadsheet import:

```
key,type,flags,size,value
"/shared/tables/psvt/PSVT",BINARY,1,156,"..."
```

## Supported Data Types

| Type | Description |
|------|-------------|
| UINT8/16/32/64 | Unsigned integers |
| INT8/16/32/64 | Signed integers |
| STRING | Null-terminated strings |
| BINARY/BLOB | Raw binary data |
| GUID | 128-bit GUIDs (formatted) |
| TEMPERATURE | DeciKelvin values (converted to Celsius) |
| TABLE | Structured table data |
| JSON/XML | Text markup |

## DPTF Table Decoding

The parser recognizes and formats common DPTF table types:

### PSVT (Passive Policy Table)
Defines passive cooling relationships between thermal sources and targets:
- Source/Target device names
- Sample period and temperature thresholds
- Hysteresis and step limits

### PPCC (Participant Power Control Capabilities)
Defines power limit parameters:
- Min/Max power limits
- Time windows
- Step sizes

## File Format

DataVault files use a binary format with:
- 2-byte signature (`0x1FE5` for standard, `0xD0BA` for repository)
- Variable-length header with version and flags
- Key-value payload with typed entries
- Optional zlib compression (signature `0x4C465A` / "ZFL")

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

## References

- [Intel DPTF Source Code](https://github.com/intel/dptf) - `esif_lib_datavault.h`, `esif_lib_datarepo.h`
- Intel ESIF (Eco-System Independent Framework) SDK
