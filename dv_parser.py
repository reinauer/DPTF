#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Intel DPTF DataVault (.dv) File Parser

Parses ESIF DataVault files used by Intel's Dynamic Platform and Thermal Framework.
Based on structures from intel/dptf source code (esif_lib_datavault.h, esif_lib_datarepo.h, etc.)

Author: Stefan Reinauer
"""

import struct
import sys
import os
import zlib
import argparse
import base64
import csv
import hashlib
import json
import xml.etree.ElementTree as ET
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional, Sequence, Tuple, BinaryIO

# DataVault signatures (little-endian)
ESIFDV_SIGNATURE = 0x1FE5  # Standard DV signature
ESIFDV_V1_SIGNATURE = 0xE51F  # Legacy V1 signature (big-endian of above)
ESIFDV_REPO_SIGNATURE = 0xD0BA  # Repository signature

# Compression signatures
COMPRESS_SIGNATURE_DEFLATE = 0x4C465A  # "ZFL" - zlib/deflate compressed

# Payload classes
class PayloadClass(IntEnum):
    KEYS = 0x5359454B  # "KEYS" - Key/Value pairs
    REPO = 0x4F504552  # "REPO" - Embedded repository


# ESIF Data Types (from esif_sdk_data_type.h)
class EsifDataType(IntEnum):
    VOID = 0
    UINT8 = 1
    UINT16 = 2
    UINT32 = 3
    UINT64 = 4
    INT8 = 5
    INT16 = 6
    INT32 = 7
    INT64 = 8
    STRING = 9
    UNICODE = 10
    BINARY = 11
    BLOB = 12
    DSP = 13
    TIME = 14
    POINTER = 15
    TABLE = 16
    JSON = 17
    XML = 18
    TEMPERATURE = 19
    POWER = 20
    PERCENT = 21
    FREQUENCY = 22
    GUID = 23
    HANDLE = 24


def esif_data_type_str(dtype: int) -> str:
    """Convert data type to string"""
    try:
        return EsifDataType(dtype).name
    except ValueError:
        return f"UNKNOWN({dtype})"


# DPTF table field names for better output formatting
PSVT_FIELDS = [
    'Source', 'Target', 'Priority', 'SamplePeriod(ms)', 'PassiveTemp(dK)',
    'DeltaLimit', 'CR3Enabled', 'Placeholder', 'HysteresisTemp',
    'StepLimit', 'DepthLimit', 'Reserved'
]

PPCC_FIELDS_PER_ROW = ['PLIndex', 'MinPower(mW)', 'MaxPower(mW)',
                       'MinTimeWindow(ms)', 'MaxTimeWindow(ms)', 'StepSize(mW)']


@dataclass
class DataVaultHeader:
    """DataVault file header structure"""
    signature: int
    header_size: int
    version: int
    flags: int
    
    @property
    def major_version(self) -> int:
        return (self.version >> 24) & 0xFF
    
    @property
    def minor_version(self) -> int:
        return (self.version >> 16) & 0xFF
    
    @property
    def revision(self) -> int:
        return self.version & 0xFFFF


@dataclass 
class RepoHeader:
    """Repository segment header"""
    signature: int
    version: int
    flags: int
    segment_id: str
    comment: str
    payload_class: int
    payload_size: int
    payload_hash: bytes  # SHA-256


@dataclass
class KeyValueEntry:
    """A single key-value entry in the DataVault"""
    key: str
    data_type: int
    flags: int
    data: bytes
    
    @property
    def type_str(self) -> str:
        return esif_data_type_str(self.data_type)
    
    def decode_value(self) -> any:
        """Attempt to decode the value based on type"""
        if not self.data:
            return None

        try:
            # Check if data contains esif_data_variant structure(s)
            # Format: type(4) + length(4) + padding(4) + actual_data
            # or for tables: row_count(4) + col_count(4) + field descriptors + data
            if len(self.data) >= 12:
                inner_type = struct.unpack('<I', self.data[:4])[0]
                inner_len = struct.unpack('<I', self.data[4:8])[0]

                # Check if this looks like a nested esif_data_variant
                if inner_type < 30 and inner_len > 0 and inner_len <= len(self.data) - 8:
                    # Try to decode the inner value
                    return self._decode_variant_array(self.data)

            # Fall back to simple type decoding
            if self.data_type == EsifDataType.STRING:
                return self.data.rstrip(b'\x00').decode('utf-8', errors='replace')
            elif self.data_type == EsifDataType.UINT8:
                return struct.unpack('<B', self.data[:1])[0]
            elif self.data_type == EsifDataType.UINT16:
                return struct.unpack('<H', self.data[:2])[0]
            elif self.data_type == EsifDataType.UINT32:
                return struct.unpack('<I', self.data[:4])[0]
            elif self.data_type == EsifDataType.UINT64:
                return struct.unpack('<Q', self.data[:8])[0]
            elif self.data_type == EsifDataType.INT8:
                return struct.unpack('<b', self.data[:1])[0]
            elif self.data_type == EsifDataType.INT16:
                return struct.unpack('<h', self.data[:2])[0]
            elif self.data_type == EsifDataType.INT32:
                return struct.unpack('<i', self.data[:4])[0]
            elif self.data_type == EsifDataType.INT64:
                return struct.unpack('<q', self.data[:8])[0]
            elif self.data_type in (EsifDataType.JSON, EsifDataType.XML):
                return self.data.rstrip(b'\x00').decode('utf-8', errors='replace')
            elif self.data_type == EsifDataType.GUID:
                if len(self.data) >= 16:
                    d = self.data[:16]
                    return f"{d[3]:02x}{d[2]:02x}{d[1]:02x}{d[0]:02x}-{d[5]:02x}{d[4]:02x}-{d[7]:02x}{d[6]:02x}-{d[8]:02x}{d[9]:02x}-{d[10]:02x}{d[11]:02x}{d[12]:02x}{d[13]:02x}{d[14]:02x}{d[15]:02x}"
            elif self.data_type == EsifDataType.TEMPERATURE:
                if len(self.data) >= 4:
                    temp_dk = struct.unpack('<I', self.data[:4])[0]
                    return f"{temp_dk} dK ({(temp_dk/10 - 273.15):.1f}°C)"
            return self.data
        except Exception as e:
            return self.data

    def _decode_variant_array(self, data: bytes) -> any:
        """Decode data that may be a GUID, table, or other structure"""
        if len(data) < 12:
            return data.hex()

        # Check first variant to determine structure type
        first_type = struct.unpack('<I', data[0:4])[0]
        second_field = struct.unpack('<I', data[4:8])[0]

        # If it looks like a single GUID (type 7, len 16)
        if first_type == 7 and second_field == 16 and len(data) >= 28:
            d = data[12:28]
            return {'type': 'GUID', 'value': f"{d[3]:02x}{d[2]:02x}{d[1]:02x}{d[0]:02x}-{d[5]:02x}{d[4]:02x}-{d[7]:02x}{d[6]:02x}-{d[8]:02x}{d[9]:02x}-{d[10]:02x}{d[11]:02x}{d[12]:02x}{d[13]:02x}{d[14]:02x}{d[15]:02x}"}

        # If first field is small (1-10) and second is also small (1-10),
        # likely a table with revision + row_count header
        if 1 <= first_type <= 10 and 1 <= second_field <= 10:
            return self._decode_esif_table(data)

        # Otherwise try variant array decoding
        return self._decode_simple_variant(data)

    def _decode_esif_table(self, data: bytes) -> dict:
        """Decode ESIF table data (PSVT, PPCC, etc.)"""
        if len(data) < 12:
            return {'raw': data.hex()}

        # Table header: revision(4) + row_count(4) + reserved(4)
        revision = struct.unpack('<I', data[0:4])[0]
        row_count = struct.unpack('<I', data[4:8])[0]

        # Parse fields starting after header
        # For strings (type 8): type(4) + len(4) + pad(4) + data(len)
        # For scalars (type 4): type(4) + value(4) + pad(4) = 12 bytes fixed
        fields = []
        pos = 12

        while pos + 12 <= len(data):
            vtype = struct.unpack('<I', data[pos:pos+4])[0]
            field2 = struct.unpack('<I', data[pos+4:pos+8])[0]

            if vtype > 20:
                break

            if vtype == 8:  # STRING type
                str_len = field2
                if pos + 12 + str_len > len(data):
                    break
                val = data[pos+12:pos+12+str_len].rstrip(b'\x00').decode('utf-8', errors='replace')
                fields.append(val)
                pos += 12 + str_len
            elif vtype == 4:  # UINT32 (value stored in field2)
                if field2 == 0xFFFFFFFF:
                    fields.append('MAX')
                else:
                    fields.append(field2)
                pos += 12
            else:
                fields.append(f'type{vtype}:{field2}')
                pos += 12

            if len(fields) > 50:  # Safety limit
                break

        return {'revision': revision, 'rows': row_count, 'fields': fields}

    def _decode_simple_variant(self, data: bytes) -> any:
        """Decode a simple esif_data_variant structure"""
        if len(data) < 12:
            return data.hex()

        vtype = struct.unpack('<I', data[0:4])[0]
        vlen = struct.unpack('<I', data[4:8])[0]

        if vlen == 16 and len(data) >= 28:  # GUID
            d = data[12:28]
            return {'type': 'GUID', 'value': f"{d[3]:02x}{d[2]:02x}{d[1]:02x}{d[0]:02x}-{d[5]:02x}{d[4]:02x}-{d[7]:02x}{d[6]:02x}-{d[8]:02x}{d[9]:02x}-{d[10]:02x}{d[11]:02x}{d[12]:02x}{d[13]:02x}{d[14]:02x}{d[15]:02x}"}
        elif vtype == 8:  # STRING
            return data[12:12+vlen].rstrip(b'\x00').decode('utf-8', errors='replace')
        elif vtype == 4:  # UINT32
            return struct.unpack('<I', data[4:8])[0]

        return data.hex()


class DataVaultParser:
    """Parser for Intel DPTF DataVault files"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.entries: List[KeyValueEntry] = []
        self.header: Optional[DataVaultHeader] = None
        self.repo_headers: List[RepoHeader] = []
        
    def log(self, msg: str):
        if self.verbose:
            print(f"[DEBUG] {msg}")
    
    def is_valid_signature(self, sig: int) -> bool:
        """Check if signature is a valid DataVault signature"""
        return sig in (ESIFDV_SIGNATURE, ESIFDV_V1_SIGNATURE, ESIFDV_REPO_SIGNATURE)
    
    def try_decompress(self, data: bytes) -> bytes:
        """Try to decompress data if it's compressed"""
        if len(data) < 12:
            return data
            
        # Check for compression header
        # Format: signature(4) + uncompressed_size(4) + compressed_data
        sig = struct.unpack('<I', data[:4])[0] & 0xFFFFFF
        if sig == COMPRESS_SIGNATURE_DEFLATE:
            try:
                uncompressed_size = struct.unpack('<I', data[4:8])[0]
                compressed_data = data[8:]
                decompressed = zlib.decompress(compressed_data)
                self.log(f"Decompressed {len(compressed_data)} -> {len(decompressed)} bytes")
                return decompressed
            except Exception as e:
                self.log(f"Decompression failed: {e}")
        return data
    
    def parse_header_v1(self, f: BinaryIO) -> Tuple[int, int]:
        """Parse legacy V1 header, returns (version, flags)"""
        # V1: signature(2) + version(1) + headersize(1) ...
        version = struct.unpack('<B', f.read(1))[0]
        header_size = struct.unpack('<B', f.read(1))[0]
        flags = struct.unpack('<I', f.read(4))[0]
        return version, flags
    
    def parse_header_v2(self, f: BinaryIO) -> Tuple[int, int, int]:
        """Parse V2+ header, returns (header_size, version, flags)"""
        # V2+: signature(2) + headersize(2) + version(4) + flags(4) ...
        header_size = struct.unpack('<H', f.read(2))[0]
        version = struct.unpack('<I', f.read(4))[0]
        flags = struct.unpack('<I', f.read(4))[0]
        return header_size, version, flags
    
    def parse_repo_header(self, f: BinaryIO) -> Optional[RepoHeader]:
        """Parse repository segment header"""
        start_pos = f.tell()
        
        sig = struct.unpack('<H', f.read(2))[0]
        if sig != ESIFDV_REPO_SIGNATURE:
            f.seek(start_pos)
            return None
            
        header_size = struct.unpack('<H', f.read(2))[0]
        version = struct.unpack('<I', f.read(4))[0]
        flags = struct.unpack('<I', f.read(4))[0]
        
        # Read segment ID (32 bytes max + null)
        segment_id_raw = f.read(33)
        segment_id = segment_id_raw.rstrip(b'\x00').decode('utf-8', errors='replace')
        
        # Read comment (64 bytes max + null)  
        comment_raw = f.read(65)
        comment = comment_raw.rstrip(b'\x00').decode('utf-8', errors='replace')
        
        payload_class = struct.unpack('<I', f.read(4))[0]
        payload_size = struct.unpack('<I', f.read(4))[0]
        
        # SHA-256 hash (32 bytes)
        payload_hash = f.read(32)
        
        # Seek to end of header
        f.seek(start_pos + header_size)
        
        return RepoHeader(
            signature=sig,
            version=version,
            flags=flags,
            segment_id=segment_id,
            comment=comment,
            payload_class=payload_class,
            payload_size=payload_size,
            payload_hash=payload_hash
        )
    
    def parse_keys_payload(self, data: bytes) -> List[KeyValueEntry]:
        """Parse KEYS payload containing key-value pairs"""
        entries = []
        pos = 0

        while pos < len(data) - 10:
            try:
                # Entry format in this DataVault version:
                # marker(2) + entry_type(4) + key_len(4) + key + null + type(4) + data_len(4) + data
                #
                # The marker is typically 0xa0d8, entry_type is usually 1

                # Read the 2-byte marker
                marker = struct.unpack('<H', data[pos:pos+2])[0]

                # Check for known entry marker (0xa0d8) or scan for valid entry
                if marker == 0xa0d8:
                    # Standard entry format
                    # Skip marker(2) + entry_type(4) = 6 bytes to get to key_len
                    entry_type = struct.unpack('<I', data[pos+2:pos+6])[0]
                    key_len = struct.unpack('<I', data[pos+6:pos+10])[0]

                    self.log(f"Entry at {pos}: marker=0x{marker:04x}, entry_type={entry_type}, key_len={key_len}")

                    if key_len == 0 or key_len > 1024:
                        pos += 1
                        continue

                    key_start = pos + 10
                    if key_start + key_len > len(data):
                        break

                    # Key is null-terminated, so actual key length in file includes null
                    key_bytes = data[key_start:key_start+key_len]
                    key = key_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

                    # After key (key_len includes null terminator): type(4) + data_len(4) + data
                    after_key = key_start + key_len

                    if after_key + 8 > len(data):
                        break

                    # Read type and data length
                    dtype = struct.unpack('<I', data[after_key:after_key+4])[0]
                    data_len = struct.unpack('<I', data[after_key+4:after_key+8])[0]

                    self.log(f"  Key: {key}, type={dtype}, data_len={data_len}")

                    # Data starts after type(4) + data_len(4)
                    data_start = after_key + 8

                    # Validate data_len
                    if data_len > len(data) - data_start or data_len > 65536:
                        # Try to find next entry marker to determine actual data length
                        next_marker_pos = data.find(b'\xd8\xa0', data_start)
                        if next_marker_pos > data_start:
                            data_len = next_marker_pos - data_start
                        else:
                            data_len = len(data) - data_start

                    entry_data = data[data_start:data_start+data_len]

                    entry = KeyValueEntry(
                        key=key,
                        data_type=dtype & 0xFF,
                        flags=entry_type,
                        data=entry_data
                    )
                    entries.append(entry)

                    pos = data_start + data_len

                else:
                    # Try legacy format or scan forward
                    # Legacy: flags(2) + key_len(2) + key + type(4) + data_len(4) + data
                    potential_keylen = struct.unpack('<H', data[pos:pos+2])[0]

                    if 0 < potential_keylen < 512:
                        flags = 0
                        key_len = potential_keylen
                        key_start = pos + 2
                    elif pos + 4 <= len(data):
                        flags = struct.unpack('<H', data[pos:pos+2])[0]
                        potential_keylen = struct.unpack('<H', data[pos+2:pos+4])[0]
                        if 0 < potential_keylen < 512:
                            key_len = potential_keylen
                            key_start = pos + 4
                        else:
                            pos += 1
                            continue
                    else:
                        pos += 1
                        continue

                    if key_start + key_len > len(data):
                        break

                    key = data[key_start:key_start+key_len].rstrip(b'\x00').decode('utf-8', errors='replace')

                    after_key = key_start + key_len

                    if after_key + 8 > len(data):
                        break

                    dtype = struct.unpack('<I', data[after_key:after_key+4])[0]
                    data_len = struct.unpack('<I', data[after_key+4:after_key+8])[0]

                    if data_len > len(data) - after_key - 8:
                        data_len = struct.unpack('<H', data[after_key+4:after_key+6])[0]
                        data_start = after_key + 6
                    else:
                        data_start = after_key + 8

                    if data_start + data_len > len(data):
                        data_len = min(data_len, len(data) - data_start)

                    entry_data = data[data_start:data_start+data_len]

                    entry = KeyValueEntry(
                        key=key,
                        data_type=dtype & 0xFF,
                        flags=flags,
                        data=entry_data
                    )
                    entries.append(entry)

                    pos = data_start + data_len

            except Exception as e:
                self.log(f"Error parsing entry at {pos}: {e}")
                pos += 1

        return entries
    
    def parse_dv_stream(self, data: bytes) -> List[KeyValueEntry]:
        """Parse a DataVault stream (may be raw or have header)"""
        entries = []
        
        if len(data) < 4:
            return entries
        
        # Check for DV signature
        sig = struct.unpack('<H', data[:2])[0]
        
        if self.is_valid_signature(sig):
            # Has header
            if sig in (ESIFDV_SIGNATURE, ESIFDV_V1_SIGNATURE):
                # Skip header and parse payload
                if sig == ESIFDV_V1_SIGNATURE:
                    header_size = data[3] if len(data) > 3 else 8
                else:
                    header_size = struct.unpack('<H', data[2:4])[0] if len(data) >= 4 else 12
                
                payload = data[header_size:]
                entries = self.parse_keys_payload(payload)
            elif sig == ESIFDV_REPO_SIGNATURE:
                # Repository format - parse repo header then payload
                header_size = struct.unpack('<H', data[2:4])[0] if len(data) >= 4 else 152
                if len(data) > header_size:
                    payload = data[header_size:]
                    entries = self.parse_keys_payload(payload)
        else:
            # No header, raw key-value data
            entries = self.parse_keys_payload(data)
        
        return entries
    
    def parse_file(self, filepath: str) -> bool:
        """Parse a DataVault file"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            self.log(f"Read {len(data)} bytes from {filepath}")
            
            if len(data) < 4:
                print(f"Error: File too small ({len(data)} bytes)")
                return False
            
            # Try decompression first
            data = self.try_decompress(data)
            
            # Check signature
            sig = struct.unpack('<H', data[:2])[0]
            self.log(f"Signature: 0x{sig:04X}")
            
            if not self.is_valid_signature(sig):
                # Check if it starts with esif_data_variant (8 bytes)
                # and skip it
                self.log("No valid signature, trying to skip esif_data_variant header")
                if len(data) > 8:
                    sig2 = struct.unpack('<H', data[8:10])[0]
                    if self.is_valid_signature(sig2):
                        data = data[8:]
                        sig = sig2
                        self.log(f"Found signature at offset 8: 0x{sig:04X}")
            
            if sig == ESIFDV_SIGNATURE or sig == ESIFDV_V1_SIGNATURE:
                self.log("Parsing as DataVault format")
                self.entries = self.parse_dv_stream(data)
            elif sig == ESIFDV_REPO_SIGNATURE:
                self.log("Parsing as Repository format")
                # Parse repo header
                pos = 0
                while pos < len(data) - 4:
                    check_sig = struct.unpack('<H', data[pos:pos+2])[0]
                    if check_sig == ESIFDV_REPO_SIGNATURE:
                        header_size = struct.unpack('<H', data[pos+2:pos+4])[0]
                        self.log(f"Found repo segment at {pos}, header size {header_size}")
                        
                        # Parse header fields
                        if pos + header_size < len(data):
                            version = struct.unpack('<I', data[pos+4:pos+8])[0]
                            flags = struct.unpack('<I', data[pos+8:pos+12])[0]
                            segment_id = data[pos+12:pos+45].rstrip(b'\x00').decode('utf-8', errors='replace')
                            comment = data[pos+45:pos+110].rstrip(b'\x00').decode('utf-8', errors='replace')
                            payload_class = struct.unpack('<I', data[pos+110:pos+114])[0]
                            payload_size = struct.unpack('<I', data[pos+114:pos+118])[0]
                            
                            self.log(f"  Segment: {segment_id}, Comment: {comment}")
                            self.log(f"  Payload class: 0x{payload_class:08X}, size: {payload_size}")
                            
                            payload_start = pos + header_size
                            payload_end = payload_start + payload_size
                            
                            if payload_end <= len(data):
                                payload = data[payload_start:payload_end]
                                
                                # Try to decompress payload
                                payload = self.try_decompress(payload)
                                
                                entries = self.parse_keys_payload(payload)
                                self.entries.extend(entries)
                                
                            pos = payload_end
                        else:
                            pos += 2
                    else:
                        pos += 1
            else:
                # Try raw parsing
                self.log("No valid signature found, trying raw key-value parsing")
                self.entries = self.parse_keys_payload(data)
            
            return True
            
        except Exception as e:
            print(f"Error parsing file: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def dump(self, output_format: str = 'text'):
        """Dump parsed entries"""
        if output_format == 'text':
            print(f"\nFound {len(self.entries)} entries:\n")
            print("-" * 80)

            for i, entry in enumerate(self.entries):
                print(f"[{i}] Key: {entry.key}")
                print(f"    Size: {len(entry.data)} bytes")

                value = entry.decode_value()
                if isinstance(value, bytes):
                    if len(value) <= 64:
                        print(f"    Value: {value.hex()}")
                    else:
                        print(f"    Value: {value[:64].hex()}... (truncated)")
                elif isinstance(value, dict):
                    if 'type' in value and value['type'] == 'GUID':
                        print(f"    GUID: {value['value']}")
                    elif 'fields' in value:
                        print(f"    Table (rev={value.get('revision', '?')}, rows={value.get('rows', '?')}):")
                        fields = value['fields']
                        # Determine field names based on key
                        if 'psvt' in entry.key.lower():
                            field_names = PSVT_FIELDS
                        elif 'ppcc' in entry.key.lower():
                            field_names = PPCC_FIELDS_PER_ROW
                        else:
                            field_names = []

                        # Format fields nicely with names
                        for j, field in enumerate(fields):
                            if field_names and j < len(field_names):
                                name = field_names[j]
                            elif field_names and 'ppcc' in entry.key.lower():
                                # PPCC repeats every 6 fields
                                idx = j % len(PPCC_FIELDS_PER_ROW)
                                row = j // len(PPCC_FIELDS_PER_ROW)
                                name = f"Row{row}.{PPCC_FIELDS_PER_ROW[idx]}"
                            else:
                                name = f"[{j}]"
                            # Add temperature conversion for dK values
                            extra = ""
                            if 'Temp' in str(name) and isinstance(field, int) and field > 2000 and field < 5000:
                                celsius = (field / 10) - 273.15
                                extra = f" ({celsius:.1f}°C)"
                            print(f"      {name}: {field}{extra}")
                    else:
                        print(f"    Value: {value}")
                else:
                    val_str = str(value)
                    if len(val_str) > 200:
                        val_str = val_str[:200] + "..."
                    print(f"    Value: {val_str}")
                print()
                
        elif output_format == 'csv':
            print("key,type,flags,size,value")
            for entry in self.entries:
                value = entry.decode_value()
                if isinstance(value, bytes):
                    val_str = value.hex()
                else:
                    val_str = str(value).replace('"', '""')
                print(f'"{entry.key}",{entry.type_str},{entry.flags},{len(entry.data)},"{val_str}"')
                
        elif output_format == 'json':
            import json
            output = []
            for entry in self.entries:
                value = entry.decode_value()
                if isinstance(value, bytes):
                    val_str = value.hex()
                else:
                    val_str = value
                output.append({
                    'key': entry.key,
                    'type': entry.type_str,
                    'type_id': entry.data_type,
                    'flags': entry.flags,
                    'size': len(entry.data),
                    'value': val_str
                })
            print(json.dumps(output, indent=2))

# ---------------------------------------------------------------------------
# Parser implementation based on Intel DPTF DataVaultHeaderV2 and
# esif_data_variant.  These definitions intentionally replace the older
# speculative parser above while keeping the public DataVaultParser name.

ESIFDV_HEADER_V2_MIN_SIZE = 148
ESIFDV_ITEM_KEYS_REV0_SIGNATURE = 0xA0D8
SEGMENT_ID_LEN = 32
COMMENT_LEN = 64
MAX_U32 = 0xFFFFFFFF
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class PayloadClass(IntEnum):
    KEYS = 0x5359454B
    REPO = 0x4F504552


class EsifDataType(IntEnum):
    UINT8 = 1
    UINT16 = 2
    UINT32 = 3
    UINT64 = 4
    GUID = 5
    TEMPERATURE = 6
    BINARY = 7
    STRING = 8
    UNICODE = 9
    INT8 = 11
    INT16 = 12
    INT32 = 13
    INT64 = 14
    POINTER = 18
    ENUM = 19
    HANDLE = 20
    VOID = 24
    POWER = 26
    PERCENT = 29
    INSTANCE = 30
    TIME = 31
    STRUCTURE = 32
    DSP = 33
    BLOB = 34
    TABLE = 35
    AUTO = 36
    XML = 38
    DECIBEL = 39
    FREQUENCY = 40
    ANGLE = 41
    JSON = 42


INTEGER_VARIANT_TYPES = {
    EsifDataType.UINT8,
    EsifDataType.UINT16,
    EsifDataType.UINT32,
    EsifDataType.UINT64,
    EsifDataType.INT8,
    EsifDataType.INT16,
    EsifDataType.INT32,
    EsifDataType.INT64,
    EsifDataType.TEMPERATURE,
    EsifDataType.POWER,
    EsifDataType.PERCENT,
    EsifDataType.INSTANCE,
    EsifDataType.TIME,
    EsifDataType.ENUM,
    EsifDataType.DECIBEL,
    EsifDataType.FREQUENCY,
    EsifDataType.ANGLE,
    EsifDataType.HANDLE,
    EsifDataType.POINTER,
    EsifDataType.VOID,
}

BUFFER_VARIANT_TYPES = {
    EsifDataType.GUID,
    EsifDataType.BINARY,
    EsifDataType.STRING,
    EsifDataType.UNICODE,
    EsifDataType.STRUCTURE,
    EsifDataType.DSP,
    EsifDataType.BLOB,
    EsifDataType.TABLE,
    EsifDataType.XML,
    EsifDataType.JSON,
}

PSVT_FIELDS = [
    "Source",
    "Target",
    "Priority",
    "SamplePeriod(ms)",
    "PassiveTemp(dK)",
    "SourceDomain",
    "ControlKnob",
    "Limit",
    "StepSize",
    "LimitCoeff",
    "UnlimitCoeff",
    "ControlKnobType",
]

PPCC_FIELDS_PER_ROW = [
    "PLIndex",
    "MinPower(mW)",
    "MaxPower(mW)",
    "MinTimeWindow(ms)",
    "MaxTimeWindow(ms)",
    "StepSize(mW)",
]


def type_name(type_id: int) -> str:
    try:
        return EsifDataType(type_id).name
    except ValueError:
        return f"UNKNOWN({type_id})"


def payload_class_name(class_id: int) -> str:
    try:
        return PayloadClass(class_id).name
    except ValueError:
        return f"UNKNOWN(0x{class_id:08x})"


def decode_c_string(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def encode_fixed_c_string(value: str, size: int) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) >= size:
        return raw[: size - 1] + b"\x00"
    return raw + b"\x00" * (size - len(raw))


def format_guid(raw: bytes) -> str:
    if len(raw) < 16:
        return raw.hex()
    d = raw[:16]
    return (
        f"{d[3]:02x}{d[2]:02x}{d[1]:02x}{d[0]:02x}-"
        f"{d[5]:02x}{d[4]:02x}-"
        f"{d[7]:02x}{d[6]:02x}-"
        f"{d[8]:02x}{d[9]:02x}-"
        f"{d[10]:02x}{d[11]:02x}{d[12]:02x}{d[13]:02x}{d[14]:02x}{d[15]:02x}"
    )


def dkelvin_to_celsius(value: int) -> float:
    return value / 10.0 - 273.15


@dataclass
class EsifVariant:
    type_id: int
    value: Any
    offset: int = 0
    size: int = 0
    reserved: int = 0

    @property
    def type_str(self) -> str:
        return type_name(self.type_id)

    @property
    def is_buffer(self) -> bool:
        try:
            return EsifDataType(self.type_id) in BUFFER_VARIANT_TYPES
        except ValueError:
            return False

    @property
    def is_integer(self) -> bool:
        try:
            return EsifDataType(self.type_id) in INTEGER_VARIANT_TYPES
        except ValueError:
            return False

    def as_text(self) -> str:
        if self.type_id == EsifDataType.STRING:
            return self.value.rstrip(b"\x00").decode("utf-8", errors="replace")
        if self.type_id == EsifDataType.UNICODE:
            return self.value.rstrip(b"\x00").decode("utf-16-le", errors="replace")
        if self.type_id == EsifDataType.GUID:
            return format_guid(self.value)
        if self.type_id == EsifDataType.BINARY and isinstance(self.value, bytes) and len(self.value) == 16:
            return format_guid(self.value)
        if self.is_integer:
            if self.value in (MAX_U32, MAX_U64):
                return "MAX"
            return str(self.value)
        if isinstance(self.value, bytes):
            return "0x" + self.value.hex()
        return str(self.value)

    def display(self, field_name: Optional[str] = None) -> str:
        text = self.as_text()
        if (
            field_name
            and "Temp" in field_name
            and self.is_integer
            and self.value not in (MAX_U32, MAX_U64)
        ):
            text += f" ({dkelvin_to_celsius(self.value):.2f} C)"
        return text

    def encode(self) -> bytes:
        if self.is_buffer:
            return struct.pack("<III", self.type_id, len(self.value), self.reserved) + self.value
        if not self.is_integer:
            raise ValueError(f"cannot encode unknown variant type {self.type_id}")
        return struct.pack("<IQ", self.type_id, self.value & MAX_U64)

    def copy_with_value(self, value: Any) -> "EsifVariant":
        return EsifVariant(self.type_id, value, self.offset, self.size, self.reserved)


@dataclass
class DecodedTable:
    kind: str
    revision: EsifVariant
    rows: List[List[EsifVariant]]
    field_names: List[str]
    trailing: List[EsifVariant] = field(default_factory=list)

    def encode(self) -> bytes:
        out = bytearray(self.revision.encode())
        for row in self.rows:
            for variant in row:
                out.extend(variant.encode())
        for variant in self.trailing:
            out.extend(variant.encode())
        return bytes(out)

    def field_index(self, name: str) -> int:
        normal = name.lower()
        for idx, field_name in enumerate(self.field_names):
            if field_name.lower() == normal:
                return idx
        raise KeyError(name)


@dataclass
class KeyValueEntry:
    key: str
    data_type: int
    flags: int
    data: bytes
    marker: int = ESIFDV_ITEM_KEYS_REV0_SIGNATURE

    @property
    def type_str(self) -> str:
        return type_name(self.data_type)

    def encode(self) -> bytes:
        key_bytes = self.key.encode("utf-8") + b"\x00"
        return b"".join(
            [
                struct.pack("<HII", self.marker, self.flags, len(key_bytes)),
                key_bytes,
                struct.pack("<II", self.data_type, len(self.data)),
                self.data,
            ]
        )

    def decode_table(self) -> Optional[DecodedTable]:
        key = self.key.lower()
        if "/psvt" in key:
            return decode_variant_table(self.data, "psvt", PSVT_FIELDS)
        if "/ppcc" in key:
            return decode_variant_table(self.data, "ppcc", PPCC_FIELDS_PER_ROW)
        return None

    def decode_variants(self) -> Optional[List[EsifVariant]]:
        try:
            variants, end = parse_variant_stream(self.data)
        except ValueError:
            return None
        if end != len(self.data):
            return None
        return variants

    def decoded_value(self) -> Any:
        table = self.decode_table()
        if table is not None:
            return table
        variants = self.decode_variants()
        if variants:
            if len(variants) == 1:
                return variants[0]
            return variants
        if self.data_type == EsifDataType.STRING:
            return self.data.rstrip(b"\x00").decode("utf-8", errors="replace")
        if self.data_type == EsifDataType.GUID and len(self.data) >= 16:
            return format_guid(self.data)
        if self.data_type in (EsifDataType.XML, EsifDataType.JSON):
            return self.data.rstrip(b"\x00").decode("utf-8", errors="replace")
        if self.data_type == EsifDataType.UINT64 and len(self.data) >= 8:
            return struct.unpack_from("<Q", self.data)[0]
        if self.data_type == EsifDataType.UINT32 and len(self.data) >= 4:
            return struct.unpack_from("<I", self.data)[0]
        return self.data


@dataclass
class DataVaultSegment:
    signature: int
    header_size: int
    version: int
    flags: int
    segment_id: str
    comment: str
    payload_hash: bytes
    payload_size: int
    payload_class: int
    entries: List[KeyValueEntry] = field(default_factory=list)
    raw_payload: bytes = b""
    offset: int = 0
    header_extra: bytes = b""

    @property
    def major_version(self) -> int:
        return (self.version >> 24) & 0xFF

    @property
    def minor_version(self) -> int:
        return (self.version >> 16) & 0xFF

    @property
    def revision(self) -> int:
        return self.version & 0xFFFF

    @property
    def hash_valid(self) -> bool:
        return hashlib.sha256(self.raw_payload).digest() == self.payload_hash

    def build_payload(self) -> bytes:
        if self.payload_class == PayloadClass.KEYS:
            return b"".join(entry.encode() for entry in self.entries)
        return self.raw_payload

    def encode(self) -> bytes:
        payload = self.build_payload()
        payload_hash = hashlib.sha256(payload).digest()
        header = b"".join(
            [
                struct.pack("<HHII", self.signature, self.header_size, self.version, self.flags),
                encode_fixed_c_string(self.segment_id, SEGMENT_ID_LEN),
                encode_fixed_c_string(self.comment, COMMENT_LEN),
                payload_hash,
                struct.pack("<II", len(payload), self.payload_class),
            ]
        )
        if len(header) > self.header_size:
            raise ValueError(f"header is larger than header_size ({len(header)} > {self.header_size})")
        if len(header) < self.header_size:
            extra = self.header_extra[: self.header_size - len(header)]
            header += extra
            header += b"\x00" * (self.header_size - len(header))
        return header + payload


def parse_variant(data: bytes, offset: int) -> Tuple[EsifVariant, int]:
    if offset + 12 > len(data):
        raise ValueError(f"truncated esif_data_variant at offset {offset}")

    type_id = struct.unpack_from("<I", data, offset)[0]
    try:
        data_type = EsifDataType(type_id)
    except ValueError as exc:
        raise ValueError(f"unknown esif_data_variant type {type_id} at offset {offset}") from exc

    if data_type in BUFFER_VARIANT_TYPES:
        length, reserved = struct.unpack_from("<II", data, offset + 4)
        end = offset + 12 + length
        if end > len(data):
            raise ValueError(f"truncated buffer variant at offset {offset}")
        return EsifVariant(type_id, data[offset + 12 : end], offset, end - offset, reserved), end

    if data_type not in INTEGER_VARIANT_TYPES:
        raise ValueError(f"unsupported esif_data_variant type {type_id} at offset {offset}")

    value = struct.unpack_from("<Q", data, offset + 4)[0]
    return EsifVariant(type_id, value, offset, 12, 0), offset + 12


def parse_variant_stream(data: bytes, offset: int = 0) -> Tuple[List[EsifVariant], int]:
    variants: List[EsifVariant] = []
    pos = offset
    while pos < len(data):
        variant, pos = parse_variant(data, pos)
        variants.append(variant)
    return variants, pos


def decode_variant_table(data: bytes, kind: str, field_names: Sequence[str]) -> Optional[DecodedTable]:
    try:
        variants, end = parse_variant_stream(data)
    except ValueError:
        return None
    if end != len(data) or not variants:
        return None

    width = len(field_names)
    revision = variants[0]
    fields = variants[1:]
    rows = [fields[i : i + width] for i in range(0, len(fields) - (len(fields) % width), width)]
    trailing = fields[len(rows) * width :]
    return DecodedTable(kind, revision, rows, list(field_names), trailing)


class DataVaultParser:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.segments: List[DataVaultSegment] = []
        self.entries: List[KeyValueEntry] = []

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"[DEBUG] {message}", file=sys.stderr)

    def parse_file(self, filepath: str) -> bool:
        with open(filepath, "rb") as f:
            return self.parse_bytes(f.read())

    def parse_bytes(self, data: bytes) -> bool:
        self.segments = []
        self.entries = []
        pos = 0

        while pos < len(data):
            if pos + ESIFDV_HEADER_V2_MIN_SIZE > len(data):
                raise ValueError(f"trailing {len(data) - pos} bytes after last DataVault segment")

            signature = struct.unpack_from("<H", data, pos)[0]
            if signature != ESIFDV_SIGNATURE:
                raise ValueError(f"invalid DataVault signature 0x{signature:04x} at offset {pos}")

            header_size, version, flags = struct.unpack_from("<HII", data, pos + 2)
            if header_size < ESIFDV_HEADER_V2_MIN_SIZE:
                raise ValueError(f"invalid DataVault header size {header_size} at offset {pos}")

            header_end = pos + header_size
            if header_end > len(data):
                raise ValueError(f"truncated DataVault header at offset {pos}")

            segment_id = decode_c_string(data[pos + 12 : pos + 44])
            comment = decode_c_string(data[pos + 44 : pos + 108])
            payload_hash = data[pos + 108 : pos + 140]
            payload_size, payload_class = struct.unpack_from("<II", data, pos + 140)
            payload_start = header_end
            payload_end = payload_start + payload_size
            if payload_end > len(data):
                raise ValueError(f"truncated DataVault payload at offset {payload_start}")

            payload = data[payload_start:payload_end]
            entries: List[KeyValueEntry] = []
            if payload_class == PayloadClass.KEYS:
                entries = self.parse_keys_payload(payload)
                self.entries.extend(entries)
            else:
                self.log(f"skipping non-KEYS payload class {payload_class_name(payload_class)}")

            segment = DataVaultSegment(
                signature=signature,
                header_size=header_size,
                version=version,
                flags=flags,
                segment_id=segment_id,
                comment=comment,
                payload_hash=payload_hash,
                payload_size=payload_size,
                payload_class=payload_class,
                entries=entries,
                raw_payload=payload,
                offset=pos,
                header_extra=data[pos + ESIFDV_HEADER_V2_MIN_SIZE : header_end],
            )
            if not segment.hash_valid:
                self.log(f"payload hash mismatch for segment {segment_id!r}")
            self.segments.append(segment)
            pos = payload_end
        return True

    def parse_keys_payload(self, data: bytes) -> List[KeyValueEntry]:
        entries: List[KeyValueEntry] = []
        pos = 0

        while pos < len(data):
            if pos + 18 > len(data):
                raise ValueError(f"truncated KEYS item at payload offset {pos}")

            marker, flags, key_len = struct.unpack_from("<HII", data, pos)
            if marker != ESIFDV_ITEM_KEYS_REV0_SIGNATURE:
                raise ValueError(f"invalid KEYS item marker 0x{marker:04x} at payload offset {pos}")
            if key_len == 0:
                raise ValueError(f"empty KEYS item key at payload offset {pos}")

            key_start = pos + 10
            key_end = key_start + key_len
            if key_end + 8 > len(data):
                raise ValueError(f"truncated KEYS item key at payload offset {pos}")
            key = data[key_start:key_end].rstrip(b"\x00").decode("utf-8", errors="replace")

            data_type, data_len = struct.unpack_from("<II", data, key_end)
            data_start = key_end + 8
            data_end = data_start + data_len
            if data_end > len(data):
                raise ValueError(f"truncated KEYS item value for {key}")

            entries.append(
                KeyValueEntry(
                    key=key,
                    data_type=data_type,
                    flags=flags,
                    data=data[data_start:data_end],
                    marker=marker,
                )
            )
            pos = data_end
        return entries

    def encode(self) -> bytes:
        return b"".join(segment.encode() for segment in self.segments)

    def find_entry(self, key: str) -> KeyValueEntry:
        for entry in self.entries:
            if entry.key == key:
                return entry
        raise KeyError(key)

    def dump_text(self) -> None:
        if self.segments:
            for idx, segment in enumerate(self.segments):
                print(
                    f"Segment[{idx}]: id={segment.segment_id} version="
                    f"{segment.major_version}.{segment.minor_version}.{segment.revision} "
                    f"class={payload_class_name(segment.payload_class)} "
                    f"payload={segment.payload_size} bytes hash={'ok' if segment.hash_valid else 'BAD'}"
                )
            print()

        print(f"Found {len(self.entries)} entries:\n")
        print("-" * 80)
        for idx, entry in enumerate(self.entries):
            print(f"[{idx}] Key: {entry.key}")
            print(f"    Type: {entry.type_str} ({entry.data_type})")
            print(f"    Size: {len(entry.data)} bytes")

            value = entry.decoded_value()
            if isinstance(value, DecodedTable):
                self._dump_table(value)
            elif isinstance(value, EsifVariant):
                print(f"    Variant: {value.type_str} = {value.display()}")
            elif isinstance(value, list) and all(isinstance(v, EsifVariant) for v in value):
                print("    Variants:")
                for vidx, variant in enumerate(value):
                    print(f"      [{vidx}] {variant.type_str}: {variant.display()}")
            elif isinstance(value, bytes):
                if len(value) <= 64:
                    print(f"    Value: {value.hex()}")
                else:
                    print(f"    Value: {value[:64].hex()}... (truncated)")
            else:
                text = str(value)
                if len(text) > 200:
                    text = text[:200] + "..."
                print(f"    Value: {text}")
            print()

    def _dump_table(self, table: DecodedTable) -> None:
        print(
            f"    Table: {table.kind.upper()} "
            f"(revision={table.revision.display()}, rows={len(table.rows)})"
        )
        if table.trailing:
            print(f"      Warning: {len(table.trailing)} trailing variant(s)")
        for row_idx, row in enumerate(table.rows):
            prefix = f"Row{row_idx}." if len(table.rows) > 1 else ""
            for field_idx, variant in enumerate(row):
                field_name = table.field_names[field_idx]
                print(f"      {prefix}{field_name}: {variant.display(field_name)}")

    def dump_csv(self) -> None:
        writer = csv.writer(sys.stdout)
        writer.writerow(["key", "type", "flags", "size", "value"])
        for entry in self.entries:
            writer.writerow(
                [entry.key, entry.type_str, entry.flags, len(entry.data), value_to_jsonable(entry.decoded_value())]
            )

    def dump_json(self) -> None:
        print(json.dumps(self.to_jsonable(), indent=2))

    def to_jsonable(self) -> dict:
        return {
            "segments": [
                {
                    "segment_id": segment.segment_id,
                    "comment": segment.comment,
                    "version": segment.version,
                    "flags": segment.flags,
                    "payload_class": payload_class_name(segment.payload_class),
                    "payload_size": segment.payload_size,
                    "hash_valid": segment.hash_valid,
                }
                for segment in self.segments
            ],
            "entries": [
                {
                    "key": entry.key,
                    "type": entry.type_str,
                    "type_id": entry.data_type,
                    "flags": entry.flags,
                    "size": len(entry.data),
                    "value": value_to_jsonable(entry.decoded_value()),
                }
                for entry in self.entries
            ],
        }

    def dump(self, output_format: str = "text") -> None:
        if output_format == "text":
            self.dump_text()
        elif output_format == "csv":
            self.dump_csv()
        elif output_format == "json":
            self.dump_json()
        elif output_format == "xml":
            sys.stdout.buffer.write(xml_to_bytes(parser_to_xml(self)))
            sys.stdout.buffer.write(b"\n")
        else:
            raise ValueError(f"unsupported format: {output_format}")


def value_to_jsonable(value: Any) -> Any:
    if isinstance(value, DecodedTable):
        return {
            "kind": value.kind,
            "revision": value.revision.as_text(),
            "rows": [
                {
                    field_name: variant.display(field_name)
                    for field_name, variant in zip(value.field_names, row)
                }
                for row in value.rows
            ],
            "trailing": [variant.display() for variant in value.trailing],
        }
    if isinstance(value, EsifVariant):
        return {"type": value.type_str, "value": value.display()}
    if isinstance(value, list):
        return [value_to_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return value


def parse_file(path: str, verbose: bool = False) -> DataVaultParser:
    dv = DataVaultParser(verbose=verbose)
    dv.parse_file(path)
    return dv


def dump_files(paths: Iterable[str], output_format: str, verbose: bool) -> int:
    status = 0
    for path in paths:
        if not os.path.exists(path):
            print(f"Error: File not found: {path}", file=sys.stderr)
            status = 1
            continue

        if output_format == "text":
            print(f"\n{'=' * 80}")
            print(f"Parsing: {path}")
            print(f"{'=' * 80}")
        try:
            dv = parse_file(path, verbose=verbose)
            dv.dump(output_format)
        except Exception as exc:
            print(f"Error parsing {path}: {exc}", file=sys.stderr)
            status = 1
    return status


def int_attr(element: ET.Element, name: str, default: Optional[int] = None) -> int:
    value = element.get(name)
    if value is None:
        if default is None:
            raise ValueError(f"missing XML attribute {name}")
        return default
    return int(value, 0)


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def variant_to_xml(parent: ET.Element, tag: str, variant: EsifVariant, index: int,
                   field_name: Optional[str] = None) -> ET.Element:
    attrs = {
        "index": str(index),
        "type": variant.type_str,
        "type_id": str(variant.type_id),
    }
    if field_name:
        attrs["name"] = field_name

    if variant.is_integer:
        attrs["value"] = str(variant.value)
        display = variant.display(field_name)
        if display != str(variant.value):
            attrs["display"] = display
        if field_name and "Temp" in field_name and variant.value not in (MAX_U32, MAX_U64):
            attrs["celsius"] = f"{dkelvin_to_celsius(variant.value):.2f}"
    elif variant.type_id in (EsifDataType.STRING, EsifDataType.UNICODE):
        attrs["value"] = variant.as_text()
        attrs["reserved"] = str(variant.reserved)
    elif variant.type_id == EsifDataType.GUID:
        attrs["value"] = variant.as_text()
        attrs["reserved"] = str(variant.reserved)
    else:
        attrs["encoding"] = "base64"
        attrs["reserved"] = str(variant.reserved)

    element = ET.SubElement(parent, tag, attrs)
    if attrs.get("encoding") == "base64":
        element.text = base64.b64encode(variant.value).decode("ascii")
    return element


def table_to_xml(parent: ET.Element, table: DecodedTable) -> ET.Element:
    table_el = ET.SubElement(
        parent,
        "table",
        {
            "kind": table.kind,
            "revision": table.revision.as_text(),
            "revision_type": table.revision.type_str,
            "revision_type_id": str(table.revision.type_id),
            "rows": str(len(table.rows)),
        },
    )
    for row_idx, row in enumerate(table.rows):
        row_el = ET.SubElement(table_el, "row", {"index": str(row_idx)})
        for field_idx, variant in enumerate(row):
            variant_to_xml(row_el, "field", variant, field_idx, table.field_names[field_idx])
    if table.trailing:
        trailing_el = ET.SubElement(table_el, "trailing")
        for idx, variant in enumerate(table.trailing):
            variant_to_xml(trailing_el, "variant", variant, idx)
    return table_el


def parser_to_xml(dv: DataVaultParser) -> ET.ElementTree:
    root = ET.Element("datavault", {"format": "intel-dptf-dv", "version": "1"})
    for segment_idx, segment in enumerate(dv.segments):
        segment_el = ET.SubElement(
            root,
            "segment",
            {
                "index": str(segment_idx),
                "signature": f"0x{segment.signature:04x}",
                "header_size": str(segment.header_size),
                "version": f"0x{segment.version:08x}",
                "flags": f"0x{segment.flags:08x}",
                "segment_id": segment.segment_id,
                "comment": segment.comment,
                "payload_class": payload_class_name(segment.payload_class),
                "payload_class_id": f"0x{segment.payload_class:08x}",
                "payload_size": str(segment.payload_size),
                "hash_valid": bool_text(segment.hash_valid),
            },
        )
        for entry_idx, entry in enumerate(segment.entries):
            entry_el = ET.SubElement(
                segment_el,
                "entry",
                {
                    "index": str(entry_idx),
                    "key": entry.key,
                    "type": entry.type_str,
                    "type_id": str(entry.data_type),
                    "flags": str(entry.flags),
                    "size": str(len(entry.data)),
                },
            )
            raw_el = ET.SubElement(entry_el, "raw", {"encoding": "base64"})
            raw_el.text = base64.b64encode(entry.data).decode("ascii")

            table = entry.decode_table()
            if table is not None:
                table_to_xml(entry_el, table)
                continue

            variants = entry.decode_variants()
            if variants:
                variants_el = ET.SubElement(entry_el, "variants")
                for variant_idx, variant in enumerate(variants):
                    variant_to_xml(variants_el, "variant", variant, variant_idx)
    return ET.ElementTree(root)


def xml_to_bytes(tree: ET.ElementTree) -> bytes:
    if hasattr(ET, "indent"):
        ET.indent(tree, space="  ")
    return ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=True)


def parse_guid_text(value: str) -> bytes:
    parts = value.split("-")
    if len(parts) != 5:
        raise ValueError(f"invalid GUID {value}")
    raw_hex = "".join(parts)
    if len(raw_hex) != 32:
        raise ValueError(f"invalid GUID {value}")
    d = bytes.fromhex(raw_hex)
    return bytes([d[3], d[2], d[1], d[0], d[5], d[4], d[7], d[6]]) + d[8:]


def variant_from_xml(element: ET.Element) -> EsifVariant:
    type_id = int_attr(element, "type_id")
    reserved = int_attr(element, "reserved", 0)
    try:
        data_type = EsifDataType(type_id)
    except ValueError as exc:
        raise ValueError(f"unknown XML variant type_id {type_id}") from exc

    if data_type in INTEGER_VARIANT_TYPES:
        return EsifVariant(type_id, int_attr(element, "value"), reserved=reserved)

    if data_type == EsifDataType.STRING:
        value = element.get("value", "").encode("utf-8") + b"\x00"
        return EsifVariant(type_id, value, reserved=reserved)
    if data_type == EsifDataType.UNICODE:
        value = element.get("value", "").encode("utf-16-le") + b"\x00\x00"
        return EsifVariant(type_id, value, reserved=reserved)
    if data_type == EsifDataType.GUID:
        return EsifVariant(type_id, parse_guid_text(element.get("value", "")), reserved=reserved)

    text = element.text or ""
    return EsifVariant(type_id, base64.b64decode(text.encode("ascii")), reserved=reserved)


def table_from_xml(element: ET.Element) -> DecodedTable:
    kind = element.get("kind", "")
    if kind == "psvt":
        field_names = PSVT_FIELDS
    elif kind == "ppcc":
        field_names = PPCC_FIELDS_PER_ROW
    else:
        raise ValueError(f"unknown table kind {kind}")

    revision = EsifVariant(int_attr(element, "revision_type_id", EsifDataType.UINT64),
                           int_attr(element, "revision"))
    rows: List[List[EsifVariant]] = []
    for row_el in element.findall("row"):
        fields = [variant_from_xml(field_el) for field_el in row_el.findall("field")]
        if len(fields) != len(field_names):
            raise ValueError(f"{kind} row has {len(fields)} field(s), expected {len(field_names)}")
        rows.append(fields)

    trailing: List[EsifVariant] = []
    trailing_el = element.find("trailing")
    if trailing_el is not None:
        trailing = [variant_from_xml(variant_el) for variant_el in trailing_el.findall("variant")]
    return DecodedTable(kind, revision, rows, list(field_names), trailing)


def entry_data_from_xml(element: ET.Element) -> bytes:
    table_el = element.find("table")
    if table_el is not None:
        return table_from_xml(table_el).encode()

    raw_el = element.find("raw")
    if raw_el is None or raw_el.text is None:
        raise ValueError(f"entry {element.get('key')} has neither table nor raw data")
    return base64.b64decode(raw_el.text.encode("ascii"))


def parser_from_xml(path: str) -> DataVaultParser:
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "datavault":
        raise ValueError("XML root must be <datavault>")

    dv = DataVaultParser()
    for segment_el in root.findall("segment"):
        entries: List[KeyValueEntry] = []
        for entry_el in segment_el.findall("entry"):
            entries.append(
                KeyValueEntry(
                    key=entry_el.get("key", ""),
                    data_type=int_attr(entry_el, "type_id"),
                    flags=int_attr(entry_el, "flags", 0),
                    data=entry_data_from_xml(entry_el),
                )
            )
        raw_payload = b"".join(entry.encode() for entry in entries)
        payload_hash = hashlib.sha256(raw_payload).digest()
        segment = DataVaultSegment(
            signature=int_attr(segment_el, "signature", ESIFDV_SIGNATURE),
            header_size=int_attr(segment_el, "header_size", ESIFDV_HEADER_V2_MIN_SIZE),
            version=int_attr(segment_el, "version"),
            flags=int_attr(segment_el, "flags", 0),
            segment_id=segment_el.get("segment_id", ""),
            comment=segment_el.get("comment", ""),
            payload_hash=payload_hash,
            payload_size=len(raw_payload),
            payload_class=int_attr(segment_el, "payload_class_id", PayloadClass.KEYS),
            entries=entries,
            raw_payload=raw_payload,
        )
        dv.segments.append(segment)
        dv.entries.extend(entries)
    return dv


def write_binary(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def command_dump_xml(args: argparse.Namespace) -> int:
    dv = parse_file(args.input, verbose=args.verbose)
    data = xml_to_bytes(parser_to_xml(dv))
    if args.output == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.write(b"\n")
    else:
        write_binary(args.output, data)
    return 0


def command_build_xml(args: argparse.Namespace) -> int:
    dv = parser_from_xml(args.input)
    write_binary(args.output, dv.encode())
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse and edit Intel DPTF DataVault (.dv) files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ../dptf.dv
  %(prog)s -f json ../dptf.dv
  %(prog)s dump-xml ../dptf.dv dptf.xml
  %(prog)s build-xml dptf.xml dptf.dv
""",
    )
    subparsers = parser.add_subparsers(dest="command")

    dump = subparsers.add_parser("dump", help="dump one or more DV files")
    dump.add_argument("files", nargs="+", help="DataVault file(s) to parse")
    dump.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    dump.add_argument(
        "-f",
        "--format",
        choices=["text", "csv", "json", "xml"],
        default="text",
        help="Output format (default: text)",
    )

    dump_xml = subparsers.add_parser("dump-xml", help="dump a DV file as editable XML")
    dump_xml.add_argument("input", help="input DataVault file")
    dump_xml.add_argument("output", nargs="?", default="-", help="output XML file, or '-' for stdout")
    dump_xml.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    dump_xml.set_defaults(func=command_dump_xml)

    build_xml = subparsers.add_parser("build-xml", help="build a DV file from XML")
    build_xml.add_argument("input", help="input XML file")
    build_xml.add_argument("output", help="output DataVault file")
    build_xml.set_defaults(func=command_build_xml)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # Preserve the original command line shape: dv_parser.py [-f json] file.dv
    if argv and argv[0] not in ("dump", "dump-xml", "build-xml", "-h", "--help"):
        legacy = argparse.ArgumentParser(description="Parse Intel DPTF DataVault (.dv) files")
        legacy.add_argument("files", nargs="+", help="DataVault file(s) to parse")
        legacy.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        legacy.add_argument(
            "-f",
            "--format",
            choices=["text", "csv", "json", "xml"],
            default="text",
            help="Output format (default: text)",
        )
        args = legacy.parse_args(argv)
        return dump_files(args.files, args.format, args.verbose)

    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.command == "dump":
        return dump_files(args.files, args.format, args.verbose)
    if hasattr(args, "func"):
        return args.func(args)
    parser.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
