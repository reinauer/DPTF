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
from enum import IntEnum
from dataclasses import dataclass
from typing import List, Optional, Tuple, BinaryIO

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


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse Intel DPTF DataVault (.dv) files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s DPTF.dv
  %(prog)s -v -f json dsp.dv
  %(prog)s -f csv *.dv > output.csv
"""
    )
    parser.add_argument('files', nargs='+', help='DataVault file(s) to parse')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-f', '--format', choices=['text', 'csv', 'json'], 
                        default='text', help='Output format (default: text)')
    
    args = parser.parse_args()
    
    for filepath in args.files:
        if not os.path.exists(filepath):
            print(f"Error: File not found: {filepath}")
            continue
            
        print(f"\n{'='*80}")
        print(f"Parsing: {filepath}")
        print(f"{'='*80}")
        
        dv_parser = DataVaultParser(verbose=args.verbose)
        if dv_parser.parse_file(filepath):
            dv_parser.dump(args.format)
        else:
            print(f"Failed to parse {filepath}")


if __name__ == '__main__':
    main()
