#!/usr/bin/env python3
import os
import sys
import struct
import zlib
import time
import math
import shutil
import re
import json
import xml.etree.ElementTree as ET
import argparse
import hashlib
import requests
import zipfile
from pathlib import Path
from typing import BinaryIO, Dict, Tuple, Counter as CounterType, TextIO, Set, Optional, List
from collections import Counter
from io import BytesIO

# Debug flag for additional output
DEBUG = False

# Configuration
TRID_DEFS_DIR = "trid_definitions"

TRID_DEFS_URL = "https://mark0.net/download/triddefs.zip"
# Known directory/extension hash patterns
PATH_PREFIXES = {
    # Full path prefixes that override other patterns
    'Icons/actions/': 0xe3f14624915fd9bc,
    # Directory prefixes
    'Source/': 0x5f3646d330776926,
    'Textures/': 0x9c41a3df40df6e04,
    'Fonts/': 0x882077226ba49817,
}

# Extension influence on high bits
EXT_HIGH_BITS = {
    '.xml': 0xe294,  # High 16 bits for .xml files
    '.lua': 0xe54f,  # High 16 bits for .lua files
    '.ttf': 0x6977,  # High 16 bits for .ttf files
    '.dds': 0x9c41,  # High 16 bits for .dds files
}
# File type definitions mapping magic bytes/content patterns to (directory, extension)
FILE_TYPES: Dict[bytes, Tuple[str, str]] = {
    b'<?xml': ('Source', 'xml'),
    b'<Interface': ('Source', 'xml'),
    b'LuaQ': ('Source', 'lua'),
    b'--[[': ('Source', 'lua'),
    b'-- ': ('Source', 'lua'),
    b'--\n': ('Source', 'lua'),
    b'--\r\n': ('Source', 'lua'),
    b'function ': ('Source', 'lua'),
    b'local ': ('Source', 'lua'),
    b'PNG': ('Images', 'png'),
    b'DDS ': ('Textures', 'dds'),
    b'OTTO': ('Fonts', 'otf'),
}

# Binary format definitions mapping magic bytes to (directory, extension)
BINARY_TYPES: Dict[bytes, Tuple[str, str]] = {
    bytes([0xD0, 0xCF, 0x11, 0xE0]): ('Compound', 'cfb'),
    bytes([0xFF, 0xD8, 0xFF, 0xE0]): ('Images', 'jpg'),
}

# Font table names to detect TTF/OTF fonts
FONT_TABLES = [b'DSIG', b'LTSH', b'GDEF', b'GPOS', b'OS/2']

class ProgressBar:
    def __init__(self, target: TextIO = sys.stdout):
        self._target = target
        self._text_only = not self._target.isatty()
        self._update_width()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.update(1.0)
        if not self._text_only:
            self._target.write('\n')
        self._target.flush()

    def _update_width(self):
        self._width, _ = shutil.get_terminal_size((80, 20))

    def update(self, progress: float):
        self._update_width()
        if self._width < 12:
            percent_str = ''
            progress_bar_str = self.progress_bar_str(progress, self._width - 2)
        elif self._width < 40:
            percent_str = "{:6.2f} %".format(progress * 100)
            progress_bar_str = self.progress_bar_str(progress, self._width - 11) + ' '
        else:
            percent_str = "{:6.2f} %".format(progress * 100) + "  "
            progress_bar_str = " " * 5 + self.progress_bar_str(progress, self._width - 21)
        
        if self._text_only:
            self._target.write(progress_bar_str + percent_str + '\n')
        else:
            self._target.write('\033[G' + progress_bar_str + percent_str)
        self._target.flush()

    @staticmethod
    def progress_bar_str(progress: float, width: int):
        progress = min(1, max(0, progress))
        whole_width = math.floor(progress * width)
        remainder_width = (progress * width) % 1
        part_width = math.floor(remainder_width * 8)
        part_char = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"][part_width]
        if (width - whole_width - 1) < 0:
            part_char = ""
        line = "[" + "█" * whole_width + part_char + " " * (width - whole_width - 1) + "]"
        return line

class TrIDAnalyzer:
    def __init__(self):
        self.definitions = self.load_trid_definitions()
        
    def load_trid_definitions(self) -> List[Dict]:
        definitions = []
        defs_path = Path(TRID_DEFS_DIR)
        
        if not defs_path.exists():
            self.update_trid_definitions()
            
        for xml_file in defs_path.glob("*.trid.xml"):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                info = root.find("Info")
                definitions.append({
                    "file_type": info.find("FileType").text,
                    "extension": info.find("Ext").text,
                    "patterns": [
                        {
                            "offset": int(pattern.attrib["offset"]),
                            "value": bytes.fromhex(pattern.text.strip())
                        }
                        for pattern in root.findall("FrontBlock/Pattern")
                    ]
                })
            except (ET.ParseError, ValueError) as e:
                if DEBUG:
                    print(f"Error parsing {xml_file}: {str(e)}")
        return definitions
    
    def update_trid_definitions(self) -> None:
        print("Updating TrID definitions...")
        response = requests.get(TRID_DEFS_URL)
        response.raise_for_status()
        
        Path(TRID_DEFS_DIR).mkdir(exist_ok=True)
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            z.extractall(TRID_DEFS_DIR)
        
        # Convert binary definitions to XML
        self.convert_trid_defs_to_xml()
        
        print(f"Updated TrID definitions in {TRID_DEFS_DIR}")
        
    def convert_trid_defs_to_xml(self) -> None:
        """Convert binary TrID definitions to XML format."""
        trd_path = Path(TRID_DEFS_DIR) / "triddefs.trd"
        if not trd_path.exists():
            return
            
        try:
            with open(trd_path, 'rb') as f:
                while True:
                    try:
                        # Read definition header
                        name_len = int.from_bytes(f.read(1), byteorder='little')
                        if not name_len:  # End of file
                            break
                            
                        ext_len = int.from_bytes(f.read(1), byteorder='little')
                        mime_len = int.from_bytes(f.read(1), byteorder='little')
                        
                        # Read strings
                        file_type = f.read(name_len).decode('utf-8')
                        ext = f.read(ext_len).decode('utf-8') if ext_len else ""
                        mime = f.read(mime_len).decode('utf-8') if mime_len else ""
                        
                        # Read patterns
                        pattern_count = int.from_bytes(f.read(2), byteorder='little')
                        patterns = []
                        
                        for _ in range(pattern_count):
                            offset = int.from_bytes(f.read(4), byteorder='little')
                            pattern_len = int.from_bytes(f.read(1), byteorder='little')
                            pattern = f.read(pattern_len)
                            patterns.append((offset, pattern))
                        
                        # Create XML definition
                        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
                            <TrID>
                                <Info>
                                    <FileType>{file_type}</FileType>
                                    <Ext>{ext}</Ext>
                                    <MIME>{mime}</MIME>
                                </Info>
                                <FrontBlock>
                                    {''.join(f'<Pattern offset="{offset}">{pattern.hex()}</Pattern>' for offset, pattern in patterns)}
                                </FrontBlock>
                            </TrID>"""
                        
                        # Save XML file
                        xml_path = Path(TRID_DEFS_DIR) / f"{file_type.replace('/', '_').replace(' ', '_')}.trid.xml"
                        with open(xml_path, 'w', encoding='utf-8') as xml_file:
                            xml_file.write(xml_content)
                            
                    except (EOFError, UnicodeDecodeError):
                        break  # End of file or corrupted entry
                        
        except Exception as e:
            if DEBUG:
                print(f"Error converting TrID definitions: {e}")

    def identify_file(self, data: bytes) -> Optional[Dict]:
        for defn in self.definitions:
            match = True
            for pattern in defn["patterns"]:
                offset = pattern["offset"]
                value = pattern["value"]
                
                if offset + len(value) > len(data):
                    match = False
                    break
                
                if data[offset:offset+len(value)] != value:
                    match = False
                    break
            
            if match:
                if DEBUG:
                    print(f"TrID identified file type: {defn['file_type']}")
                return {
                    "file_type": defn["file_type"],
                    "extension": defn["extension"],
                    "confidence": 100.0
                }
        return None

TRID = TrIDAnalyzer()

def read_int(f: BinaryIO) -> int:
    return struct.unpack('<I', f.read(4))[0]

def read_long(f: BinaryIO) -> int:
    return struct.unpack('<Q', f.read(8))[0]

def read_short(f: BinaryIO) -> int:
    return struct.unpack('<H', f.read(2))[0]

def normalize_path(path: str) -> str:
    path = path.replace('\\', '/')
    while '../' in path:
        path = re.sub(r'[^/]+/\.\./','', path)
    path = path.replace('./', '')
    path = re.sub(r'^Data/Interface/','', path)
    return path

def extract_file_paths(data: bytes) -> list[str]:
    paths: list[str] = []
    try:
        text = data.decode('utf-8', 'ignore')
        patterns = [
            r'(?:file|source|path|src|texture|font|image|script|background|icon)="([^"]+)"',
            r'(?:[A-Za-z0-9_-]+[\\/])+[A-Za-z0-9_.-]+',
            r'<!--.*?(?:file|path):\s*([^\s<>]+).*?-->',
            r'(?:Source|Textures|Fonts|Scripts|Interface)/[A-Za-z0-9_.-]+',
            r'target="([^"]+)"',
            r'value="([^"]+\.(?:xml|lua|ttf|dds))"'
        ]
        
        for pattern in patterns:
            if '"' in pattern:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                paths.extend(match.group(1) for match in matches)
            else:
                paths.extend(re.findall(pattern, text))
        
        cleaned = [normalize_path(p) for p in paths if p and not p.isspace()]
        return list(set(cleaned))
    except Exception as e:
        if DEBUG:
            print(f"Error extracting paths: {e}")
        return []

def try_derive_path(content: bytes, ext: str, filename_hash: int) -> Optional[str]:
    try:
        if ext == 'txt':
            text = content.decode('utf-8', 'ignore')
            paths = [line.strip() for line in text.splitlines() if line.strip()]
            paths = [p.replace('Data\\Interface\\', '').replace('\\', '/') for p in paths]
            for path in paths:
                if path.lower().endswith(('.lua', '.xml', '.dds')):
                    # Normalize directory case before hashing
                    parts = path.split('/')
                    if len(parts) > 1:
                        parts[0] = parts[0].title()  # Capitalize first directory
                        path = '/'.join(parts)
                    computed_hash = hash_filename(path)
                    if computed_hash == filename_hash:
                        return path
        
        elif ext == 'lua':
            text = content.decode('utf-8', 'ignore')
            lines = text.splitlines()
            for line in lines:
                if not line.startswith('--'):
                    if ' = {' in line or 'function ' in line:
                        name = line.split('=')[0].strip() if '=' in line else line.split('.')[0].replace('function ', '').strip()
                        paths = [
                            f"Source/{name}.lua",
                            f"Source/Generic/{name}.lua",
                            f"UO_ChatWindow/Source/{name}.lua"
                        ]
                        for path in paths:
                            computed_hash = hash_filename(path)
                            if computed_hash == filename_hash:
                                return path
                        break

        elif ext == 'xml':
            text = content.decode('utf-8', 'ignore')
            if '<Interface' in text:
                for line in text.splitlines():
                    if 'name=' in line.lower():
                        match = re.search(r'name="([^"]+)"', line, re.IGNORECASE)
                        if match:
                            name = match.group(1)
                            paths = [
                                f"Source/{name}.xml",
                                f"Source/Generic/{name}.xml",
                                f"UO_ChatWindow/Source/{name}.xml"
                            ]
                            # Try more specific paths for fonts and interfaces
                            if 'font' in name.lower():
                                paths.insert(0, f"Fonts/{name}.xml")
                            elif 'interface' in name.lower():
                                paths.insert(0, f"Interface/{name}.xml")
                            for path in paths:
                                computed_hash = hash_filename(path)
                                if computed_hash == filename_hash:
                                    return path
    except Exception as e:
        if DEBUG:
            print(f"Error deriving path: {e}")
    return None

def load_hash_mappings() -> Dict[int, str]:
    try:
        with open('hash_mappings.json', 'r') as f:
            return {int(k): v for k, v in json.load(f).items()}
    except (IOError, json.JSONDecodeError):
        return {}

def save_hash_mappings(mappings: Dict[int, str]) -> None:
    serializable = {str(k): v for k, v in mappings.items()}
    with open('hash_mappings.json', 'w') as f:
        json.dump(serializable, f, indent=2)

def find_matching_default_file(data: bytes, ext: str, filename_hash: int, hash_mappings: Dict[int, str], block_id: int, file_id: int) -> Optional[str]:
    default_dir = "Default"
    if not os.path.exists(default_dir):
        return None
        
    for root, _, files in os.walk(default_dir):
        for filename in files:
            # Special debug for 12.93.txt
            # Block 12, file 93 would be 12*256 + 93 = 3165
            if block_id == 12 and file_id == 93:
                print(f"\nDEBUG: Checking {filename} for 12.93.txt match")
                print(f"Filename hash: 0x{filename_hash:016x}")
            
            if ext == 'txt' and not any(filename.endswith(e) for e in ['.lua', '.xml']):
                continue
            elif ext != 'txt' and not filename.endswith(f".{ext}"):
                continue
            
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    # More debug for 12.93.txt
                    if block_id == 12 and file_id == 93:
                        print(f"Comparing with {file_path}")
                        if file_data == data:
                            print("CONTENT MATCHES!")
                        else:
                            print("Content differs")
                    
                    if file_data == data:
                        rel_path = os.path.relpath(file_path, default_dir)
                        hash_mappings[filename_hash] = rel_path
                        save_hash_mappings(hash_mappings)
                        if DEBUG:
                            print(f"Found new hash mapping: 0x{filename_hash:016x} -> {rel_path}")
                        return rel_path
            except (IOError, OSError) as e:
                if DEBUG:
                    print(f"Error reading {file_path}: {e}")
                continue
    
    return None

def detect_file_type(data: bytes) -> Tuple[str, str, str, list[str]]:
    # Try content-based detection first since we trust it more
    try:
        # XML detection
        preview = data[:1000].decode('utf-8', 'ignore')
        if '<?xml' in preview or '<Interface' in preview:
            paths = extract_file_paths(data)
            if 'font' in preview.lower() or any('font' in p.lower() for p in paths):
                return 'Fonts', 'xml', "XML font config detected", paths
            elif any(marker in preview.lower() for marker in ['<interface', '<ea_contextmenu']):
                dir_name = 'Interface'
                for path in preview.splitlines():
                    if 'ea_contextmenu' in path.lower():
                        dir_name = 'EA_ContextMenu'
                        break
                return dir_name, 'xml', "XML interface definition", paths
            return 'Source', 'xml', "XML content detected", paths

        # Lua script detection
        if any(pattern in preview for pattern in [
            'function', 'local', '--[[', '-- ', 'if', 'then', 'end', 'return'
        ]):
            paths = extract_file_paths(data)
            return 'Source', 'lua', "Lua content detected", paths
            
        # Generic text detection
        if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in preview):
            paths = extract_file_paths(data)
            if '<' in preview and '>' in preview:
                return 'Source', 'xml', "XML-like content detected", paths
            if '--' in preview or 'function' in preview:
                return 'Source', 'lua', "Lua-like content detected", paths
            return 'Text/plain', 'txt', "Text content detected", paths
    except UnicodeDecodeError:
        pass

    # Binary format detection
    for magic, (dir_name, ext) in BINARY_TYPES.items():
        if data.startswith(magic):
            return dir_name, ext, f"Binary format: {magic!r}", []

    # Font file detection (more reliable than TrID)
    if any(table in data[:64] for table in FONT_TABLES):
        tables = [t.decode() for t in FONT_TABLES if t in data[:64]]
        return 'Fonts', 'ttf', f"Font tables: {','.join(tables)}", []

    # Try TrID identification for remaining files
    trid_result = TRID.identify_file(data)
    if trid_result:
        type_parts = trid_result['file_type'].split('/')
        if DEBUG:
            print(f"TrID identified file type: {trid_result['file_type']}")

        # Map TrID types to our directory structure
        if any('Font' in part for part in type_parts):
            dir_path = 'Fonts'
        elif any(x in type_parts[0] for x in ['Icon', 'Button']):
            dir_path = 'Icons'
        elif 'Texture' in type_parts[0] or 'Image' in type_parts[0]:
            dir_path = 'Textures'
        elif 'Binary' in type_parts[0]:
            dir_path = 'Data'
        else:
            dir_path = type_parts[0].title()

        return (
            dir_path,
            trid_result['extension'].lower(),
            f"TrID: {trid_result['file_type']}",
            []
        )
    
    # Default to binary data
    file_hash = hashlib.sha256(data).hexdigest()
    return 'Data', 'bin', f"Unknown binary data (SHA-256: {file_hash})", []

def extract_uop(uop_path: str, output_dir: str) -> Tuple[CounterType[str], Set[int], str]:
    hash_mappings = load_hash_mappings()
    content_hashes: Dict[str, str] = {}
    os.makedirs(output_dir, exist_ok=True)
    
    extension_counts: CounterType[str] = Counter[str]()
    seen_hashes: Set[int] = set()
    hash_log_path = os.path.join(output_dir, "hashes.txt")
    
    with open(uop_path, 'rb') as f, open(hash_log_path, 'w') as hash_log:
        if f.read(4) != b'MYP\0':
            print("Error: Not a valid UOP file")
            return Counter(), set(), "Error: Not a valid UOP file"

        version = read_int(f)
        misc = read_int(f)
        block_offset = read_long(f)
        max_files_per_block = read_int(f)
        file_count = read_int(f)

        print(f"Version: {version}")
        print(f"Files per block: {max_files_per_block}")
        print(f"Total files: {file_count}")
        print("Extracting")

        f.seek(block_offset)
        
        block_id = 0
        files_processed = 0
        last_progress = time.time()

        with ProgressBar() as progress:
            while True:
                count = read_int(f)
                next_block = read_long(f)
                
                for file_id in range(count):
                    now = time.time()
                    if now - last_progress >= 0.1:
                        progress.update(files_processed / file_count)
                        last_progress = now
                    
                    try:
                        data = f.read(8)
                        if len(data) < 8:
                            break
                        data_offset = struct.unpack('<Q', data)[0]
                        
                        header_size = read_int(f)
                        compressed_size = read_int(f)
                        decompressed_size = read_int(f)
                        filename_hash = read_long(f)
                        header_hash = read_int(f)
                        compressed = read_short(f) > 0
                        
                        current_pos = f.tell()
                    except struct.error:
                        break
                    
                    if (header_size > 1024*1024 or
                        compressed_size > 100*1024*1024 or
                        decompressed_size > 100*1024*1024 or
                        data_offset > os.path.getsize(uop_path)):
                        # print(f"Warning: Invalid header values for file {block_id}.{file_id}")
                        continue

                    file_data = None
                    try:
                        if data_offset > 0:
                            f.seek(data_offset)
                            
                            if header_size > 0:
                                header = f.read(header_size)
                                
                            data = f.read(compressed_size)
                            if compressed:
                                try:
                                    file_data = zlib.decompress(data)
                                except zlib.error as e:
                                    print(f"Warning: Failed to decompress file {block_id}.{file_id}: {e}")
                                    continue
                            else:
                                file_data = data
                        else:
                            continue
                    except (ValueError, OSError) as e:
                        print(f"Warning: Failed to read file {block_id}.{file_id}: {e}")
                        continue

                    content_hash = hashlib.sha256(file_data).hexdigest()
                    if content_hash in content_hashes:
                        rel_path = content_hashes[content_hash]
                        # Normalize directory case in reused paths
                        parts = rel_path.split('/')
                        if len(parts) > 1:
                            parts[0] = parts[0].title()  # Capitalize first directory
                            rel_path = '/'.join(parts)
                        output_path = os.path.join(output_dir, rel_path)
                        if DEBUG:
                            print(f"Reused path from content hash: {rel_path}")
                        continue

                    dir_name, ext, content_info, file_paths = detect_file_type(file_data)
                    output_path = None
                    found_match = False
                    rel_path = None

                    for path in file_paths:
                        computed_hash = hash_filename(path)
                        if computed_hash == filename_hash:
                            hash_mappings[filename_hash] = path
                            found_match = True
                            if DEBUG:
                                print(f"Matched path: {path} -> 0x{filename_hash:016x}")
                            break
                        elif DEBUG and path.endswith(('.xml', '.lua', '.ttf', '.dds')):
                            print(f"Near miss for {path}:")
                            print(f"Expected: 0x{filename_hash:016x}")
                            print(f"Got:      0x{computed_hash:016x}")

                    known_path = hash_mappings.get(filename_hash)
                    if known_path:
                        rel_path = known_path
                        output_path = os.path.join(output_dir, rel_path)
                        _, ext = os.path.splitext(rel_path)
                        ext = ext[1:] if ext else ''
                        dir_name = os.path.dirname(rel_path).split('/')[0] if '/' in rel_path else dir_name
                        if DEBUG:
                            print(f"Using known hash mapping: {rel_path}")
                    
                    if not output_path:
                        derived_path = try_derive_path(file_data, ext, filename_hash)
                        if derived_path:
                            rel_path = derived_path
                            output_path = os.path.join(output_dir, rel_path)
                            _, ext = os.path.splitext(rel_path)
                            ext = ext[1:] if ext else ''
                            # Keep full directory path
                            dir_name = os.path.dirname(rel_path)
                            hash_mappings[filename_hash] = rel_path
                            if DEBUG:
                                print(f"Derived path from content: {rel_path}")

                    if not output_path and os.path.exists("Default"):
                        default_match = find_matching_default_file(file_data, ext, filename_hash, hash_mappings, block_id, file_id)
                        if default_match:
                            rel_path = default_match
                            output_path = os.path.join(output_dir, rel_path)
                            _, ext = os.path.splitext(rel_path)
                            ext = ext[1:] if ext else ''
                            dir_name = os.path.dirname(rel_path).split('/')[0] if '/' in rel_path else dir_name
                            if DEBUG:
                                print(f"Matched file contents: {rel_path}")
                    
                    if not output_path and found_match:
                        rel_path = hash_mappings[filename_hash]
                        output_path = os.path.join(output_dir, rel_path)
                        _, ext = os.path.splitext(rel_path)
                        ext = ext[1:] if ext else ''
                        dir_name = os.path.dirname(rel_path).split('/')[0] if '/' in rel_path else dir_name
                    
                    if not output_path:
                        output_path = os.path.join(output_dir, dir_name, f"{block_id}.{file_id}.{ext}")
                    
                    # Use full directory path in counter
                    extension_counts[f"{dir_name or 'root'}/{ext}"] += 1

                    seen_hashes.add(filename_hash)

                    dirname = os.path.dirname(output_path)
                    if dirname:
                        os.makedirs(dirname, exist_ok=True)

                    try:
                        with open(output_path, 'wb') as out:
                            out.write(file_data)
                    except OSError as e:
                        print(f"Warning: Failed to write file {output_path}: {e}")
                        output_path = os.path.join(output_dir, dir_name, f"{block_id}.{file_id}.{ext}")
                        dirname = os.path.dirname(output_path)
                        if dirname:
                            os.makedirs(dirname, exist_ok=True)
                        with open(output_path, 'wb') as out:
                            out.write(file_data)
                    
                    if rel_path:
                        content_hashes[content_hash] = rel_path
                    
                    f.seek(current_pos)
                    files_processed += 1
                
                if next_block == 0:
                    break
                    
                f.seek(next_block)
                block_id += 1

    summary_lines = [
        "\nExtraction complete:",
        f"Found {len(seen_hashes)} unique filename hashes",
        "Hash information written above.",
        "File counts by type/extension:",
    ]

    by_type: Dict[str, CounterType[str]] = {}
    for key, count in sorted(extension_counts.items()):
        parts = key.split('/')
        ext = parts[-1]  # Last part is extension
        dir_name = '/'.join(parts[:-1])  # Everything before is directory path
        
        # Normalize directory names for the summary
        dir_parts = dir_name.split('/')
        if dir_parts:
            dir_parts[0] = dir_parts[0].title()  # Capitalize first part
            dir_name = '/'.join(dir_parts)
        
        if dir_name not in by_type:
            by_type[dir_name] = Counter()
        by_type[dir_name][ext] += count
    
    for dir_name, exts in sorted(by_type.items()):
        summary_lines.append(f"\n{dir_name.upper()}:")
        for ext, count in sorted(exts.items()):
            if ext:
                summary_lines.append(f"  {ext.upper()} files: {count}")
            else:
                summary_lines.append(f"  (no extension): {count}")
    summary_lines.append(f"\nTotal files: {sum(extension_counts.values())}")
    summary = "\n".join(summary_lines)
    
    print(summary)
    
    with open(hash_log_path, 'a') as hash_log:
        hash_log.write("\n" + summary + "\n")
    
    save_hash_mappings(hash_mappings)
    
    return extension_counts, seen_hashes, summary

def hash_filename(filename: str) -> int:
    filename = filename.replace('\\', '/')
    
    for prefix, hash_val in PATH_PREFIXES.items():
        if filename.startswith(prefix):
            return hash_val
    
    path_parts = filename.split('/')
    base_name = path_parts[-1]
    path = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else ""
    name, ext = os.path.splitext(base_name)
    ext = ext.lower()
    
    hash_val = EXT_HIGH_BITS.get(ext, 0)
    hash_val <<= 48
    
    path_bytes = path.encode('ascii')
    path_hash = 0
    for b in path_bytes:
        path_hash = ((path_hash << 5) | (path_hash >> 59)) + b
    path_hash &= 0xFFFFFFFF
    hash_val |= (path_hash & 0xFFFF0000)
    
    name_bytes = name.encode('ascii')
    name_hash = 0
    for b in name_bytes:
        name_hash = ((name_hash << 5) | (name_hash >> 59)) + b
    name_hash &= 0xFFFFFFFF
    hash_val |= (name_hash & 0xFFFF)
    
    return hash_val

def main() -> None:
    parser = argparse.ArgumentParser(description="UOP File Extractor with Enhanced Identification")
    parser.add_argument("uop_file", help="Path to UOP file to extract")
    parser.add_argument("output_dir", help="Directory to extract files to")
    parser.add_argument("--update-trid", action="store_true", 
                      help="Update TrID definitions before extraction")
    parser.add_argument("--debug", action="store_true",
                      help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        global DEBUG
        DEBUG = True

    if args.update_trid:
        TRID.update_trid_definitions()
    
    if not os.path.exists(args.uop_file):
        print(f"Error: File not found: {args.uop_file}")
        sys.exit(1)
        
    extension_counts, seen_hashes, summary = extract_uop(args.uop_file, args.output_dir)

if __name__ == '__main__':
    main()
