import struct
import zlib
import time
import os
import re
from typing import BinaryIO, Dict, Optional
from path_hash import hash_filename, save_hash_mappings

# Debug configuration
DEBUG = False
DEBUG_LOG = "debug.log"

def clear_debug_log() -> None:
    """Clear the debug log file and write the start marker"""
    with open(DEBUG_LOG, 'w') as f:
        f.write(f"=== Debug Log Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

def debug_print(msg: str) -> None:
    """Write debug messages to the debug log file"""
    if DEBUG:
        with open(DEBUG_LOG, 'a') as f:
            f.write(f"{msg}\n")

def read_int(f: BinaryIO) -> int:
    """Read a 4-byte integer from a binary file."""
    return struct.unpack('<I', f.read(4))[0]

def read_long(f: BinaryIO) -> int:
    """Read an 8-byte long integer from a binary file."""
    return struct.unpack('<Q', f.read(8))[0]

def read_short(f: BinaryIO) -> int:
    """Read a 2-byte short integer from a binary file."""
    return struct.unpack('<H', f.read(2))[0]

def try_derive_path(content: bytes, ext: str, filename_hash: int) -> Optional[str]:
    """Attempt to derive the file path from its content and hash."""
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
            debug_print(f"Error deriving path: {e}")
        return None
    return None

def find_matching_default_file(data: bytes, ext: str, filename_hash: int, hash_mappings: Dict[int, str], block_id: int, file_id: int) -> Optional[str]:
    """Find a matching file in the default directory."""
    default_dir = "Default"
    if not os.path.exists(default_dir):
        return None
        
    for root, _, files in os.walk(default_dir):
        for filename in files:
            # Special debug for 12.93.txt
            # Block 12, file 93 would be 12*256 + 93 = 3165
            if block_id == 12 and file_id == 93:
                debug_print(f"\nDEBUG: Checking {filename} for 12.93.txt match")
                debug_print(f"Filename hash: 0x{filename_hash:016x}")
            
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
                        debug_print(f"Comparing with {file_path}")
                        if file_data == data:
                            debug_print("CONTENT MATCHES!")
                        else:
                            debug_print("Content differs")
                    
                    if file_data == data:
                        rel_path = os.path.relpath(file_path, default_dir)
                        hash_mappings[filename_hash] = rel_path
                        save_hash_mappings(hash_mappings)
                        if DEBUG:
                            debug_print(f"Found new hash mapping: 0x{filename_hash:016x} -> {rel_path}")
                        return rel_path
            except (IOError, OSError) as e:
                if DEBUG:
                    debug_print(f"Error reading {file_path}: {e}")
                continue
    
    return None
