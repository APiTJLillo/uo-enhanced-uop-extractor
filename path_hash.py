import os
import json
from typing import Dict

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

def hash_filename(filename: str) -> int:
    """Calculate the hash value for a given filename."""
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

def load_hash_mappings() -> Dict[int, str]:
    """Load filename hash mappings from JSON file."""
    try:
        with open('hash_mappings.json', 'r') as f:
            return {int(k): v for k, v in json.load(f).items()}
    except (IOError, json.JSONDecodeError):
        return {}

def save_hash_mappings(mappings: Dict[int, str]) -> None:
    """Save filename hash mappings to JSON file."""
    serializable = {str(k): v for k, v in mappings.items()}
    with open('hash_mappings.json', 'w') as f:
        json.dump(serializable, f, indent=2)
