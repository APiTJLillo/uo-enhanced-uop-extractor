import os
import hashlib
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, BinaryIO, TYPE_CHECKING
import subprocess
import requests  # type: ignore
import json

# Debug configuration
DEBUG = False
DEBUG_LOG = "debug.log"

def debug_print(msg: str) -> None:
    """Write debug messages to the debug log file"""
    if DEBUG:
        with open(DEBUG_LOG, 'a') as f:
            f.write(f"{msg}\n")

# Configuration
TRID_DEFS_DIR = "trid_definitions"
TRID_DEFS_URL = "https://mark0.net/download/triddefs_xml.7z"

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
                if info is not None:
                    file_type_elem = info.find("FileType")
                    ext_elem = info.find("Ext")
                    if file_type_elem is not None and ext_elem is not None and file_type_elem.text is not None and ext_elem.text is not None:
                        patterns = []
                        for pattern in root.findall("FrontBlock/Pattern"):
                            if pattern.text is not None and pattern.get("offset") is not None:
                                try:
                                    patterns.append({
                                        "offset": int(pattern.get("offset", "0")),
                                        "value": bytes.fromhex(pattern.text.strip())
                                    })
                                except (ValueError, AttributeError):
                                    if DEBUG:
                                        debug_print(f"Error parsing pattern in {xml_file}")
                                    continue
                        
                        definitions.append({
                            "file_type": file_type_elem.text,
                            "extension": ext_elem.text,
                            "patterns": patterns
                        })
            except (ET.ParseError, ValueError) as e:
                if DEBUG:
                    debug_print(f"Error parsing {xml_file}: {str(e)}")
        return definitions
    
    def update_trid_definitions(self) -> None:
        """Download and extract XML TrID definitions"""
        msg = "Updating TrID definitions..."
        debug_print(msg)
        print(msg)
        
        response = requests.get(TRID_DEFS_URL)
        response.raise_for_status()
        
        # Create definitions directory
        Path(TRID_DEFS_DIR).mkdir(exist_ok=True)
        
        # Write the downloaded 7z file
        archive_path = Path(TRID_DEFS_DIR) / "triddefs_xml.7z"
        archive_path.write_bytes(response.content)
        
        # Extract using 7z command line tool
        try:
            subprocess.run(['7z', 'x', str(archive_path), f'-o{TRID_DEFS_DIR}', '-y'], 
                         check=True, capture_output=True)
            msg = f"Updated TrID definitions in {TRID_DEFS_DIR}"
            debug_print(msg)
            print(msg)
        except subprocess.CalledProcessError as e:
            error_msg = f"Error extracting definitions: {e}"
            debug_print(error_msg)
            print(error_msg)
            if e.stderr:
                stderr_msg = f"7z error output: {e.stderr.decode()}"
                debug_print(stderr_msg)
                print(stderr_msg)
        finally:
            # Clean up the downloaded archive
            archive_path.unlink()

    TridResult = Dict[str, Union[str, float]]

    def _create_result(self, file_type: str, extension: str) -> TridResult:
        """Create a properly typed result dictionary."""
        return {
            "file_type": str(file_type or ""),
            "extension": str(extension or ""),
            "confidence": 100.0
        }

    def identify_file(self, data: bytes) -> Optional[TridResult]:
        for defn in self.definitions:
            try:
                file_type = str(defn.get("file_type", ""))
                extension = str(defn.get("extension", ""))
                if not file_type:  # Skip if no file type
                    continue

                match = True
                for pattern in defn.get("patterns", []):
                    offset = int(pattern.get("offset", 0))
                    value = pattern.get("value", b"")
                    if not isinstance(value, bytes):
                        continue

                    if offset + len(value) > len(data):
                        match = False
                        break

                    if data[offset:offset+len(value)] != value:
                        match = False
                        break

                if match:
                    if DEBUG:
                        debug_print(f"TrID identified file type: {file_type}")
                    return self._create_result(file_type, extension)
            except (ValueError, TypeError, AttributeError):
                continue  # Skip malformed entries
        return None

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
            debug_print(f"Error extracting paths: {e}")
        return []

def normalize_path(path: str) -> str:
    path = path.replace('\\', '/')
    while '../' in path:
        path = re.sub(r'[^/]+/\.\./','', path)
    path = path.replace('./', '')
    path = re.sub(r'^Data/Interface/','', path)
    return path

def detect_file_type(data: bytes, trid_analyzer: TrIDAnalyzer) -> Tuple[str, str, str, list[str]]:
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
    trid_result = trid_analyzer.identify_file(data)
    if trid_result:
        file_type = str(trid_result.get('file_type', ''))
        extension = str(trid_result.get('extension', '')).lower()
        
        if file_type:  # Only process if we have a valid file type
            type_parts = [str(p) for p in file_type.split('/')]
            if DEBUG:
                debug_print(f"TrID identified file type: {file_type}")

            # Map TrID types to our directory structure
            if any('Font' in str(part) for part in type_parts):
                dir_path = 'Fonts'
            elif any(x in str(type_parts[0]) for x in ['Icon', 'Button']):
                dir_path = 'Icons'
            elif 'Texture' in str(type_parts[0]) or 'Image' in str(type_parts[0]):
                dir_path = 'Textures'
            elif 'Binary' in str(type_parts[0]):
                dir_path = 'Data'
            else:
                dir_path = str(type_parts[0]).title()

            return (dir_path, extension, f"TrID: {file_type}", [])
    
    # Default to binary data
    file_hash = hashlib.sha256(data).hexdigest()
    return 'Data', 'bin', f"Unknown binary data (SHA-256: {file_hash})", []

# Initialize the TrID analyzer
TRID = TrIDAnalyzer()
