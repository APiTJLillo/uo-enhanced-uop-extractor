import hashlib
from typing import Dict, List, Optional, Tuple
from path_utils import extract_file_paths, extract_lua_global_name
from utils import debug_print

# Known file signatures and their info
FILE_SIGNATURES: Dict[bytes, Tuple[str, str, str]] = {
    # Text formats
    b'<?xml': ('Source', 'xml', "XML content"),
    b'<Interface': ('Source', 'xml', "Interface XML"),
    b'--[[': ('Source', 'lua', "Lua script"),
    b'-- ': ('Source', 'lua', "Lua script"),
    b'--\n': ('Source', 'lua', "Lua script"),
    b'--\r\n': ('Source', 'lua', "Lua script"),
    b'function ': ('Source', 'lua', "Lua script"),
    b'local ': ('Source', 'lua', "Lua script"),
    
    # Binary formats
    bytes([0xD0, 0xCF, 0x11, 0xE0]): ('Compound', 'cfb', "Compound File Binary"),
    bytes([0xFF, 0xD8, 0xFF, 0xE0]): ('Images', 'jpg', "JPEG image"),
    b'DDS |': ('Textures', 'dds', "DirectDraw Surface"),  # More specific DDS header
    b'PNG': ('Images', 'png', "PNG image"),
    b'OTTO': ('Fonts', 'otf', "OpenType Font"),
    bytes([0x00, 0x01, 0x00, 0x00]): ('Fonts', 'ttf', "TrueType Font")  # Common TTF header
}

# Common UI asset extensions that might appear in paths
UI_ASSETS = {
    'dds': 'Textures',    # DirectDraw Surface textures
    'png': 'Images',      # PNG images
    'jpg': 'Images',      # JPEG images
    'ttf': 'Fonts',      # TrueType fonts
    'otf': 'Fonts',      # OpenType fonts
    'lua': 'Source',     # Lua scripts
    'luac': 'Luac',      # Compiled Lua
    'xml': 'Source',     # XML files
}

# Font table names to detect TTF/OTF fonts
FONT_TABLES = [b'DSIG', b'LTSH', b'GDEF', b'GPOS', b'OS/2', b'head', b'name']

class FileTypeDetector:
    def __init__(self, debug: bool = False, debug_log: str = "debug.log") -> None:
        self.debug = debug
        self.debug_log = debug_log

    def detect_file_type(self, data: bytes) -> Tuple[str, str, str, List[str], Optional[str]]:
        """
        Detect the type of file from its content.
        
        Returns:
        - directory: The suggested directory to store the file
        - extension: The detected file extension
        - info: Information about how the type was detected
        - paths: List of file paths found in the content
        - name: Optional name derived from content (e.g., Lua global object name)
        """
        try:
            # Lua bytecode detection
            def check_lua_bytecode(chunk: bytes) -> Optional[str]:
                # Standard headers
                LUA_SIGNATURES = [
                    bytes([0x1B, 0x4C, 0x75, 0x61]),      # Standard Lua (ESC + "Lua")
                    b'LuaQ',                              # LuaQ bytecode
                    b'LuaS',                              # LuaS bytecode
                    b'LuaP',                              # LuaP bytecode
                    bytes([0x1B, 0x4C, 0x4A]),            # LuaJIT (ESC + "LJ")
                    b'LuaXP',                             # LuaPlus
                    b'LuaM',                              # Lua Module
                    bytes([0x1B, 0x4C]) + b'ua',          # Lua with offset
                    bytes([0x1B]) + b'Lua',               # Lua with null
                    b'#!lua\n',                           # Lua script with shebang
                ]
                
                # Version-specific signatures 
                VERSION_SIGNATURES = [
                    bytes([0x1B, 0x4C, 0x75, 0x61, x]) for x in range(0x50, 0x54)  # Lua 5.0-5.3
                ]

                # Common bytecode sequences
                BYTECODE_PATTERNS = [
                    bytes([0x1B]),                        # ESC
                    b'LJ',                               # LuaJIT 2.0
                    b'LUAC',                             # Compiled chunk
                    bytes([0x40, 0x00, 0x00]),           # Common opcode
                    bytes([0x00, 0x01, 0x04]),           # Common header
                    bytes([0x2C, 0x80, 0x46]),          # Custom header pattern
                    bytes([0x2C, 0xF8]),                # Alternative header
                ]

                # Check for repeated byte patterns that may indicate compiled code
                def has_repeating_pattern(data: bytes, length: int = 4) -> bool:
                    if len(data) < length * 3:
                        return False
                    counts: Dict[bytes, int] = {}
                    for i in range(0, len(data) - length):
                        pattern = data[i:i+length]
                        if pattern in counts:
                            counts[pattern] += 1
                            if counts[pattern] > 2:  # Same pattern seen 3+ times
                                return True
                    return False
                
                # Check all signatures
                for sig in LUA_SIGNATURES + VERSION_SIGNATURES:
                    if sig in chunk:
                        return f"Lua signature {sig!r}"
                
                # Check bytecode patterns
                matches = 0
                for pattern in BYTECODE_PATTERNS:
                    if pattern in chunk:
                        matches += 1
                if matches >= 2:  # If we see multiple patterns, it's likely bytecode
                    return f"Lua bytecode patterns ({matches})"
                
                # Check for repeating patterns that may indicate compiled code
                if has_repeating_pattern(chunk):
                    return "Lua bytecode (repeating instruction patterns)"
                
                return None
            
            # Check first 16KB in chunks to handle files with headers/prefixes
            search_size = min(16384, len(data))  # 16KB
            for i in range(0, search_size, 512):
                chunk = data[i:i+512]
                if result := check_lua_bytecode(chunk):
                    paths = extract_file_paths(data)
                    offset_hex = f"0x{i:04x}"
                    return 'Luac', 'luac', f"{result} at offset {offset_hex}", paths, None

            # Secondary bytecode check - look for repeated patterns of valid opcodes
            if len(data) > 1024:
                pattern_count = sum(1 for i in range(0, min(4096, len(data)-2), 2) 
                                  if data[i] in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05] 
                                  and data[i+1] < 0x40)
                if pattern_count > 10:  # If we see lots of valid-looking opcodes
                    paths = extract_file_paths(data)
                    return 'Luac', 'luac', f"Probable Lua bytecode (opcode pattern)", paths, None

            # Try text-based detection
            try:
                preview = data[:1000].decode('utf-8')
            except UnicodeDecodeError:
                preview = data[:1000].decode('utf-8', 'ignore')

            # XML detection (using decoded preview)
            if '<?xml' in preview or '<Interface' in preview:
                paths = extract_file_paths(data)
                if 'font' in preview.lower() or any('font' in p.lower() for p in paths):
                    return 'Fonts', 'xml', "XML font config detected", paths, None
                elif any(marker in preview.lower() for marker in ['<interface', '<ea_contextmenu']):
                    dir_name = 'Source'
                    for line in preview.splitlines():
                        if 'ea_contextmenu' in line.lower():
                            dir_name = 'EA_ContextMenu'
                            break
                    return dir_name, 'xml', "XML interface definition", paths, None
                return 'Source', 'xml', "XML content detected", paths, None

            # Lua script detection (using decoded preview)
            if any(pattern in preview for pattern in [
                'function', 'local', '--[[', '-- ', 'if', 'then', 'end', 'return',
                'module(...)', 'module(',  # Lua module patterns
                'require(',                # Module import
                'package.loadlib'          # Dynamic module loading
            ]):
                paths = extract_file_paths(data)
                name = extract_lua_global_name(data)
                return 'Source', 'lua', "Lua content detected", paths, name
                
            # Generic text detection
            if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in preview):
                paths = extract_file_paths(data)
                if '<' in preview and '>' in preview:
                    return 'Source', 'xml', "XML-like content detected", paths, None
                if '--' in preview or 'function' in preview:
                    name = extract_lua_global_name(data)
                    return 'Source', 'lua', "Lua-like content detected", paths, name
                return 'Text/plain', 'txt', "Text content detected", paths, None
        except UnicodeDecodeError:
            pass

        # Check for known file signatures
        for magic, (dir_name, ext, type_info) in FILE_SIGNATURES.items():
            if data.startswith(magic):
                return dir_name, ext, type_info, [], None

        # Font table detection as backup for TTF/OTF detection
        if any(table in data[:64] for table in FONT_TABLES):
            tables = [t.decode() for t in FONT_TABLES if t in data[:64]]
            return 'Fonts', 'ttf', f"Font tables: {','.join(tables)}", [], None

        # Extract paths to look for recognized file extensions
        paths = extract_file_paths(data)
        for path in paths:
            try:
                ext = path.split('.')[-1].lower() if '.' in path else ''
                if ext in UI_ASSETS:
                    return UI_ASSETS[ext], ext, f"Path extension detected: {path}", paths, None
            except UnicodeDecodeError:
                continue

        # Default to binary data for unknown types
        file_hash = hashlib.sha256(data).hexdigest()
        return 'Data', 'bin', f"Unknown binary data (SHA-256: {file_hash})", [], None
