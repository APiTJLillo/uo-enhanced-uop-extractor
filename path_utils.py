import re
from typing import List, Optional, Tuple, cast
from path_hash import hash_filename, load_hash_mappings, save_hash_mappings

def extract_lua_global_name(content: bytes) -> Optional[str]:
    """Extract global object name from Lua content."""
    try:
        text = content.decode('utf-8', 'ignore')
        lines = text.splitlines()
        
        # Look for global object declarations
        for line in lines:
            # Skip comments
            if line.strip().startswith('--'):
                continue
                
            # Look for patterns like "GlobalName = {}" or "GlobalName = { }"
            match = re.match(r'^([A-Za-z][A-Za-z0-9_]*)\s*=\s*{\s*}', line.strip())
            if match:
                return match.group(1)
            
            # Look for patterns like "GlobalName = {" (open brace)
            match = re.match(r'^([A-Za-z][A-Za-z0-9_]*)\s*=\s*{', line.strip())
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error extracting Lua global name: {e}")
    return None

def normalize_path(path: str) -> str:
    """Normalize a file path by standardizing separators and removing relative components."""
    path = path.replace('\\', '/')
    while '../' in path:
        path = re.sub(r'[^/]+/\.\./','', path)
    path = path.replace('./', '')
    path = re.sub(r'^Data/Interface/','', path)
    return path

def extract_file_paths(data: bytes) -> List[str]:
    """Extract potential file paths from binary data."""
    paths: List[str] = []
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
        print(f"Error extracting paths: {e}")
        return []

def try_derive_path(content: bytes, ext: str, filename_hash: int) -> Optional[str]:
    """Attempt to derive a file path from content and hash."""
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
        print(f"Error deriving path: {e}")
    return None
