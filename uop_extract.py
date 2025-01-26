#!/usr/bin/env python3
import os
import sys
import struct
import zlib
import time
import math
import shutil
from typing import BinaryIO, Dict, Tuple, Counter as CounterType, TextIO
from collections import Counter

# File type definitions mapping magic bytes/content patterns to (directory, extension)
FILE_TYPES: Dict[bytes, Tuple[str, str]] = {
    b'<?xml': ('xml', 'xml'),
    b'<Interface': ('xml', 'xml'),
    b'LuaQ': ('lua', 'lua'),
    b'--': ('lua', 'lua'),
    b'\r\n--': ('lua', 'lua'),
    b'-' * 30: ('lua', 'lua'),
    b'Data\\Interface\\': ('lua', 'lua'),
    b'PNG': ('images', 'png'),
    b'DDS ': ('textures', 'dds'),
    b'OTTO': ('fonts', 'otf'),
}

# Binary format definitions mapping magic bytes to (directory, extension)
BINARY_TYPES: Dict[bytes, Tuple[str, str]] = {
    bytes([0xD0, 0xCF, 0x11, 0xE0]): ('compound', 'cfb'),  # Microsoft Compound Binary
    bytes([0xFF, 0xD8, 0xFF, 0xE0]): ('images', 'jpg'),    # JPEG
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
            # Set to 100% for neatness, if no exception is thrown
            self.update(1.0)
        if not self._text_only:
            # ANSI-output should be rounded off with a newline
            self._target.write('\n')
        self._target.flush()

    def _update_width(self):
        self._width, _ = shutil.get_terminal_size((80, 20))

    def update(self, progress: float):
        # Update width in case of resize
        self._update_width()
        # Progress bar itself
        if self._width < 12:
            # No label in excessively small terminal
            percent_str = ''
            progress_bar_str = ProgressBar.progress_bar_str(progress, self._width - 2)
        elif self._width < 40:
            # No padding at smaller size
            percent_str = "{:6.2f} %".format(progress * 100)
            progress_bar_str = ProgressBar.progress_bar_str(progress, self._width - 11) + ' '
        else:
            # Standard progress bar with padding and label
            percent_str = "{:6.2f} %".format(progress * 100) + "  "
            progress_bar_str = " " * 5 + ProgressBar.progress_bar_str(progress, self._width - 21)
        # Write output
        if self._text_only:
            self._target.write(progress_bar_str + percent_str + '\n')
            self._target.flush()
        else:
            self._target.write('\033[G' + progress_bar_str + percent_str)
            self._target.flush()

    @staticmethod
    def progress_bar_str(progress: float, width: int):
        # 0 <= progress <= 1
        progress = min(1, max(0, progress))
        whole_width = math.floor(progress * width)
        remainder_width = (progress * width) % 1
        part_width = math.floor(remainder_width * 8)
        part_char = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"][part_width]
        if (width - whole_width - 1) < 0:
            part_char = ""
        line = "[" + "█" * whole_width + part_char + " " * (width - whole_width - 1) + "]"
        return line

def read_int(f: BinaryIO) -> int:
    return struct.unpack('<I', f.read(4))[0]

def read_long(f: BinaryIO) -> int:
    return struct.unpack('<Q', f.read(8))[0]

def read_short(f: BinaryIO) -> int:
    return struct.unpack('<H', f.read(2))[0]

def detect_file_type(data: bytes) -> Tuple[str, str]:
    """Detect file type from content and return (directory, extension)."""
    # Check binary format magic bytes first
    for magic, (dir_name, ext) in BINARY_TYPES.items():
        if data.startswith(magic):
            return dir_name, ext
    
    # Check text format patterns
    for pattern, (dir_name, ext) in FILE_TYPES.items():
        if data.startswith(pattern):
            return dir_name, ext
            
    # Check for font tables (TTF/OTF detection)
    if any(table in data[:64] for table in FONT_TABLES):
        return 'fonts', 'ttf'
    
    # Unknown type
    return 'data', 'bin'

def extract_uop(uop_path: str, output_dir: str) -> None:
    """Extract files from a UOP archive.
    
    Args:
        uop_path: Path to UOP file to extract
        output_dir: Directory to extract files to
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Keep track of file counts by extension
    extension_counts: CounterType[str] = Counter[str]()
    
    with open(uop_path, 'rb') as f:
        # Check magic bytes "MYP\0"
        if f.read(4) != b'MYP\0':
            print("Error: Not a valid UOP file")
            return

        # Read header
        version = read_int(f)
        misc = read_int(f)
        block_offset = read_long(f)
        max_files_per_block = read_int(f)
        file_count = read_int(f)

        print(f"Version: {version}")
        print(f"Files per block: {max_files_per_block}")
        print(f"Total files: {file_count}")
        print("Extracting")

        # Seek to first block
        f.seek(block_offset)
        
        block_id = 0
        files_processed = 0
        last_progress = time.time()

        with ProgressBar() as progress:
            while True:
                # Read block header
                count = read_int(f)
                next_block = read_long(f)
                
                # Process files in block
                for file_id in range(count):
                    # Show progress every 100ms
                    now = time.time()
                    if now - last_progress >= 0.1:
                        progress.update(files_processed / file_count)
                        last_progress = now
                    
                    # Read file header
                    try:
                        data = f.read(8)
                        if len(data) < 8:  # EOF
                            break
                        data_offset = struct.unpack('<Q', data)[0]
                        
                        header_size = read_int(f)
                        compressed_size = read_int(f)
                        decompressed_size = read_int(f)
                        filename_hash = read_long(f)
                        header_hash = read_int(f)
                        compressed = read_short(f) > 0
                        
                        # Save current position
                        current_pos = f.tell()
                    except struct.error:
                        break  # EOF reached
                    
                    # Validate header values
                    if (header_size > 1024*1024 or  # Max 1MB header
                        compressed_size > 100*1024*1024 or  # Max 100MB compressed
                        decompressed_size > 100*1024*1024 or  # Max 100MB decompressed
                        data_offset > os.path.getsize(uop_path)):  # Can't be beyond file size
                        print(f"Warning: Invalid header values for file {block_id}.{file_id}")
                        continue

                    # Read file data
                    try:
                        if data_offset > 0:
                            # Use absolute offset from start of file
                            f.seek(data_offset)
                            
                            # Read header if needed (header is part of the data)
                            if header_size > 0:
                                header = f.read(header_size)
                                
                            # Read actual data
                            data = f.read(compressed_size)
                        else:
                            continue  # Skip invalid offsets
                    except (ValueError, OSError) as e:
                        print(f"Warning: Failed to read file {block_id}.{file_id}: {e}")
                        continue
                    
                    if compressed:
                        try:
                            data = zlib.decompress(data)
                        except zlib.error as e:
                            print(f"Warning: Failed to decompress file {block_id}.{file_id}: {e}")
                            continue

                    # Detect file type and determine output path
                    dir_name, ext = detect_file_type(data)
                    output_path = os.path.join(output_dir, dir_name, f"{block_id}.{file_id}.{ext}")
                    extension_counts[ext] += 1

                    # Ensure directory exists
                    dirname = os.path.dirname(output_path)
                    if dirname:
                        os.makedirs(dirname, exist_ok=True)

                    # Write to output file
                    with open(output_path, 'wb') as out:
                        out.write(data)
                    
                    # Return to file headers
                    f.seek(current_pos)
                    files_processed += 1
                
                if next_block == 0:
                    break
                    
                f.seek(next_block)
                block_id += 1

        # Print summary at end of extraction
        print("\nExtraction complete:")
        for ext, count in sorted(extension_counts.items()):
            print(f"{ext.upper()} files: {count}")
        print(f"Total files: {sum(extension_counts.values())}")

def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: uop_extract.py <uop_file> <output_dir>")
        sys.exit(1)
        
    uop_path = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(uop_path):
        print(f"Error: File not found: {uop_path}")
        sys.exit(1)
        
    extract_uop(uop_path, output_dir)

if __name__ == '__main__':
    main()
