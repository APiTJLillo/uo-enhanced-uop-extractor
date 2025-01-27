#!/usr/bin/env python3
import os
import sys
import zlib
import json
import argparse
import hashlib
from pathlib import Path
from typing import BinaryIO, Dict, Tuple, Counter as CounterType, TextIO, Set, Optional, List, Union, cast
from collections import Counter
from io import BytesIO

from file_type_detector import FileTypeDetector
from path_utils import normalize_path, try_derive_path
from path_hash import hash_filename, load_hash_mappings, save_hash_mappings
from progress_bar import ProgressBar
from utils import (
    DEBUG_LOG, debug_print, clear_debug_log, read_int, read_long, read_short,
    time, struct
)
import utils  # Import utils module to access DEBUG directly

def find_matching_default_file(data: bytes, ext: str, filename_hash: int, hash_mappings: Dict[int, str], block_id: int, file_id: int) -> Optional[str]:
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
                        if utils.DEBUG:
                            debug_print(f"Found new hash mapping: 0x{filename_hash:016x} -> {rel_path}")
                        return rel_path
            except (IOError, OSError) as e:
                if utils.DEBUG:
                    debug_print(f"Error reading {file_path}: {e}")
                continue
    
    return None

def extract_uop(uop_path: str, output_dir: str) -> Tuple[CounterType[str], Set[int], str]:
    hash_mappings = load_hash_mappings()
    content_hashes: Dict[str, str] = {}
    os.makedirs(output_dir, exist_ok=True)
    
    extension_counts: CounterType[str] = Counter[str]()
    seen_hashes: Set[int] = set()
    hash_log_path = os.path.join(output_dir, "hashes.txt")
    
    file_type_detector = FileTypeDetector(debug=utils.DEBUG, debug_log=DEBUG_LOG)
    
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
                                    debug_print(f"Warning: Failed to decompress file {block_id}.{file_id}: {e}")
                                    continue
                            else:
                                file_data = data
                        else:
                            continue
                    except (ValueError, OSError) as e:
                        debug_print(f"Warning: Failed to read file {block_id}.{file_id}: {e}")
                        continue

                    content_hash = hashlib.sha256(file_data).hexdigest()
                    if content_hash in content_hashes:
                        reused_path = content_hashes[content_hash]
                        # Normalize directory case in reused paths
                        parts = reused_path.split('/')
                        if len(parts) > 1:
                            parts[0] = parts[0].title()  # Capitalize first directory
                            reused_path = '/'.join(parts)
                        reused_output = os.path.join(output_dir, reused_path)
                        if utils.DEBUG:
                            debug_print(f"Reused path from content hash: {reused_path}")
                        continue

                    # Initialize variables with default values
                    dir_name: str = 'Data'  # Default directory
                    ext: str = 'bin'        # Default extension
                    current_output: Optional[str] = None
                    current_path: Optional[str] = None

                    # First try hash mappings
                    known_path = hash_mappings.get(filename_hash, "")
                    if known_path:
                        current_path = known_path
                        current_output = os.path.join(output_dir, current_path)
                        _, ext_part = os.path.splitext(current_path)
                        ext = ext_part[1:] if ext_part else ext
                        dir_name = os.path.dirname(current_path).split('/')[0] if '/' in current_path else dir_name
                        if utils.DEBUG:
                            debug_print(f"Using known hash mapping: {current_path}")
                    
                    # If no hash mapping found, try TrID analysis
                    if not current_output:
                        detect_result = file_type_detector.detect_file_type(file_data)
                        if detect_result:
                            dir_name, ext, content_info, file_paths, name = detect_result
                            
                            # Try to match any paths found in the content
                            for path in file_paths:
                                computed_hash = hash_filename(path)
                                if computed_hash == filename_hash:
                                    current_path = path
                                    current_output = os.path.join(output_dir, path)
                                    hash_mappings[filename_hash] = path
                                    if utils.DEBUG:
                                        debug_print(f"Matched path from content: {path} -> 0x{filename_hash:016x}")
                                    break
                                elif utils.DEBUG and path.endswith(('.xml', '.lua', '.ttf', '.dds')):
                                    debug_print(f"Near miss for {path}:")
                                    debug_print(f"Expected: 0x{filename_hash:016x}")
                                    debug_print(f"Got:      0x{computed_hash:016x}")
                            
                            # If still no match, try to derive path from content
                            if not current_output:
                                derived_path = try_derive_path(file_data, ext, filename_hash)
                                if derived_path:
                                    current_path = derived_path
                                    current_output = os.path.join(output_dir, derived_path)
                                    _, ext = os.path.splitext(derived_path)
                                    ext = ext[1:] if ext else ''
                                    dir_name = os.path.dirname(derived_path)
                                    hash_mappings[filename_hash] = derived_path
                                    if utils.DEBUG:
                                        debug_print(f"Derived path from content: {derived_path}")
                    
                    if not current_output:
                        # If it's a Lua file and we found a global object name, use that
                        if ext == 'lua' and name:
                            final_path = os.path.join(output_dir, dir_name, f"{name}.{ext}")
                        else:
                            final_path = os.path.join(output_dir, dir_name, f"{block_id}.{file_id}.{ext}")
                    else:
                        final_path = current_output
                    
                    # Use full directory path in counter
                    extension_counts[f"{dir_name or 'root'}/{ext}"] += 1

                    seen_hashes.add(filename_hash)

                    dirname = os.path.dirname(final_path)
                    if dirname:
                        os.makedirs(dirname, exist_ok=True)

                    try:
                        with open(final_path, 'wb') as out:
                            out.write(file_data)
                    except OSError as e:
                        debug_print(f"Warning: Failed to write file {final_path}: {e}")
                        fallback_path = os.path.join(output_dir, dir_name, f"{block_id}.{file_id}.{ext}")
                        dirname = os.path.dirname(fallback_path)
                        if dirname:
                            os.makedirs(dirname, exist_ok=True)
                        with open(fallback_path, 'wb') as out:
                            out.write(file_data)
                    
                    if current_path:
                        content_hashes[content_hash] = current_path
                    
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
        import utils
        utils.DEBUG = True
        clear_debug_log()

    if args.update_trid:
        file_type_detector = FileTypeDetector(debug=utils.DEBUG, debug_log=DEBUG_LOG)
        file_type_detector.trid_analyzer.update_trid_definitions()
    
    if not os.path.exists(args.uop_file):
        print(f"Error: File not found: {args.uop_file}")
        sys.exit(1)
        
    extension_counts, seen_hashes, summary = extract_uop(args.uop_file, args.output_dir)

if __name__ == '__main__':
    main()
