#!/usr/bin/env python3
import sys
import os
import time
import struct
import zlib
import hashlib
import argparse
from collections import Counter
from typing import Counter as CounterType, Set, Dict, Tuple, Optional, List
from pathlib import Path

from progress_bar import ProgressBar
from file_type_analyzer import detect_file_type, TRID, extract_file_paths
from path_hash import hash_filename, load_hash_mappings, save_hash_mappings
from utils import (
    DEBUG, DEBUG_LOG, clear_debug_log, debug_print,
    read_int, read_long, read_short,
    try_derive_path, find_matching_default_file
)

def extract_uop(uop_path: str, output_dir: str) -> Tuple[CounterType[str], Set[int], str]:
    """Extract files from a UOP archive."""
    hash_mappings = load_hash_mappings()
    content_hashes: Dict[str, str] = {}
    os.makedirs(output_dir, exist_ok=True)
    
    extension_counts: CounterType[str] = Counter[str]()
    seen_hashes: Set[int] = set()
    hash_log_path = os.path.join(output_dir, "hashes.txt")
    
    with open(uop_path, 'rb') as f, open(hash_log_path, 'w') as hash_log:
        if f.read(4) != b'MYP\0':
            error_msg = "Error: Not a valid UOP file"
            debug_print(error_msg)
            print(error_msg)
            return Counter(), set(), error_msg

        version = read_int(f)
        misc = read_int(f)
        block_offset = read_long(f)
        max_files_per_block = read_int(f)
        file_count = read_int(f)

        debug_print(f"Version: {version}")
        debug_print(f"Files per block: {max_files_per_block}")
        debug_print(f"Total files: {file_count}")
        debug_print("Extracting")
        
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
                        # Skip invalid files
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
                                    msg = f"Warning: Failed to decompress file {block_id}.{file_id}: {e}"
                                    debug_print(msg)
                                    print(msg)
                                    continue
                            else:
                                file_data = data
                        else:
                            continue
                    except (ValueError, OSError) as e:
                        msg = f"Warning: Failed to read file {block_id}.{file_id}: {e}"
                        debug_print(msg)
                        print(msg)
                        continue

                    content_hash = hashlib.sha256(file_data).hexdigest()
                    if content_hash in content_hashes:
                        reused_path = content_hashes[content_hash]
                        # Normalize directory case in reused paths
                        parts = reused_path.split('/')
                        if len(parts) > 1:
                            parts[0] = parts[0].title()  # Capitalize first part
                            reused_path = '/'.join(parts)
                        reused_output = os.path.join(output_dir, reused_path)
                        if DEBUG:
                            debug_print(f"Reused path from content hash: {reused_path}")
                        continue

                    # Initialize variables with default values
                    dir_name: str = 'Data'  # Default directory
                    ext: str = 'bin'        # Default extension
                    content_info: str = ""   # Default info
                    file_paths: list[str] = [] # Default empty list
                    current_output: Optional[str] = None
                    found_match: bool = False
                    current_path: Optional[str] = None

                    # Detect file type
                    detect_result = detect_file_type(file_data, TRID)
                    if detect_result:
                        dir_name, ext, content_info, file_paths = detect_result

                    for path in file_paths:
                        computed_hash = hash_filename(path)
                        if computed_hash == filename_hash:
                            hash_mappings[filename_hash] = path
                            found_match = True
                            if DEBUG:
                                debug_print(f"Matched path: {path} -> 0x{filename_hash:016x}")
                            break
                        elif DEBUG and path.endswith(('.xml', '.lua', '.ttf', '.dds')):
                            debug_print(f"Near miss for {path}:")
                            debug_print(f"Expected: 0x{filename_hash:016x}")
                            debug_print(f"Got:      0x{computed_hash:016x}")

                    known_path = hash_mappings.get(filename_hash, "")  # Default to empty string
                    if known_path:
                        current_path = known_path
                        current_output = os.path.join(output_dir, current_path)
                        _, ext_part = os.path.splitext(current_path)
                        ext = ext_part[1:] if ext_part else ext  # Keep existing ext if no extension
                        dir_name = os.path.dirname(current_path).split('/')[0] if '/' in current_path else dir_name
                        if DEBUG:
                            debug_print(f"Using known hash mapping: {current_path}")
                    
                    if not current_output:
                        derived_path = try_derive_path(file_data, ext, filename_hash)
                        if derived_path:
                            current_path = derived_path
                            current_output = os.path.join(output_dir, current_path)
                            _, ext = os.path.splitext(current_path)
                            ext = ext[1:] if ext else ''
                            # Keep full directory path
                            dir_name = os.path.dirname(current_path)
                            hash_mappings[filename_hash] = current_path
                            if DEBUG:
                                debug_print(f"Derived path from content: {current_path}")

                    if not current_output and os.path.exists("Default"):
                        default_match = find_matching_default_file(file_data, ext, filename_hash, hash_mappings, block_id, file_id)
                        if default_match:
                            current_path = default_match
                            current_output = os.path.join(output_dir, current_path)
                            _, ext = os.path.splitext(current_path)
                            ext = ext[1:] if ext else ''
                            dir_name = os.path.dirname(current_path).split('/')[0] if '/' in current_path else dir_name
                            if DEBUG:
                                debug_print(f"Matched file contents: {current_path}")
                    
                    if not current_output and found_match:
                        current_path = hash_mappings[filename_hash]
                        current_output = os.path.join(output_dir, current_path)
                        _, ext = os.path.splitext(current_path)
                        ext = ext[1:] if ext else ''
                        dir_name = os.path.dirname(current_path).split('/')[0] if '/' in current_path else dir_name
                    
                    if not current_output:
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
                        msg = f"Warning: Failed to write file {final_path}: {e}"
                        debug_print(msg)
                        print(msg)
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

    # Build the final summary
    final_summary = "\n".join([
        "\nExtraction complete:",
        f"Found {len(seen_hashes)} unique filename hashes",
        "Hash information written above.",
        "File counts by type/extension:"
    ])
    
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
    
    # Add type counts
    for dir_name, exts in sorted(by_type.items()):
        final_summary += f"\n\n{dir_name.upper()}:"
        for ext, count in sorted(exts.items()):
            if ext:
                final_summary += f"\n  {ext.upper()} files: {count}"
            else:
                final_summary += f"\n  (no extension): {count}"
    
    final_summary += f"\n\nTotal files: {sum(extension_counts.values())}"
    
    debug_print(final_summary)
    print(final_summary)
    
    with open(hash_log_path, 'a') as hash_log:
        hash_log.write("\n" + final_summary + "\n")
    
    save_hash_mappings(hash_mappings)
    
    return extension_counts, seen_hashes, final_summary

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
        clear_debug_log()

    if args.update_trid:
        TRID.update_trid_definitions()
    
    if not os.path.exists(args.uop_file):
        msg = f"Error: File not found: {args.uop_file}"
        debug_print(msg)
        print(msg)
        sys.exit(1)
        
    extension_counts, seen_hashes, summary = extract_uop(args.uop_file, args.output_dir)

if __name__ == '__main__':
    main()
