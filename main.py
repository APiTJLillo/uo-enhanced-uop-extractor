#!/usr/bin/env python3
import os
import sys
import argparse
from utils import DEBUG, clear_debug_log
from uop_extract import extract_uop
from file_type_detector import FileTypeDetector

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
        import utils  # Get the latest DEBUG value
        file_type_detector = FileTypeDetector(debug=utils.DEBUG)
        file_type_detector.trid_analyzer.update_trid_definitions()
    
    if not os.path.exists(args.uop_file):
        print(f"Error: File not found: {args.uop_file}")
        sys.exit(1)
        
    extension_counts, seen_hashes, summary = extract_uop(args.uop_file, args.output_dir)

if __name__ == '__main__':
    main()
