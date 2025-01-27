"""
This module is now deprecated. Please use the following modules instead:
- trid_analyzer.py: For TrID-based file type detection
- path_utils.py: For path manipulation and extraction
- file_type_detector.py: For comprehensive file type detection
"""

from file_type_detector import FileTypeDetector

# For backwards compatibility
TRID = FileTypeDetector()
detect_file_type = TRID.detect_file_type
