import struct
import time
from typing import BinaryIO, Any

# Debug configuration
DEBUG = False
DEBUG_LOG = "debug.log"

def set_debug(enabled: bool = True, log_file: str = "debug.log") -> None:
    """Enable or disable debug logging and set the log file path"""
    global DEBUG, DEBUG_LOG
    DEBUG = enabled
    DEBUG_LOG = log_file
    if enabled:
        clear_debug_log()

# Expose for use in other modules
struct = struct
time = time

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
