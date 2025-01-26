# UO Enhanced UOP Extractor

A Python tool for extracting and identifying files from UOP (Ultima Online Patch) archives with enhanced file type detection.

## Features

- Extracts files from UOP archives
- Enhanced file type detection using content analysis
- TrID-based file type identification
- Maintains filename hash mappings
- Progress bar visualization
- Detailed extraction summary

## Project Structure

- `main.py` - Main entry point and UOP extraction logic
- `file_type_analyzer.py` - File type detection and identification
- `path_hash.py` - Path hashing and mapping utilities
- `progress_bar.py` - Progress bar visualization
- `utils.py` - Common utility functions

## Requirements

- Python 3.6+
- p7zip-full (for TrID definition updates)

## Usage

```bash
python main.py input.uop output_dir [--debug] [--update-trid]
```

### Options

- `--debug`: Enable debug output
- `--update-trid`: Update TrID definitions before extraction

## Notes

The requests package is used for downloading TrID definitions but type stubs are optional. The code uses a type ignore comment to handle this gracefully.
