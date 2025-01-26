# uo-enhanced-uop-extractor

A Python tool for extracting UOP archives from Ultima Online Enhanced and Ultima Online: Stygian Abyss. Features automatic file type detection, smart categorization, and a smooth progress display.

## Features

- Extracts and categorizes files from UO Enhanced/Stygian Abyss UOP archives
- Automatically detects and organizes files by type:
  - XML files (including Interface files)
  - Lua scripts
  - PNG/JPEG images
  - DDS textures
  - OpenType/TrueType fonts
  - Microsoft Compound Binary files
  - Unknown files (stored in data directory)
- Handles compressed and uncompressed files
- Shows extraction progress with a smooth Unicode progress bar
- Provides file type statistics after extraction
- Adapts to terminal size
- Cross-platform support

## Requirements

- Python 3.6 or later
- No external dependencies required

## Installation

Clone this repository:
```bash
git clone https://github.com/yourusername/uo-enhanced-uop-extractor.git
cd uo-enhanced-uop-extractor
```

The script is standalone and requires no installation.

## Usage

```bash
python uop_extract.py <uop_file> <output_dir>
```

### Arguments

- `uop_file`: Path to the UOP archive to extract
- `output_dir`: Directory where extracted files will be saved

### Example

```bash
python uop_extract.py interface.uop extracted/
```

This will extract the contents of `interface.uop` to the `extracted/` directory, organizing files into subdirectories based on their type.

### Output Structure

```
extracted/
├── xml/          # XML and interface files
├── lua/          # Lua scripts
├── images/       # PNG and JPEG images
├── textures/     # DDS texture files
├── fonts/        # TTF and OTF font files
├── compound/     # Microsoft compound binary files
└── data/         # Unknown file types
```

## File Type Detection

The extractor automatically detects and categorizes files based on:

- Magic bytes/file signatures
- Content patterns
- File headers
- Font table signatures

Supported file types and their detection methods:

| Type | Detection Method |
|------|-----------------|
| XML | Content starts with `<?xml` or `<Interface` |
| Lua | Content starts with `LuaQ` or `--` |
| PNG | Content starts with PNG signature |
| JPEG | Content starts with JPEG signature |
| DDS | Content starts with `DDS ` |
| OpenType | Content starts with `OTTO` |
| TrueType | Contains font tables (DSIG, LTSH, etc.) |
| Compound | Starts with Microsoft CFB signature |

## Progress Bar

The extractor includes a sophisticated progress bar that:
- Shows accurate extraction progress
- Uses Unicode block characters for smooth progress display
- Adapts to terminal width
- Shows completion percentage
- Handles both regular and text-only terminals
- Updates in real-time

Example output:
```
Version: 7
Files per block: 100
Total files: 1234
Extracting
     [██████████████████████████                ]  54.32 %
```

## License

MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
