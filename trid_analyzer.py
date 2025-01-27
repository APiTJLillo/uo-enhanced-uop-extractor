import os
import subprocess
import xml.etree.ElementTree as ET
import requests  # type: ignore
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

from utils import debug_print as utils_debug_print

class TrIDAnalyzer:
    debug: bool
    debug_log: str
    definitions: List[Dict[str, Any]]
    
    def debug_print(self, msg: str) -> None:
        """Write debug messages using the utility debug_print function."""
        if self.debug:
            utils_debug_print(msg)

    def __init__(self, debug: bool = False, debug_log: str = "debug.log"):
        self.debug = debug
        self.debug_log = debug_log
        self.definitions = self.load_trid_definitions()

    def load_trid_definitions(self) -> List[Dict[str, Any]]:
        definitions = []
        defs_dir = Path("trid_definitions")
        
        if self.debug:
            self.debug_print(f"Checking for definitions directory at: {defs_dir.absolute()}")
        
        if not defs_dir.exists():
            if self.debug:
                self.debug_print("Definitions directory not found, downloading...")
            self.update_trid_definitions()
        elif self.debug:
            self.debug_print("Found existing definitions directory")
        
        if self.debug:
            self.debug_print("Loading TrID XML definitions...")
            
        # Recursively search for XML files in all subdirectories
        xml_files = list(defs_dir.rglob("*.xml"))
        
        if self.debug:
            self.debug_print(f"Found {len(xml_files)} XML definition files")
            self.debug_print("XML files found:")
            for xml_file in xml_files[:5]:  # Print first 5 files for debugging
                self.debug_print(f"- {xml_file}")
            if len(xml_files) > 5:
                self.debug_print(f"... and {len(xml_files) - 5} more files")
            
        for xml_file in xml_files:
            try:
                if self.debug:
                    self.debug_print(f"\nParsing {xml_file}")
                tree = ET.parse(xml_file)
                root = tree.getroot()
                info = root.find("Info")
                if info is not None:
                    file_type_elem = info.find("FileType")
                    ext_elem = info.find("Ext")
                    if file_type_elem is not None and ext_elem is not None and file_type_elem.text is not None and ext_elem.text is not None:
                        if self.debug:
                            self.debug_print(f"Found file type: {file_type_elem.text}, ext: {ext_elem.text}")
                        patterns = []
                        pattern_count = 0
                        for pattern in root.findall(".//Pattern"):
                            pattern_count += 1
                            bytes_elem = pattern.find("Bytes")
                            pos_elem = pattern.find("Pos")
                            
                            if bytes_elem is not None and bytes_elem.text and pos_elem is not None and pos_elem.text:
                                try:
                                    pattern_text = bytes_elem.text.strip()
                                    offset = int(pos_elem.text)
                                    if pattern_text:
                                        patterns.append({
                                            "offset": offset,
                                            "value": bytes.fromhex(pattern_text)
                                        })
                                except (ValueError, AttributeError) as e:
                                    if self.debug:
                                        self.debug_print(f"Error parsing pattern in {xml_file}: {e}")
                                    continue
                        
                        if patterns:  # Only add if we found valid patterns
                            if self.debug:
                                self.debug_print(f"Found {len(patterns)} valid patterns out of {pattern_count} in {xml_file.name}")
                            definitions.append({
                                "file_type": file_type_elem.text,
                                "extension": ext_elem.text,
                                "patterns": patterns
                            })
                            if self.debug:
                                self.debug_print(f"Successfully added definition for {file_type_elem.text}")
            except (ET.ParseError, ValueError) as e:
                if self.debug:
                    self.debug_print(f"Error parsing {xml_file}: {str(e)}")
                    import traceback
                    self.debug_print(traceback.format_exc())
        return definitions
    
    def update_trid_definitions(self) -> None:
        """Download and extract XML TrID definitions"""
        TRID_DEFS_URL = "https://mark0.net/download/triddefs_xml.7z"
        print("Updating TrID definitions...")
        
        response = requests.get(TRID_DEFS_URL)
        response.raise_for_status()
        
        # Create definitions directory
        defs_dir = Path("trid_definitions")
        defs_dir.mkdir(exist_ok=True)
        
        # Write the downloaded 7z file
        archive_path = defs_dir / "triddefs_xml.7z"
        archive_path.write_bytes(response.content)
        
        # Extract using 7z command line tool
        try:
            # First clean up the entire defs directory if it exists
            defs_subdir = defs_dir / "defs"
            if defs_subdir.exists():
                import shutil
                shutil.rmtree(defs_subdir)
            
            # Extract directly to trid_definitions directory
            result = subprocess.run(['7z', 'x', str(archive_path), f'-o{str(defs_dir)}', '-y'],
                         check=True, capture_output=True)
            if self.debug:
                self.debug_print("7z output:")
                self.debug_print(result.stdout.decode())
                if result.stderr:
                    self.debug_print("7z errors:")
                    self.debug_print(result.stderr.decode())
            
            # Verify extracted files recursively
            xml_files = list(defs_dir.rglob("*.xml"))
            if self.debug:
                self.debug_print(f"Extracted {len(xml_files)} XML files")
            print("Updated TrID definitions in trid_definitions")
        except subprocess.CalledProcessError as e:
            if self.debug:
                self.debug_print(f"Error extracting definitions: {e}")
                if e.stderr:
                    self.debug_print(f"7z error output: {e.stderr.decode()}")
        finally:
            # Clean up the downloaded archive
            archive_path.unlink()

    TridResult = Dict[str, Union[str, float]]

    def _create_result(self, file_type: str, extension: str, confidence: float) -> TridResult:
        """Create a properly typed result dictionary."""
        return {
            "file_type": str(file_type or ""),
            "extension": str(extension or ""),
            "confidence": confidence
        }

    def identify_file(self, data: bytes) -> Optional[TridResult]:
        # List to track all matching definitions
        matches = []
        
        if self.debug:
            self.debug_print(f"\nAnalyzing file of size {len(data)} bytes")
            self.debug_print(f"Have {len(self.definitions)} TrID definitions to check")
        
        for defn in self.definitions:
            try:
                file_type = str(defn.get("file_type", ""))
                extension = str(defn.get("extension", ""))
                if not file_type:  # Skip if no file type
                    continue

                # Track pattern matches for this definition
                patterns_matched = 0
                total_patterns = len(defn.get("patterns", []))
                
                if total_patterns == 0:  # Skip definitions with no patterns
                    continue

                for pattern in defn.get("patterns", []):
                    offset = int(pattern.get("offset", 0))
                    value = pattern.get("value", b"")
                    if not isinstance(value, bytes):
                        continue

                    # Skip if pattern would extend beyond data
                    if offset + len(value) > len(data):
                        continue

                    # Check if pattern matches at given offset
                    if data[offset:offset+len(value)] == value:
                        patterns_matched += 1

                # Calculate match confidence
                if patterns_matched > 0:
                    confidence = (patterns_matched / total_patterns) * 100
                    matches.append({
                        "file_type": file_type,
                        "extension": extension,
                        "confidence": confidence,
                        "patterns_matched": patterns_matched,
                        "total_patterns": total_patterns
                    })
                    
            except (ValueError, TypeError, AttributeError) as e:
                if self.debug:
                    self.debug_print(f"Error processing definition: {e}")
                continue

        # Find best match with 100% confidence
        CONFIDENCE_THRESHOLD = 100.0  # Only return perfect matches
        
        high_confidence_matches = []
        for match in matches:
            if isinstance(match["confidence"], (int, float)) and match["confidence"] >= CONFIDENCE_THRESHOLD:
                high_confidence_matches.append(match)

        if high_confidence_matches:
            # Extract values and validate types to handle mypy errors
            def get_match_score(m: Dict[str, Any]) -> Tuple[float, int]:
                conf = float(str(m.get("confidence", "0")))
                pats = int(str(m.get("patterns_matched", "0")))
                return (conf, pats)
                
            best_match = max(high_confidence_matches, key=get_match_score)
            
            file_type = str(best_match.get("file_type", ""))
            extension = str(best_match.get("extension", ""))
            confidence = float(str(best_match.get("confidence", "0")))
            
            if self.debug:
                self.debug_print(f"Best TrID match: {file_type} ({confidence:.1f}% confidence)")
                
            return self._create_result(file_type, extension, confidence)

        return None
