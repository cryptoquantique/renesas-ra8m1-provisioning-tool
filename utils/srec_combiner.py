"""
SREC Combiner - Wrapper for srec_cat tool.

Combines multiple SREC files (bootloader, app, certificates) into a single file.
Provides overlap detection, OSM record handling, and final validation.

This module provides:
    - Binary to SREC conversion with memory offset
    - SREC file merging with conflict detection
    - OSM record extraction and injection
    - S5/S7 record management

Classes:
    SrecSegment: Data class representing a memory segment in SREC
    SrecCombiner: Main class for SREC file operations

Example:
    >>> combiner = SrecCombiner(Path("tools/srec_cat.exe"))
    >>> combiner.combine_srecs(
    ...     [bootloader_srec, app_srec],
    ...     output_srec
    ... )
"""

import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from dataclasses import dataclass

from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SrecSegment:
    """Represents a memory segment in SREC."""
    start_addr: int
    end_addr: int
    size: int
    source_file: str


class SrecCombiner:
    """
    Combines multiple SREC files using srec_cat tool.
    
    Handles:
    - Binary to SREC conversion with offset
    - SREC file merging
    - Overlap detection
    - OSM record extraction/injection
    - S5/S7 record management
    """
    
    def __init__(self, srec_cat_exe: Path):
        """
        Initialize SREC combiner.
        
        Args:
            srec_cat_exe: Path to srec_cat.exe tool
            
        Raises:
            FirmwareError: If srec_cat.exe not found
        """
        if not srec_cat_exe.exists():
            raise FirmwareError(f"srec_cat.exe not found: {srec_cat_exe}")
        
        self.srec_cat_exe = srec_cat_exe
        logger.info(f"Initialized SrecCombiner with: {srec_cat_exe}")
    
    def bin_to_srec(
        self,
        binary_file: Path,
        output_srec: Path,
        offset: int,
        exec_start_addr: Optional[int] = None
    ) -> Path:
        """
        Convert binary file to SREC with offset.
        
        Args:
            binary_file: Input binary file
            output_srec: Output SREC file
            offset: Memory offset for binary data
            exec_start_addr: Execution start address (S7 record), defaults to offset
            
        Returns:
            Path to output SREC file
            
        Raises:
            FirmwareError: If conversion fails
        """
        if not binary_file.exists():
            raise FirmwareError(f"Binary file not found: {binary_file}")
        
        if exec_start_addr is None:
            exec_start_addr = offset
        
        logger.info(f"Converting {binary_file.name} to SREC with offset 0x{offset:08X}")
        
        cmd = [
            str(self.srec_cat_exe),
            str(binary_file),
            "-binary",
            "-offset", f"0x{offset:X}",
            "-execution-start-address", f"0x{exec_start_addr:X}",
            "-o", str(output_srec)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )
            
            if not output_srec.exists():
                raise FirmwareError(f"SREC file not created: {output_srec}")
            
            logger.info(f"[OK] Created SREC: {output_srec.name} ({output_srec.stat().st_size} bytes)")
            return output_srec
            
        except subprocess.CalledProcessError as e:
            raise FirmwareError(f"srec_cat failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise FirmwareError("srec_cat timed out after 30 seconds")
        except Exception as e:
            raise FirmwareError(f"Failed to convert binary to SREC: {e}")
    
    def combine_srec_files(
        self,
        srec_files: List[Path],
        output_file: Path,
        check_overlap: bool = True
    ) -> Path:
        """
        Combine multiple SREC files into one.
        
        Args:
            srec_files: List of SREC files to combine
            output_file: Output combined SREC file
            check_overlap: Check for memory overlaps
            
        Returns:
            Path to combined SREC file
            
        Raises:
            FirmwareError: If combination fails or overlaps detected
        """
        # Validate inputs
        for srec_file in srec_files:
            if not srec_file.exists():
                raise FirmwareError(f"SREC file not found: {srec_file}")
        
        logger.info(f"Combining {len(srec_files)} SREC files:")
        for f in srec_files:
            logger.info(f"  - {f.name}")
        
        # Check for overlaps if requested
        if check_overlap:
            overlaps = self._check_overlaps(srec_files)
            if overlaps:
                error_msg = "Memory overlaps detected:\n"
                for seg1, seg2 in overlaps:
                    error_msg += f"  {seg1.source_file}: 0x{seg1.start_addr:08X}-0x{seg1.end_addr:08X}\n"
                    error_msg += f"  {seg2.source_file}: 0x{seg2.start_addr:08X}-0x{seg2.end_addr:08X}\n"
                raise FirmwareError(error_msg)
        
        # Build srec_cat command
        cmd = [str(self.srec_cat_exe)]
        for srec_file in srec_files:
            cmd.append(str(srec_file))
        cmd.extend(["-o", str(output_file)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )
            
            if not output_file.exists():
                raise FirmwareError(f"Combined SREC not created: {output_file}")
            
            # Verify output
            with open(output_file, 'r') as f:
                lines = f.readlines()
                s3_count = sum(1 for line in lines if line.strip().startswith('S3'))
            
            logger.info(f"[OK] Combined SREC created: {output_file.name}")
            logger.info(f"  Size: {output_file.stat().st_size} bytes")
            logger.info(f"  S3 records: {s3_count}")
            logger.info(f"  Total lines: {len(lines)}")
            
            return output_file
            
        except subprocess.CalledProcessError as e:
            raise FirmwareError(f"srec_cat combine failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise FirmwareError("srec_cat timed out after 30 seconds")
        except Exception as e:
            raise FirmwareError(f"Failed to combine SREC files: {e}")
    
    def _check_overlaps(self, srec_files: List[Path]) -> List[Tuple[SrecSegment, SrecSegment]]:
        """
        Check for memory overlaps between SREC files.
        
        Args:
            srec_files: List of SREC files to check
            
        Returns:
            List of overlapping segment pairs
        """
        segments = []
        
        for srec_file in srec_files:
            file_segments = self._extract_segments(srec_file)
            segments.extend(file_segments)
        
        # Check all pairs for overlap
        overlaps = []
        for i in range(len(segments)):
            for j in range(i + 1, len(segments)):
                seg1, seg2 = segments[i], segments[j]
                if self._segments_overlap(seg1, seg2):
                    overlaps.append((seg1, seg2))
        
        return overlaps
    
    def _extract_segments(self, srec_file: Path) -> List[SrecSegment]:
        """
        Extract memory segments from SREC file.
        
        Returns separate segments for each contiguous memory region.
        This correctly handles files with discontinuous regions like:
        - Code Flash (0x02000000)
        - OSM (0x0300Axxx)
        - Option bytes (0x27030xxx)
        """
        # Collect all address ranges
        ranges = []
        
        with open(srec_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('S3'):
                    continue
                
                # Parse S3 record: S3 LL AAAAAAAA DD...DD CC
                addr = int(line[4:12], 16)
                count = int(line[2:4], 16)
                data_len = count - 5  # address (4) + checksum (1)
                ranges.append((addr, addr + data_len))
        
        if not ranges:
            return []
        
        # Sort by start address
        ranges.sort(key=lambda x: x[0])
        
        # Merge contiguous ranges (gap > 256 bytes = new segment)
        # This threshold handles normal SREC record gaps but separates
        # truly different memory regions (Code Flash vs OSM vs Option bytes)
        GAP_THRESHOLD = 0x10000  # 64KB gap = new segment
        
        segments = []
        current_start = ranges[0][0]
        current_end = ranges[0][1]
        
        for start, end in ranges[1:]:
            if start <= current_end + GAP_THRESHOLD:
                # Contiguous or small gap - extend current segment
                current_end = max(current_end, end)
            else:
                # Large gap - save current segment and start new one
                segments.append(SrecSegment(
                    start_addr=current_start,
                    end_addr=current_end,
                    size=current_end - current_start,
                    source_file=srec_file.name
                ))
                current_start = start
                current_end = end
        
        # Add final segment
        segments.append(SrecSegment(
            start_addr=current_start,
            end_addr=current_end,
            size=current_end - current_start,
            source_file=srec_file.name
        ))
        
        return segments
    
    def _segments_overlap(self, seg1: SrecSegment, seg2: SrecSegment) -> bool:
        """Check if two segments overlap."""
        return not (seg1.end_addr <= seg2.start_addr or seg2.end_addr <= seg1.start_addr)
    
    def extract_osm_records(self, bootloader_srec: Path) -> List[str]:
        """
        Extract OSM (Option Setting Memory) records from bootloader.
        
        OSM addresses:
        - 0x0300Axxx: Code Flash/Data Flash protection
        - 0x2703xxxx: Security settings
        
        Args:
            bootloader_srec: Bootloader SREC file
            
        Returns:
            List of OSM record lines
        """
        osm_records = []
        
        with open(bootloader_srec, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('S3'):
                    addr = line[4:12]
                    # Check OSM address ranges
                    if addr.upper().startswith('0300A') or addr.upper().startswith('27030'):
                        osm_records.append(line)
        
        logger.info(f"Extracted {len(osm_records)} OSM records from {bootloader_srec.name}")
        return osm_records
    
    def add_osm_records(
        self,
        combined_srec: Path,
        osm_records: List[str],
        bootloader_srec: Optional[Path] = None
    ) -> None:
        """
        Add OSM records to combined SREC file.
        
        Args:
            combined_srec: Combined SREC file to modify
            osm_records: OSM records to add
            bootloader_srec: Optional bootloader for extracting reset vector
        """
        if not osm_records:
            logger.warning("No OSM records to add - device may not boot correctly!")
            return
        
        # Read combined SREC
        combined_lines = []
        s5_line = None
        s7_line = None
        
        with open(combined_srec, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('S5'):
                    s5_line = line
                    continue
                elif line.startswith('S7'):
                    s7_line = line
                    continue
                combined_lines.append(line)
        
        # Add OSM records before termination
        combined_lines.extend(osm_records)
        
        # Recalculate S5 record (data record count)
        data_record_count = sum(1 for l in combined_lines if l.startswith(('S1', 'S2', 'S3')))
        s5_data = f'03{data_record_count:04X}'
        s5_checksum = (~sum(bytes.fromhex(s5_data)) & 0xFF)
        new_s5 = f'S5{s5_data}{s5_checksum:02X}'
        
        # Get S7 from bootloader if available
        if bootloader_srec and bootloader_srec.exists():
            new_s7 = self._extract_reset_vector(bootloader_srec)
        else:
            new_s7 = s7_line if s7_line else 'S70502000000F8'
        
        # Write back
        with open(combined_srec, 'w') as f:
            for line in combined_lines:
                f.write(line + '\n')
            f.write(new_s5 + '\n')
            f.write(new_s7 + '\n')
        
        logger.info(f"[OK] Added {len(osm_records)} OSM records to {combined_srec.name}")
    
    def _extract_reset_vector(self, bootloader_srec: Path) -> str:
        """Extract reset vector from bootloader and create S7 record."""
        memory = {}
        
        with open(bootloader_srec, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('S3'):
                    addr = int(line[4:12], 16)
                    count = int(line[2:4], 16)
                    data_len = count - 5
                    data_bytes = bytes.fromhex(line[12:12 + data_len * 2])
                    for i, b in enumerate(data_bytes):
                        memory[addr + i] = b
        
        # Read reset handler from bootloader vector table at 0x02000004
        if 0x02000004 in memory:
            import struct
            reset_handler = struct.unpack('<I', bytes([memory[0x02000004 + i] for i in range(4)]))[0]
            s7_data = f'05{reset_handler:08X}'
            s7_checksum = (~sum(bytes.fromhex(s7_data)) & 0xFF)
            return f'S7{s7_data}{s7_checksum:02X}'
        
        # Fallback to default bootloader start
        return 'S70502000000F8'
