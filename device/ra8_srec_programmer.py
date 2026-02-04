"""
RA8 SREC Programming Module.

Handles SREC file parsing and programming, including OSM (Option Setting Memory) handling.
"""

import time
from pathlib import Path
from typing import List, Tuple, Optional

from device.ra8_provisioning_client import RA8ProvisioningClient
from utils.logging import get_logger
from utils.exceptions import DeviceError

logger = get_logger(__name__)


class RA8SRECProgrammer:
    """Handles SREC file programming operations for RA8 devices."""
    
    def __init__(self, client: RA8ProvisioningClient):
        """
        Initialize SREC programmer.
        
        Args:
            client: RA8ProvisioningClient instance
        """
        self.client = client
    
    def _parse_srec_file_strict(self, filename: Path) -> List[Tuple[int, bytes]]:
        """Parse S1/S2/S3 records, verify checksum, return list of (address, bytes)."""
        blocks = []
        try:
            with open(filename, 'r') as f:
                for ln, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line[0] != 'S':
                        continue
                    
                    rtype = line[1]
                    if rtype in ('1', '2', '3'):
                        count = int(line[2:4], 16)
                        addr_len = 4 if rtype == '1' else (6 if rtype == '2' else 8)
                        address = int(line[4:4+addr_len], 16)
                        data_start = 4 + addr_len
                        data_end = 4 + (count * 2)
                        data_hex = line[data_start:data_end-2]
                        raw = bytes.fromhex(line[2:data_end])
                        
                        if (sum(raw) & 0xFF) != 0xFF:
                            raise ValueError(f"SREC line {ln}: checksum mismatch")
                        
                        data = bytes.fromhex(data_hex)
                        blocks.append((address, data))
                    else:
                        # S0/S5/S7/S8/S9 ignored
                        continue
            
            return blocks
        except Exception as e:
            logger.error(f"Error parsing SREC file: {e}")
            raise DeviceError(f"Failed to parse SREC file: {e}")
    
    def _merge_contiguous_blocks(self, blocks: List[Tuple[int, bytes]], phrase_size: int = 128) -> List[Tuple[int, bytes]]:
        """
        Merge sorted (address, bytes) blocks unless the gap contains at least one aligned, full write phrase.
        
        Args:
            blocks: List of (addr, data) tuples sorted by addr
            phrase_size: Flash block size (default: 128 bytes)
        
        Returns:
            Merged blocks list
        """
        if not blocks:
            return []
        
        cur_addr, cur_data = blocks[0]
        cur_data = bytearray(cur_data)
        merged = []
        
        for addr, data in blocks[1:]:
            data = bytes(data)
            cur_end = cur_addr + len(cur_data) - 1
            
            if addr <= cur_end:
                # Overlap: expand and overlay
                overlap_start = addr
                overlap_end = min(cur_end, addr + len(data) - 1)
                
                if addr + len(data) - 1 > cur_end:
                    extend_len = (addr + len(data) - 1) - cur_end
                    cur_data += b'\xFF' * extend_len
                    cur_end = cur_addr + len(cur_data) - 1
                
                for i in range(overlap_start, overlap_end + 1):
                    cur_data[i - cur_addr] = data[i - addr]
                continue
            
            # Non-overlapping: check gap
            gap_start = cur_end + 1
            gap_end = addr - 1
            gap_len = addr - (cur_end + 1)
            
            start_aligned = ((gap_start + phrase_size - 1) // phrase_size) * phrase_size
            last_phrase_start = (gap_end // phrase_size) * phrase_size
            has_full_aligned_phrase = (start_aligned + phrase_size - 1) <= gap_end
            
            if has_full_aligned_phrase:
                merged.append((cur_addr, bytes(cur_data)))
                cur_addr, cur_data = addr, bytearray(data)
            else:
                cur_data += b'\xFF' * gap_len
                cur_data += data
        
        merged.append((cur_addr, bytes(cur_data)))
        return merged
    
    def _remap_alias(self, address: int, to_secure: bool = True) -> int:
        """Map upper/non-secure alias -> lower/secure alias."""
        if to_secure:
            if self.client.NONSEC_ALIAS_BASE <= address <= self.client.NONSEC_ALIAS_LIMIT:
                offset = address - self.client.NONSEC_ALIAS_BASE
                return self.client.SECURE_ALIAS_BASE + offset
        else:
            if self.client.SECURE_ALIAS_BASE <= address <= self.client.SECURE_ALIAS_LIMIT:
                offset = address - self.client.SECURE_ALIAS_BASE
                return self.client.NONSEC_ALIAS_BASE + offset
        
        return address
    
    def _classify_region(self, addr: int) -> str:
        """Classify memory region."""
        if self.client.SECURE_ALIAS_BASE <= addr <= self.client.SECURE_ALIAS_LIMIT:
            return "code_secure"
        if self.client.NONSEC_ALIAS_BASE <= addr <= self.client.NONSEC_ALIAS_LIMIT:
            return "code_nonsec"
        if 0x0300A000 <= addr <= 0x0300AFFF:
            return "option_setting"
        if 0x37000000 <= addr <= 0x37002FFF:
            return "data_flash"
        if 0x22000000 <= addr <= 0x22FFFFFF:
            return "sram"
        return "other"
    
    def _range_check_block(self, addr: int, data_len: int) -> bool:
        """Check if block is within valid range."""
        end_addr = addr + data_len - 1
        in_secure = (
            self.client.SECURE_ALIAS_BASE <= addr <= self.client.SECURE_ALIAS_LIMIT and
            self.client.SECURE_ALIAS_BASE <= end_addr <= self.client.SECURE_ALIAS_LIMIT
        )
        in_nonsec = (
            self.client.NONSEC_ALIAS_BASE <= addr <= self.client.NONSEC_ALIAS_LIMIT and
            self.client.NONSEC_ALIAS_BASE <= end_addr <= self.client.NONSEC_ALIAS_LIMIT
        )
        return in_secure or in_nonsec
    
    def _align_down(self, addr: int, size: int) -> int:
        """Align address down."""
        return addr - (addr % size)
    
    def _align_up(self, addr: int, size: int) -> int:
        """Align address up."""
        return ((addr + size - 1) // size) * size
    
    def _command_erase(self, start_addr: int, end_addr: int) -> bool:
        """Erase inclusive range [start_addr..end_addr], aligned externally."""
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x09'
        CMD = b'\x12'
        SAD = start_addr.to_bytes(4, 'big')
        EAD = end_addr.to_bytes(4, 'big')
        SUM = self.client._calc_sum(LNH + LNL + CMD + SAD + EAD)
        ETX = b'\x03'
        
        pkt = SOH + LNH + LNL + CMD + SAD + EAD + SUM + ETX
        
        logger.info(f"Erasing 0x{start_addr:08X}..0x{end_addr:08X}")
        self.client.ser.write(pkt)
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        st = self.client._decode_status_packet(rp)
        
        return (st.get("RES") == 0x12) and (st.get("STS") in (0x00, None))
    
    def _command_write(self, address: int, data: bytes) -> bool:
        """Write data to flash with robust RES/STS checking."""
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        # Command packet (announce address span)
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x09'
        CMD = b'\x13'
        SAD = address.to_bytes(4, 'big')
        EAD = (address + len(data) - 1).to_bytes(4, 'big')
        SUM = self.client._calc_sum(LNH + LNL + CMD + SAD + EAD)
        ETX = b'\x03'
        
        self.client.ser.write(SOH + LNH + LNL + CMD + SAD + EAD + SUM + ETX)
        time.sleep(self.client.FLASH_WRITE_DELAY)
        
        rp = self.client._receive_data_packet()
        st = self.client._decode_status_packet(rp)
        
        if st.get("RES") != 0x13:
            logger.error(f"WRITE cmd nack: {st}")
            return False
        
        if st.get("STS") not in (0x00, None):
            logger.error(f"WRITE cmd nack: {st}")
            return False
        
        # Data chunks (<=1024 bytes each)
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset+1024]
            SOD = b'\x81'
            length = len(chunk) + 1
            LNH = (length >> 8).to_bytes(1, 'big')
            LNL = (length & 0xFF).to_bytes(1, 'big')
            RES = b'\x13'
            SUM = self.client._calc_sum(LNH + LNL + RES + chunk)
            ETX = b'\x03'
            
            self.client.ser.write(SOD + LNH + LNL + RES + chunk + SUM + ETX)
            time.sleep(self.client.FLASH_WRITE_DELAY)
            
            rp = self.client._receive_data_packet()
            st = self.client._decode_status_packet(rp)
            
            if st.get("RES") != 0x13:
                logger.error(f"WRITE data nack: {st}")
                return False
            
            if st.get("STS") not in (0x00, None):
                logger.error(f"WRITE data nack: {st}")
                return False
            
            offset += len(chunk)
        
        return True
    
    def _write_block_in_phrases_aligned(self, start_addr: int, data_bytes: bytes) -> bool:
        """Write data_bytes starting at start_addr using 128-byte, phrase-aligned writes."""
        # Align start down to phrase boundary
        aligned_start = start_addr & ~(self.client.FLASH_BLOCK_SIZE - 1)
        pre_gap = start_addr - aligned_start
        
        # Build buffer with leading 0xFF for gap, then data
        buf = (b'\xFF' * pre_gap) + data_bytes
        
        # Pad tail to multiple of FLASH_BLOCK_SIZE
        tail = (self.client.FLASH_BLOCK_SIZE - (len(buf) % self.client.FLASH_BLOCK_SIZE)) % self.client.FLASH_BLOCK_SIZE
        if tail:
            buf += b'\xFF' * tail
        
        # Program one phrase per write command
        for i in range(0, len(buf), self.client.FLASH_BLOCK_SIZE):
            phrase_addr = aligned_start + i
            phrase = buf[i:i+self.client.FLASH_BLOCK_SIZE]
            
            ok = self._command_write(phrase_addr, phrase)
            if not ok:
                raise DeviceError(f"Phrase write failed @ 0x{phrase_addr:08X}")
        
        return True
    
    def _erase_srec_span_skip_bootblock(self, blocks: List[Tuple[int, bytes]]) -> bool:
        """Erase union of SREC addresses aligned to 32KB, skipping boot block."""
        if not blocks:
            return True
        
        min_addr = min(a for a, _ in blocks)
        max_addr = max(a + len(d) - 1 for a, d in blocks)
        
        start = self._align_down(min_addr, self.client.ERASE_SECTOR_SIZE)
        end = self._align_up(max_addr, self.client.ERASE_SECTOR_SIZE) - 1
        
        return self._command_erase(start, end)
    
    def program_srec_file(self, srec_file: Path, enforce_secure_alias: bool = True) -> None:
        """
        Program SREC file to device.
        
        Args:
            srec_file: Path to SREC file
            enforce_secure_alias: Whether to remap non-secure addresses to secure alias
        """
        logger.info(f"Programming {srec_file}")
        
        blocks = self._parse_srec_file_strict(srec_file)
        if not blocks:
            raise DeviceError("Failed to parse SREC file or no data records")
        
        # Sort blocks
        blocks.sort(key=lambda x: x[0])
        
        # Classify & collect
        code_blocks = []
        skipped = []
        
        for addr, data in blocks:
            region = self._classify_region(addr)
            if region == "code_secure":
                code_blocks.append((addr, data))
            elif region == "code_nonsec":
                if enforce_secure_alias:
                    code_blocks.append((self._remap_alias(addr, to_secure=True), data))
                else:
                    code_blocks.append((addr, data))
            else:
                skipped.append((addr, len(data), region))
        
        # Range checks
        for addr, data in code_blocks:
            if not self._range_check_block(addr, len(data)):
                raise DeviceError(
                    f"SREC code block outside alias: 0x{addr:08X}..0x{addr+len(data)-1:08X}"
                )
        
        # Merge contiguous blocks
        code_blocks = self._merge_contiguous_blocks(code_blocks)
        logger.info(f"Found {len(code_blocks)} merged code-flash blocks")
        
        # Erase range (skip boot block)
        if not self._erase_srec_span_skip_bootblock(code_blocks):
            raise DeviceError("Erase failed before programming")
        
        # Write
        for i, (address, data) in enumerate(code_blocks):
            logger.info(f"Writing block {i+1}/{len(code_blocks)}: 0x{address:08X} ({len(data)} bytes)")
            if not self._write_block_in_phrases_aligned(address, data):
                raise DeviceError(f"Write failed at address 0x{address:08X}")
        
        logger.info("SREC programming completed successfully")
    
    def _collect_osm_srec_records(self, srec_file: Path) -> List[Tuple[int, bytes]]:
        """Collect OSM (Option Setting Memory) records from SREC file."""
        blocks = self._parse_srec_file_strict(srec_file)
        if not blocks:
            return []
        
        CF_MIN, CF_MAX = 0x0300A100, 0x0300A2FF
        DF_MIN, DF_MAX = 0x27030050, 0x270303FF
        
        def pad16_ff(data: bytes, max_len: Optional[int] = None) -> bytes:
            tail = (-len(data)) % 16
            padded = data + (b'\xFF' * tail if tail else b'')
            if max_len is not None and len(padded) > max_len:
                padded = padded[:max_len]
            return padded
        
        out = []
        for addr, data in blocks:
            end = addr + len(data)
            
            # CF OSM intersection
            if not (end <= CF_MIN or addr > CF_MAX):
                s = max(addr, CF_MIN)
                e = min(end, CF_MAX + 1)
                slice_len = e - s
                piece = data[s - addr : s - addr + slice_len]
                max_len_cf = (CF_MAX + 1) - s
                out.append((s, pad16_ff(piece, max_len_cf)))
            
            # DF OSM intersection
            if not (end <= DF_MIN or addr > DF_MAX):
                s = max(addr, DF_MIN)
                e = min(end, DF_MAX + 1)
                slice_len = e - s
                piece = data[s - addr : s - addr + slice_len]
                max_len_df = (DF_MAX + 1) - s
                out.append((s, pad16_ff(piece, max_len_df)))
        
        out.sort(key=lambda x: x[0])
        return out
    
    def program_osm_from_srec(self, srec_file: Path) -> None:
        """Program OSM (Option Setting Memory) from SREC file."""
        osm_records = self._collect_osm_srec_records(srec_file)
        
        if not osm_records:
            logger.info("[OSM] No OSM records to program.")
            return
        
        for addr, data in osm_records:
            logger.info(f"[OSM] Programming record 0x{addr:08X}")
            self._command_write(addr, data)
        
        logger.info("[OSM] CF + DF option-setting programmed from SREC records.")


