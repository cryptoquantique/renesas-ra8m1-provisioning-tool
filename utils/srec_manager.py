"""
SREC File Manager.

Handles SREC file operations: checksum calculation, key injection, address offsetting.
"""

from pathlib import Path
from typing import List


class SrecManager:
    """Manages SREC file operations."""
    
    @staticmethod
    def calculate_checksum(hex_data: str) -> int:
        """
        Calculate SREC checksum (one's complement of sum of bytes).
        
        Args:
            hex_data: Hexadecimal string (without 'S' prefix or checksum)
            
        Returns:
            Checksum byte (0x00-0xFF)
        """
        total = 0
        for i in range(0, len(hex_data), 2):
            total += int(hex_data[i:i+2], 16)
        return (~total) & 0xFF
    
    def inject_customer_key(self, srec_file: Path, key_data: bytes, start_addr: int) -> None:
        """
        Inject customer public key (DER SubjectPublicKeyInfo format) into SREC file at specified address.
        
        CRITICAL: Bootloader expects DER SubjectPublicKeyInfo format (91 bytes for P-256),
        NOT RAW uncompressed format!
        
        Args:
            srec_file: Path to combined SREC file (will be modified in-place)
            key_data: Customer public key in DER SubjectPublicKeyInfo format (91 bytes)
            start_addr: Start address for key injection (e.g., 0x02009114)
        
        Raises:
            ValueError: If key is not 91 bytes (DER format expected)
        """
        # Accept both DER (91 bytes) and RAW (65 bytes) for backward compatibility
        if len(key_data) == 91:
            # DER SubjectPublicKeyInfo format (correct!)
            if key_data[0] != 0x30:  # SEQUENCE tag
                raise ValueError("Invalid DER format: must start with SEQUENCE (0x30)")
        elif len(key_data) == 65:
            # RAW uncompressed format (legacy, convert to DER)
            if key_data[0] != 0x04:
                raise ValueError("Invalid RAW format: must start with uncompressed point prefix (0x04)")
            # For now, reject RAW - bootloader expects DER!
            raise ValueError(f"Bootloader expects DER format (91 bytes), got RAW format (65 bytes). Use DER SubjectPublicKeyInfo!")
        else:
            raise ValueError(f"Customer key must be 91 bytes (DER format), got {len(key_data)}")
        
        key_end = start_addr + len(key_data)
        output_lines = []
        
        # Read all lines
        with open(srec_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            
            # Non-S3 records - keep as-is
            if not line or not line.startswith('S3'):
                output_lines.append(line)
                continue
            
            # Parse S3 record
            count = int(line[2:4], 16)
            addr = int(line[4:12], 16)
            data_len = count - 5
            record_end = addr + data_len
            
            # Check if this record overlaps with customer key zone
            overlaps = not (record_end <= start_addr or addr >= key_end)
            
            if not overlaps:
                # No overlap - keep original line UNCHANGED
                output_lines.append(line)
                continue
            
            # This record contains customer key zone - inject key bytes
            data_hex = line[12:12 + data_len * 2]
            data = bytearray.fromhex(data_hex)
            
            # Calculate overlap range within this record
            inject_start = max(0, start_addr - addr)
            inject_end = min(data_len, key_end - addr)
            key_offset = max(0, addr - start_addr)
            
            # Inject key bytes
            for i in range(inject_start, inject_end):
                data[i] = key_data[key_offset + (i - inject_start)]
            
            # Rebuild S3 record with new checksum
            record_data = f"{count:02X}{addr:08X}{data.hex().upper()}"
            checksum = self.calculate_checksum(record_data)
            new_line = f"S3{record_data}{checksum:02X}"
            output_lines.append(new_line)
        
        # Write back
        with open(srec_file, 'w') as f:
            for line in output_lines:
                f.write(line + "\n")
        
        # FIX: Regenerate S5 record count (srec_cat validates this)
        data_record_count = sum(1 for line in output_lines if line.startswith(('S1', 'S2', 'S3')))
        
        # Rebuild file with correct S5
        final_lines = []
        for line in output_lines:
            if line.startswith('S5'):
                # Replace old S5 with correct count
                s5_data = f"S503{data_record_count:04X}"
                s5_checksum = self.calculate_checksum(s5_data[2:])
                final_lines.append(f"{s5_data}{s5_checksum:02X}")
            else:
                final_lines.append(line)
        
        # Write final version
        with open(srec_file, 'w') as f:
            for line in final_lines:
                f.write(line + "\n")
    
    def offset_addresses(self, input_file: Path, output_file: Path, offset: int) -> None:
        """
        Offset all addresses in an SREC file by the given value.
        
        Args:
            input_file: Input SREC file
            output_file: Output SREC file
            offset: Address offset to apply (can be negative)
        """
        # Read as binary to handle signed SREC files (may contain binary data)
        try:
            content = input_file.read_text(encoding='latin-1')
            lines = content.splitlines()
        except Exception:
            # Fallback: read as binary and decode line by line
            with open(input_file, 'rb') as f:
                lines = [line.decode('latin-1', errors='ignore').strip() for line in f]
        
        output_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Parse SREC record type
            if line.startswith('S0') or line.startswith('S4') or line.startswith('S5') or line.startswith('S6'):
                # Header, reserved, or count records - keep as is
                output_lines.append(line)
            elif line.startswith('S1') or line.startswith('S2') or line.startswith('S3'):
                # Data records - offset address
                record_type = line[:2]
                byte_count = int(line[2:4], 16)
                
                if record_type == 'S1':
                    addr_len = 4  # 2 bytes
                elif record_type == 'S2':
                    addr_len = 6  # 3 bytes
                else:  # S3
                    addr_len = 8  # 4 bytes
                
                address = int(line[4:4+addr_len], 16)
                new_address = address + offset
                
                # Rebuild the record
                data_and_checksum = line[4+addr_len:]
                data = data_and_checksum[:-2]  # Remove old checksum
                
                # Create new address string
                if record_type == 'S1':
                    new_addr_str = f"{new_address:04X}"
                elif record_type == 'S2':
                    new_addr_str = f"{new_address:06X}"
                else:
                    new_addr_str = f"{new_address:08X}"
                
                # Recalculate checksum
                new_record = f"{record_type}{byte_count:02X}{new_addr_str}{data}"
                checksum = self.calculate_checksum(new_record[2:])
                new_record += f"{checksum:02X}"
                
                output_lines.append(new_record)
            elif line.startswith('S7') or line.startswith('S8') or line.startswith('S9'):
                # End records - offset start address
                record_type = line[:2]
                byte_count = int(line[2:4], 16)
                
                if record_type == 'S9':
                    addr_len = 4
                elif record_type == 'S8':
                    addr_len = 6
                else:  # S7
                    addr_len = 8
                
                address = int(line[4:4+addr_len], 16)
                new_address = address + offset
                
                # Rebuild
                if record_type == 'S9':
                    new_addr_str = f"{new_address:04X}"
                elif record_type == 'S8':
                    new_addr_str = f"{new_address:06X}"
                else:
                    new_addr_str = f"{new_address:08X}"
                
                new_record = f"{record_type}{byte_count:02X}{new_addr_str}"
                checksum = self.calculate_checksum(new_record[2:])
                new_record += f"{checksum:02X}"
                
                output_lines.append(new_record)
            else:
                output_lines.append(line)
        
        output_file.write_text('\n'.join(output_lines) + '\n')
    
    def _coalesce_records(self, records: List[str]) -> List[str]:
        """
        Coalesce contiguous SREC records into larger records.
        
        Args:
            records: List of SREC record strings
            
        Returns:
            List of coalesced SREC record strings
        """
        if not records:
            return []
        
        # Parse all records into (address, data) tuples
        parsed = []
        for record in records:
            if not record.startswith('S3'):
                # Keep non-S3 records as-is
                parsed.append((None, None, record))
                continue
            
            count = int(record[2:4], 16)
            addr = int(record[4:12], 16)
            data_len = count - 5  # count = addr(4) + data + checksum(1)
            data = bytes.fromhex(record[12:12 + data_len * 2])
            parsed.append((addr, data, None))
        
        # Merge consecutive records
        coalesced = []
        i = 0
        while i < len(parsed):
            addr, data, original = parsed[i]
            
            if addr is None:
                # Non-S3 record - keep as-is
                coalesced.append(original)
                i += 1
                continue
            
            # Start a merge group
            merged_data = bytearray(data)
            next_expected_addr = addr + len(data)
            j = i + 1
            
            # Look for consecutive records
            while j < len(parsed):
                next_addr, next_data, next_orig = parsed[j]
                if next_addr is None:
                    break
                if next_addr == next_expected_addr:
                    # Consecutive merge it
                    merged_data.extend(next_data)
                    next_expected_addr = next_addr + len(next_data)
                    j += 1
                else:
                    break
            
            # Create coalesced S3 record
            data_len = len(merged_data)
            count = data_len + 5  # addr(4) + data + checksum(1)
            record_str = f"S3{count:02X}{addr:08X}{merged_data.hex().upper()}"
            checksum = self.calculate_checksum(record_str[2:])
            coalesced.append(f"{record_str}{checksum:02X}")
            
            # Skip merged records
            i = j
        
        return coalesced
