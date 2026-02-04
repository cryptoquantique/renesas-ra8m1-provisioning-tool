"""
MCUboot Public Key Injector

Injects AWS KMS public key into bootloader SREC at the address where
MCUboot expects root_pub_der[] (compiled from keys.c).

This allows using AWS KMS keys without recompiling the bootloader!
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def calculate_srec_checksum(data_hex: str) -> int:
    """Calculate SREC checksum (one's complement of sum of bytes)."""
    total = sum(bytes.fromhex(data_hex))
    return (~total) & 0xFF


def inject_key_into_srec(
    srec_file: Path,
    key_der: bytes,
    key_address: int,
    output_file: Optional[Path] = None
) -> Path:
    """
    Inject a public key into SREC file at specified address.
    
    Args:
        srec_file: Input SREC file (bootloader)
        key_der: Public key in DER format (91 bytes for EC P-256)
        key_address: Address where key should be written (e.g., 0x02009114)
        output_file: Output SREC file. If None, modifies in place.
        
    Returns:
        Path to output SREC file
    """
    if not srec_file.exists():
        raise FileNotFoundError(f"SREC file not found: {srec_file}")
    
    if len(key_der) != 91:
        logger.warning(f"Key length {len(key_der)} != 91 (expected for EC P-256)")
    
    output_file = output_file or srec_file
    
    logger.info(f"Injecting {len(key_der)}-byte key at 0x{key_address:08X}")
    logger.info(f"Input:  {srec_file}")
    logger.info(f"Output: {output_file}")

    with open(srec_file, 'r') as f:
        lines = f.readlines()
    
    # Find and replace lines containing key data
    key_end_address = key_address + len(key_der)
    modified_lines = []
    key_bytes_written = 0
    
    for line in lines:
        line = line.strip()
        if not line:
            modified_lines.append(line)
            continue
        
        # Parse S3 records (32-bit address)
        if line.startswith('S3'):
            byte_count = int(line[2:4], 16)
            record_addr = int(line[4:12], 16)
            data_len = byte_count - 5  # minus 4 addr bytes and 1 checksum byte
            data_hex = line[12:12 + data_len * 2]
            record_end_addr = record_addr + data_len
            
            # Check if this record overlaps with key address range
            if record_addr < key_end_address and record_end_addr > key_address:
                new_data = bytearray(bytes.fromhex(data_hex))
                
                for i in range(data_len):
                    byte_addr = record_addr + i
                    if key_address <= byte_addr < key_end_address:
                        key_offset = byte_addr - key_address
                        new_data[i] = key_der[key_offset]
                        key_bytes_written += 1
                
                # Rebuild S3 record with new data and checksum
                new_data_hex = new_data.hex().upper()
                checksum_data = f"{byte_count:02X}{record_addr:08X}{new_data_hex}"
                new_checksum = calculate_srec_checksum(checksum_data)
                new_line = f"S3{checksum_data}{new_checksum:02X}"
                
                logger.debug(f"Modified: 0x{record_addr:08X} ({data_len} bytes)")
                modified_lines.append(new_line)
            else:
                modified_lines.append(line)
        else:
            modified_lines.append(line)

    with open(output_file, 'w') as f:
        for line in modified_lines:
            f.write(line + '\n')
    
    logger.info(f"[OK] Injected {key_bytes_written} key bytes into SREC")
    
    if key_bytes_written != len(key_der):
        logger.warning(f"Expected {len(key_der)} bytes, wrote {key_bytes_written}")
    
    return output_file


def inject_aws_kms_key(
    srec_file: Path,
    kms_key_id: str,
    key_address: int,
    aws_config: dict,
    output_file: Optional[Path] = None
) -> Path:
    """
    Inject AWS KMS public key into SREC file.
    
    Args:
        srec_file: Input SREC file (bootloader)
        kms_key_id: AWS KMS Key ID for mcuboot_app_key
        key_address: Address where key should be written
        aws_config: AWS credentials dict
        output_file: Output SREC file
        
    Returns:
        Path to output SREC file
    """
    import boto3
    kms = boto3.client(
        'kms',
        region_name=aws_config.get('region', 'eu-central-1'),
        aws_access_key_id=aws_config.get('access_key_id'),
        aws_secret_access_key=aws_config.get('secret_access_key')
    )
    
    response = kms.get_public_key(KeyId=kms_key_id)
    key_der = response['PublicKey']
    
    logger.info(f"Retrieved {len(key_der)}-byte public key from AWS KMS")
    logger.info(f"Key ID: {kms_key_id}")
    
    return inject_key_into_srec(srec_file, key_der, key_address, output_file)
