"""
CloudHSM PKCS#11-based firmware signing - MANDATORY!

This replaces AWS KMS completely!
Uses CloudHSM PKCS#11 for all signing operations.
"""

from pathlib import Path
from typing import Optional

from config.settings import HSMConfig
from firmware.imgtool_runner import sign_image as imgtool_sign
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem
from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)


def sign_image_with_cloudhsm(
    input_file: Path,
    output_file: Path,
    key_label: str,
    config: HSMConfig,
    header_size: int,
    align: int,
    max_align: int,
    slot_size: int,
    max_sectors: int,
    version: str,
    pad_header: bool,
    pad: bool,
    confirm: bool,
) -> None:
    """
    Sign firmware image using CloudHSM PKCS#11.
    
    ALL PARAMETERS ARE REQUIRED (read from project_config.json).
    NO default values - caller MUST provide all parameters.
    
    Args:
        input_file: Application binary to sign
        output_file: Signed output file
        key_label: Key label in CloudHSM
        config: HSM configuration
        header_size: MCUboot header size (from imgtool.header_size)
        align: Flash alignment (from imgtool.align)
        max_align: Maximum flash alignment (from imgtool.max_align)
        slot_size: Image slot size (from imgtool.slot_size)
        max_sectors: Maximum sectors (from imgtool.max_sectors)
        version: Image version string (from imgtool.version)
        pad_header: Pad header to header_size (from imgtool.pad_header)
        pad: Pad image to slot_size (from imgtool.pad)
        confirm: Set image as confirmed (from imgtool.confirm)
    """
    if not input_file.exists():
        raise FirmwareError(f"Input file not found: {input_file}")
    
    logger.info("")
    logger.info("="*70)
    logger.info("CLOUDHSM PKCS#11 FIRMWARE SIGNING - MANDATORY!")
    logger.info("="*70)
    logger.info(f"  Input:  {input_file}")
    logger.info(f"  Output: {output_file}")
    logger.info(f"  Key:    {key_label}")
    
    try:
        # Connect to CloudHSM
        hsm_client = create_hsm_client(config)
        hsm_client.connect()
        
        logger.info("")
        logger.info("STEP 1: Export public key from CloudHSM")
        logger.info("-" * 70)
        
        # Get public key (for imgtool signing)
        public_key_der = hsm_client.get_public_key(key_label)
        logger.info(f"  Public key: {len(public_key_der)} bytes (DER)")
        
        # Save public key to temp PEM file (imgtool needs PEM format)
        temp_public_key = output_file.parent / f"{key_label}_public.pem"
        save_public_key_pem(public_key_der, temp_public_key)
        logger.info(f"  Saved to: {temp_public_key}")
        
        logger.info("")
        logger.info("STEP 2: Sign with imgtool (using CloudHSM key)")
        logger.info("-" * 70)
        logger.info("  NOTE: imgtool will create dummy signature")
        logger.info("  We'll replace it with CloudHSM signature!")
        
        # Create dummy signed image using imgtool
        # This gives us correct MCUboot structure
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Generate temporary private key for dummy signing
        temp_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        temp_key_pem = output_file.parent / f"temp_sign_key.pem"
        
        with open(temp_key_pem, 'wb') as f:
            f.write(temp_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Sign with imgtool (dummy signature)
        dummy_output = output_file.parent / f"{output_file.stem}_dummy{output_file.suffix}"
        
        imgtool_sign(
            input_file=input_file,
            output_file=dummy_output,
            key_file=temp_key_pem,
            header_size=header_size,
            align=align,
            max_align=max_align,
            slot_size=slot_size,
            max_sectors=max_sectors,
            version=version,
            pad_header=pad_header,
            pad=pad,
            confirm=confirm,
        )
        
        logger.info(f"  [OK] Dummy signed: {dummy_output.stat().st_size} bytes")
        
        logger.info("")
        logger.info("STEP 3: Extract hash from dummy image")
        logger.info("-" * 70)
        
        # Read dummy image and extract protected data hash
        dummy_data = dummy_output.read_bytes()
        
        # Parse MCUboot header
        import struct
        magic = struct.unpack('<I', dummy_data[0:4])[0]
        if magic != 0x96F3B83D:
            raise FirmwareError(f"Invalid MCUboot magic: 0x{magic:08X}")
        
        img_size = struct.unpack('<I', dummy_data[0x14:0x18])[0]
        tlv_start = header_size + img_size
        
        # Find SHA256 TLV (type=0x0010)
        offset = tlv_start + 4  # Skip TLV_INFO header
        sha256_hash = None
        
        while offset < len(dummy_data):
            tlv_type, tlv_len = struct.unpack('<HH', dummy_data[offset:offset+4])
            if tlv_type == 0xFFFF:  # End marker
                break
            if tlv_type == 0x0010:  # SHA256
                sha256_hash = dummy_data[offset+4:offset+4+tlv_len]
                break
            offset += 4 + tlv_len
        
        if not sha256_hash:
            raise FirmwareError("SHA256 hash not found in TLV!")
        
        logger.info(f"  [OK] SHA256 hash: {sha256_hash.hex()}")
        
        logger.info("")
        logger.info("STEP 4: Sign hash with CloudHSM")
        logger.info("-" * 70)
        
        # Sign with CloudHSM
        signature_der = hsm_client.sign_digest(key_label, sha256_hash)
        logger.info(f"  [OK] CloudHSM signature: {len(signature_der)} bytes (DER)")
        
        logger.info("")
        logger.info("STEP 5: Replace dummy signature with CloudHSM signature")
        logger.info("-" * 70)

        offset = tlv_start + 4
        sig_offset = None
        sig_len = None
        
        while offset < len(dummy_data):
            tlv_type, tlv_len = struct.unpack('<HH', dummy_data[offset:offset+4])
            if tlv_type == 0xFFFF:
                break
            if tlv_type == 0x0022:  # ECDSA signature
                sig_offset = offset
                sig_len = tlv_len
                break
            offset += 4 + tlv_len
        
        if sig_offset is None:
            raise FirmwareError("Signature TLV not found!")
        
        logger.info(f"  Dummy signature: {sig_len} bytes at offset 0x{sig_offset:X}")
        logger.info(f"  CloudHSM signature: {len(signature_der)} bytes")

        final_data = bytearray(dummy_data)

        final_data[sig_offset:sig_offset+4] = struct.pack('<HH', 0x0022, len(signature_der))
        final_data[sig_offset+4:sig_offset+4+len(signature_der)] = signature_der

        tlv_entries_size = 0
        offset = tlv_start + 4
        while offset < len(final_data):
            tlv_type, tlv_len = struct.unpack('<HH', final_data[offset:offset+4])
            if tlv_type == 0xFFFF:
                break
            tlv_entries_size += 4 + tlv_len
            offset += 4 + tlv_len
        
        # Update TLV_INFO total length
        final_data[tlv_start+2:tlv_start+4] = struct.pack('<H', tlv_entries_size)
        
        logger.info(f"  [OK] Signature TLV: len={len(signature_der)} (DER EXACT, NO PADDING!)")
        logger.info(f"  [OK] TLV total length: {tlv_entries_size} bytes")
        
        # Write final image
        output_file.write_bytes(bytes(final_data[:slot_size]))
        logger.info(f"  [OK] Final image: {output_file.stat().st_size} bytes")
        
        # Cleanup
        temp_key_pem.unlink()
        temp_public_key.unlink()
        dummy_output.unlink()
        
        logger.info("")
        logger.info("="*70)
        logger.info("SUCCESS! Firmware signed with CloudHSM PKCS#11!")
        logger.info("="*70)
        logger.info(f"  Output: {output_file}")
        logger.info(f"  Size: {output_file.stat().st_size} bytes")
        
    except Exception as e:
        logger.error(f"CloudHSM signing failed: {str(e)}")
        raise FirmwareError(f"CloudHSM signing failed: {str(e)}") from e
    finally:
        try:
            hsm_client.disconnect()
        except:
            pass
