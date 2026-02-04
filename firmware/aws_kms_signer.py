"""
AWS KMS firmware signer.

This module provides functionality to sign firmware images using AWS KMS keys.
Since AWS KMS keys cannot be exported, we use a workaround:
1. Export public key from AWS KMS
2. Use imgtool with a dummy/temporary key to create image structure
3. Sign the hash with AWS KMS
4. Replace signature in the image

Note: This is a simplified approach. For production, consider using
imgtool's Python API directly or implementing full MCUboot image format support.
"""

import tempfile
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Optional

from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem
from models.keys import KeyCurve
from utils.exceptions import FirmwareError, HSMError
from utils.logging import get_logger
from config.settings import HSMConfig

logger = get_logger(__name__)


def sign_image_with_aws_kms(
    input_file: Path,
    output_file: Path,
    aws_kms_key_id: str,
    config: HSMConfig,
    header_size: int = 0x200,
    align: int = 8,
    max_align: int = 8,
    slot_size: int = 0,
    max_sectors: int = 29,
    version: Optional[str] = None,
    pad_header: bool = True,
    pad: bool = False,
    confirm: bool = False,
) -> None:
    """
    Sign firmware image using AWS KMS key.

    This function creates the MCUboot image structure and signs it using AWS KMS.
    Since AWS KMS keys cannot be exported, we:
    1. Create the image structure using imgtool
    2. Extract the hash that needs to be signed
    3. Sign the hash using AWS KMS
    4. Inject the signature back into the image

    Args:
        input_file: Path to input firmware binary
        output_file: Path to output signed firmware binary
        aws_kms_key_id: AWS KMS Key ID or ARN
        config: HSMConfig instance
        header_size: Size of image header in bytes
        align: Flash alignment requirement
        max_align: Maximum flash alignment
        slot_size: Size of image slot (0 = auto)
        max_sectors: Maximum number of sectors
        version: Image version string
        pad_header: Pad header to header_size
        pad: Pad image to slot_size (WITHOUT trailer magic)
        confirm: Confirm image upgrade (adds trailer magic - use with pad)

    Raises:
        FirmwareError: If signing fails
    """
    if not input_file.exists():
        raise FirmwareError(f"Input file not found: {input_file}")

    try:
        # Connect to AWS KMS
        hsm_client = create_hsm_client(config)
        hsm_client.connect()

        # Get public key from AWS KMS to determine curve
        public_key_der = hsm_client.get_public_key(aws_kms_key_id)
        
        # Determine curve from key spec
        try:
            key_info = hsm_client.kms_client.describe_key(KeyId=aws_kms_key_id)
            key_spec = key_info["KeyMetadata"]["KeySpec"]
            
            curve_map = {
                "ECC_NIST_P256": KeyCurve.SECP256R1,
                "ECC_NIST_P384": KeyCurve.SECP384R1,
                "ECC_NIST_P521": KeyCurve.SECP521R1,
            }
            
            if key_spec not in curve_map:
                raise FirmwareError(f"Unsupported key spec for signing: {key_spec}")
            
            curve = curve_map[key_spec]
        except Exception as e:
            raise FirmwareError(f"Failed to determine key curve: {str(e)}") from e

        # For now, use a workaround: export public key and use imgtool normally
        # In the future, we can implement direct signing with AWS KMS
        # by manipulating the image structure directly
        
        # Export public key to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp_key:
            tmp_key_path = Path(tmp_key.name)
            save_public_key_pem(public_key_der, tmp_key_path, curve)

        try:
            # Import imgtool modules
            try:
                from imgtool import image
                from imgtool.main import getpubhash
                import hashlib
            except ImportError:
                raise FirmwareError(
                    "imgtool is not installed.\n\n"
                    "To install imgtool, run:\n"
                    "  pip install imgtool\n\n"
                    "Or if using a virtual environment, activate it first:\n"
                    "  pip install -r requirements.txt"
                )
            
            # Load and prepare image
            img = image.Image()
            img.pad_header = pad_header
            img.load(path=str(input_file))
            
            # Set image properties
            if version:
                from imgtool.main import decode_version
                img_version = decode_version(version)
                img.version = img_version
            
            # Note: img_size and flags are set automatically by imgtool
            # when creating the image structure
            if confirm:
                img.confirm = True
            
            if slot_size > 0:
                img.slot_size = slot_size
            
            # Use imgtool to create image structure, then replace signature with AWS KMS signature
            # Since AWS KMS keys can't be exported, we:
            # 1. Create image structure with imgtool using a temporary key
            # 2. Extract the hash that was signed
            # 3. Sign the same hash with AWS KMS
            # 4. Replace signature in the image
            
            from security.key_utils import generate_local_key_pair
            from models.keys import KeyType
            import tempfile as tf
            
            with tf.TemporaryDirectory() as tmpdir:
                tmp_key_dir = Path(tmpdir)
                # Generate a temporary key pair for structure creation
                _, tmp_priv_key, _ = generate_local_key_pair(
                    KeyType.CUSTOMER, curve, tmp_key_dir
                )
                
                # Use imgtool to create the image structure (signed with temp key)
                tmp_signed = tmp_key_dir / "tmp_signed.bin"
                
                from firmware.imgtool_wrapper import ImgToolWrapper
                imgtool_wrapper = ImgToolWrapper()
                imgtool_wrapper.sign_image(
                    input_file=input_file,
                    output_file=tmp_signed,
                    key_file=tmp_priv_key,
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
                
                # Load the signed image to extract hash and replace signature
                # Must set pad_header before loading to match the signed image format
                signed_img = image.Image()
                signed_img.pad_header = pad_header
                signed_img.load(path=str(tmp_signed))
                
                # Get the hash that was signed (from image_hash or calculate from payload)
                image_hash = signed_img.image_hash
                if not image_hash or len(image_hash) == 0:
                    # Calculate hash from payload if not available
                    payload = signed_img.payload
                    image_hash = hashlib.sha256(payload).digest()
                
                logger.info(f"Image hash to sign: {image_hash.hex()[:32]}...")
                
                # Sign hash using AWS KMS
                signature = hsm_client.sign_data(aws_kms_key_id, image_hash)
                logger.info(f"Signature from AWS KMS: {len(signature)} bytes")
                
                # Replace signature in the image
                signed_img.signature = signature
                
                # CRITICAL: signed_img.save() LOSES padding from imgtool --pad!
                # Solution: Directly modify tmp_signed binary to replace signature
                # Instead of saving with signed_img.save() which recreates the image structure
                
                # Read the tmp_signed binary (has correct padding from imgtool)
                with open(tmp_signed, 'rb') as f:
                    signed_data = f.read()
                
                logger.info(f"tmp_signed size (with padding): {len(signed_data)} bytes (0x{len(signed_data):X})")
                
                # Find signature offset in TLV section
                # Signature TLV starts after image data
                # Format: [Header(32)] [Payload] [TLV: Type(2) Len(2) Signature]
                # We need to replace the signature bytes in the TLV
                
                from imgtool.image import TLV_VALUES
                SIG_TLV_TYPE = TLV_VALUES["ECDSASIG"]  # 0x0022 for ECDSA signature
                
                # Search for signature TLV (type 0x0022)
                # TLV format: [Type(2 bytes BE)] [Len(2 bytes BE)] [Data]
                import struct
                
                # Find TLV section (after payload)
                # signed_img.header_size + signed_img.payload size
                tlv_start = header_size + len(signed_img.payload) - header_size
                
                if tlv_start < len(signed_data):
                    # Search for signature TLV in TLV section
                    offset = tlv_start
                    while offset < len(signed_data) - 4:
                        tlv_type, tlv_len = struct.unpack('>HH', signed_data[offset:offset+4])
                        
                        if tlv_type == SIG_TLV_TYPE:
                            # Found signature TLV
                            sig_offset = offset + 4
                            old_sig_len = tlv_len
                            
                            logger.info(f"Found signature TLV at offset 0x{offset:X}, length {old_sig_len}")
                            
                            if len(signature) != old_sig_len:
                                logger.warning(f"Signature length mismatch: AWS KMS={len(signature)}, TLV={old_sig_len}")
                            
                            # Replace signature
                            signed_data = signed_data[:sig_offset] + signature + signed_data[sig_offset + len(signature):]
                            
                            logger.info(f"Replaced signature at offset 0x{sig_offset:X}")
                            break
                        
                        # Move to next TLV
                        offset += 4 + tlv_len
                
                # Save the modified binary (preserves padding!)
                tmp_bin_final = tmp_key_dir / "final_signed.bin"
                with open(tmp_bin_final, 'wb') as f:
                    f.write(signed_data)
                
                logger.info(f"Final signed image size: {len(signed_data)} bytes (0x{len(signed_data):X})")
                
                # CRITICAL FIX: Remove MCUboot trailer magic if present
                # imgtool --pad adds boot_magic at the end
                # Standard: 77C295F360D2AF7F, but byte 6 can vary (erased_val dependent)
                # Renesas Secure Boot does NOT use this trailer!
                BOOT_MAGIC_START = bytes([0x77, 0xc2, 0x95, 0xf3])  # First 4 bytes are constant
                
                if pad and len(signed_data) >= 16:
                    # Check last 16 bytes for boot_magic (first 4 bytes)
                    last_16 = signed_data[-16:]
                    
                    # Search for boot_magic pattern (77C295F3)
                    magic_pos_in_chunk = -1
                    for i in range(len(last_16) - 3):
                        if last_16[i:i+4] == BOOT_MAGIC_START:
                            magic_pos_in_chunk = i
                            break
                    
                    if magic_pos_in_chunk >= 0:
                        global_pos = len(signed_data) - 16 + magic_pos_in_chunk
                        
                        logger.info(f"[FIX] Found MCUboot trailer magic at offset 0x{global_pos:X}")
                        
                        # Full boot_magic is 8 bytes: 77C295F3 60D2xxxx (xx can vary)
                        magic_len = 8
                        
                        # Replace boot_magic with 0xFF
                        signed_data = signed_data[:global_pos] + (b'\xFF' * magic_len) + signed_data[global_pos + magic_len:]
                        
                        logger.info(f"[FIX] Replaced boot_magic with 0xFF (8 bytes)")
                        
                        # CRITICAL: Also check for image_ok flag (0x01) BEFORE magic
                        # MCUboot puts this at: (slot_end - trailer_size + image_ok_offset)
                        # For slot_size=0x20000, trailer ~512 bytes, image_ok is at slot_end - 256 - 8
                        # Which is at offset: 0x1FF00 (0x20000 - 0x100)
                        IMAGE_OK_OFFSET = 0x1FF00  # Fixed offset for 128KB slot
                        
                        if IMAGE_OK_OFFSET < len(signed_data):
                            if signed_data[IMAGE_OK_OFFSET] == 0x01:
                                logger.info(f"[FIX] Found image_ok flag (0x01) at offset 0x{IMAGE_OK_OFFSET:X}")
                                signed_data = signed_data[:IMAGE_OK_OFFSET] + b'\xFF' + signed_data[IMAGE_OK_OFFSET + 1:]
                                logger.info(f"[FIX] Replaced image_ok flag with 0xFF")
                        
                        # Write back cleaned binary
                        with open(tmp_bin_final, 'wb') as f:
                            f.write(signed_data)
                        
                        logger.info(f"[OK] Trailer magic removed, image is now Renesas-compliant")
                
                # CRITICAL FIX: imgtool.Image.save() adds 32 bytes of 0xFF padding at the start
                # We no longer use signed_img.save(), so this is NOT needed anymore!
                # (Keeping code commented for reference)
                # if len(data) >= 32 and data[:32] == bytes([0xFF] * 32):
                #     logger.info("[FIX] Removing 32 bytes of alignment padding")
                #     with open(tmp_bin_final, 'wb') as f:
                #         f.write(data[32:])
                
                # Determine output format from file extension
                output_ext = output_file.suffix.lower()
                
                # Copy signed binary to output
                shutil.copy(tmp_bin_final, output_file)
                
                if output_ext in ['.srec', '.s19', '.s28', '.s37', '.hex', '.ihex']:
                    logger.warning(
                        f"Output format {output_ext} requested. "
                        f"File saved as binary. For SREC/HEX conversion, use: "
                        f"objcopy -I binary -O srec {output_file} {output_file}"
                    )
            logger.info(f"Firmware signed successfully with AWS KMS key {aws_kms_key_id}: {output_file}")

        finally:
            # Clean up temporary key file
            if tmp_key_path.exists():
                try:
                    tmp_key_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete temporary key file {tmp_key_path}: {e}")

        hsm_client.disconnect()

    except HSMError as e:
        raise FirmwareError(f"AWS KMS signing failed: {str(e)}") from e
    except Exception as e:
        raise FirmwareError(f"Unexpected error signing with AWS KMS: {str(e)}") from e

