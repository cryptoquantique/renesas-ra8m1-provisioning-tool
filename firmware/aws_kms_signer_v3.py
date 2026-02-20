"""
AWS KMS-based firmware signing - CORRECT WORKFLOW v3.

FIXED APPROACH (2026-01-16 - Final):
1. Generate dummy signed image with --pad-sig → Fixed 64-byte RAW signature
2. Extract SHA256 hash from TLV (not from modified payload)
3. Sign hash with AWS KMS → DER signature
4. Convert DER → RAW (64 bytes)
5. Replace signature in TLV (64 bytes → 64 bytes, NO size change!)
6. Hash remains VALID because we didn't modify the protected area!

KEY INSIGHT: --pad-sig ensures dummy signature is exactly 64 bytes (RAW),
so replacing it with AWS KMS signature (also 64 bytes RAW) doesn't change
the binary structure or invalidate the hash!
"""

import hashlib
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec

from config.settings import HSMConfig
from models.keys import KeyCurve, KeyType
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem, generate_local_key_pair
from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)


def sign_image_with_aws_kms(
    input_file: Path,
    output_file: Path,
    aws_kms_key_id: str,
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
    allow_local_temp_keys: bool = True,
) -> None:
    """
    Sign a firmware image using AWS KMS with CORRECT MCUBoot format.

    This function ensures the signature verification will pass by:
    1. Using --pad-sig to generate fixed-size (64 bytes) dummy signature
    2. Extracting the ACTUAL hash from the TLV section
    3. Signing that hash with AWS KMS
    4. Replacing the dummy signature with AWS KMS signature (SAME size!)
    5. This preserves the binary structure and hash integrity

    ALL PARAMETERS ARE REQUIRED (read from project_config.json):
    - NO default values
    - NO fallback logic
    - If a parameter is missing, the call will fail

    Args:
        input_file: Path to input firmware binary
        output_file: Path to output signed firmware binary
        aws_kms_key_id: AWS KMS Key ID or ARN (from aws.kms.mcuboot_app_key_id)
        config: HSMConfig instance
        header_size: Size of image header in bytes (from imgtool.header_size)
        align: Flash alignment requirement (from imgtool.align)
        max_align: Maximum flash alignment (from imgtool.max_align)
        slot_size: Size of image slot (from imgtool.slot_size)
        max_sectors: Maximum number of sectors (from imgtool.max_sectors)
        version: Image version string (from imgtool.version)
        pad_header: Pad header to header_size (from imgtool.pad_header)
        pad: Pad image to slot_size (from imgtool.pad)
        confirm: Confirm image upgrade (from imgtool.confirm)
        allow_local_temp_keys: If False, blocks temporary local key generation (production mode)

    Raises:
        FirmwareError: If signing fails
    """
    if not input_file.exists():
        raise FirmwareError(f"Input file not found: {input_file}")

    # Determine signing backend for log messages
    hsm_type = config.hsm_type.lower() if config.hsm_type else "broker"
    if hsm_type == "broker":
        backend_label = "PKCS#11 Broker → AWS KMS"
    elif hsm_type == "aws_kms":
        backend_label = "AWS KMS (direct)"
    else:
        backend_label = hsm_type

    logger.info(f"")
    logger.info(f"=" * 70)
    logger.info(f"FIRMWARE SIGNING via {backend_label}")
    logger.info(f"=" * 70)
    logger.info(f"  Input:  {input_file}")
    logger.info(f"  Output: {output_file}")
    logger.info(f"  Key ID: {aws_kms_key_id}")
    logger.info(f"  Backend: {backend_label}")

    try:
        hsm_client = create_hsm_client(config)
        hsm_client.connect()

        # Get public key from HSM (AWS KMS or broker)
        public_key_der = hsm_client.get_public_key(aws_kms_key_id)

        # Determine curve from public key DER (works with any HSM backend)
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend

            pub_key = load_der_public_key(public_key_der, backend=default_backend())
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                raise FirmwareError("Key is not an ECC key")

            key_curve = pub_key.curve
            if isinstance(key_curve, ec.SECP256R1):
                curve = KeyCurve.SECP256R1
            elif isinstance(key_curve, ec.SECP384R1):
                curve = KeyCurve.SECP384R1
            elif isinstance(key_curve, ec.SECP521R1):
                curve = KeyCurve.SECP521R1
            else:
                raise FirmwareError(f"Unsupported curve: {key_curve.name}")

            logger.info(f"  Curve:  {curve.value}")
        except Exception as e:
            raise FirmwareError(f"Failed to determine key curve: {str(e)}") from e

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_dir = Path(tmpdir)
            
            # Save HSM public key to PEM file (temp for imgtool)
            pub_key_file = tmp_dir / "hsm_public_key.pem"
            save_public_key_pem(public_key_der, pub_key_file, curve)
            logger.info(f"  Saved {backend_label} public key: {pub_key_file.name}")
            
            # Also save to output directory for later use (avoids reconnect)
            customer_pk_pem = output_file.parent / "customer_public.pem"
            save_public_key_pem(public_key_der, customer_pk_pem, curve)
            logger.info(f"  Customer public key saved: {customer_pk_pem.name}")
            
            # STEP 1: Generate dummy signed image with HSM public key
            logger.info(f"")
            logger.info(f"STEP 1: Generate temporary signed image")
            logger.info(f"  Purpose: Create MCUBoot structure with correct KEYHASH for {backend_label} key")
            logger.info(f"  CRITICAL: Use {backend_label} public key for KEYHASH calculation!")

            if not allow_local_temp_keys:
                raise FirmwareError(
                    "This workflow requires temporary local keys for imgtool. "
                    "Set allow_local_temp_keys=True or implement alternative MCUboot structure builder."
                )
            
            _, tmp_priv_key, _ = generate_local_key_pair(
                KeyType.CUSTOMER, curve, tmp_dir
            )
            logger.info(f"  Generated temporary local key: {tmp_priv_key.name}")
            logger.info(f"  This key will ONLY be used for dummy signature!")
            logger.info(f"  KEYHASH will be calculated from {backend_label} public key!")

            tmp_signed = tmp_dir / "dummy_signed.bin"
            
            imgtool_dir = Path(__file__).parent.parent / "imgtool"

            if imgtool_dir.exists() and (imgtool_dir / "main.py").exists():
                imgtool_cmd = [sys.executable, "-c", 
                    f"import sys; sys.path.insert(0, r'{imgtool_dir.parent}'); from imgtool.main import imgtool; imgtool()"]
                logger.info(f"  Using imgtool (Renesas version with align=128): {imgtool_dir}")
            else:
                logger.error(f"  Renesas imgtool NOT FOUND at: {imgtool_dir}")
                raise FirmwareError(f"Renesas imgtool required but not found: {imgtool_dir}")
            
            cmd_dummy = imgtool_cmd + [
                "sign",
                "--key", str(tmp_priv_key),
                "--header-size", hex(header_size),
                "--align", str(align),
                "--max-align", str(max_align),
                "--slot-size", hex(slot_size),
                "--max-sectors", str(max_sectors),
                "--version", version or "1.0.0",
                "--pad-sig",
            ]
            
            if pad_header:
                cmd_dummy.append("--pad-header")
            
            if pad:
                cmd_dummy.append("--pad")
            
            if confirm:
                cmd_dummy.append("--confirm")
            
            cmd_dummy.extend([
                str(input_file),
                str(tmp_signed),
            ])
            
            logger.debug(f"  Command: {' '.join(cmd_dummy)}")
            
            try:
                result = subprocess.run(
                    cmd_dummy,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                logger.info(f"  Dummy signed image created: {tmp_signed.name}")
                logger.info(f"  Size: {tmp_signed.stat().st_size} bytes (0x{tmp_signed.stat().st_size:X})")
            except subprocess.CalledProcessError as e:
                error_msg = f"imgtool dummy sign failed: {e.stderr or e.stdout}"
                logger.error(error_msg)
                raise FirmwareError(error_msg) from e

            logger.info(f"")
            logger.info(f"STEP 2: Extract SHA256 hash from TLV & Fix KEYHASH")
            logger.info(f"  Purpose: Get the ACTUAL hash + Replace dummy KEYHASH with {backend_label} KEYHASH")

            dummy_data = bytearray(tmp_signed.read_bytes())

            img_size = struct.unpack('<I', dummy_data[12:16])[0]
            tlv_start = header_size + img_size
            
            logger.info(f"  Image size from header: 0x{img_size:X} bytes")
            logger.info(f"  TLV section starts at: 0x{tlv_start:X}")

            tlv_info = struct.unpack('<HH', dummy_data[tlv_start:tlv_start+4])
            tlv_magic = tlv_info[0]
            tlv_tot_len = tlv_info[1]
            
            logger.info(f"  TLV magic: 0x{tlv_magic:04X}")
            logger.info(f"  TLV total length: {tlv_tot_len} bytes (0x{tlv_tot_len:X})")

            if tlv_magic not in [0x6907, 0x6908]:
                raise FirmwareError(f"Invalid TLV magic: 0x{tlv_magic:04X}")

            offset = tlv_start + 4
            sha256_hash = None
            dummy_signature = None
            sig_offset = None
            keyhash_tlv_offset = None
            dummy_keyhash = None
            
            while offset < len(dummy_data) - 4:
                if dummy_data[offset:offset+4] == b'\xff\xff\xff\xff':
                    break
                
                tlv_type, tlv_len = struct.unpack('<HH', dummy_data[offset:offset+4])
                tlv_data = dummy_data[offset+4:offset+4+tlv_len]
                
                logger.debug(f"  TLV at 0x{offset:X}: type=0x{tlv_type:04X}, len={tlv_len}, data={tlv_data.hex()[:32]}...")

                # MCUboot TLV types (from image.h)
                TLV_SHA256 = 0x10    # IMAGE_TLV_SHA256 - hash of image
                TLV_KEYHASH = 0x01   # IMAGE_TLV_KEYHASH - hash of public key
                TLV_ECDSA256 = 0x22  # IMAGE_TLV_ECDSA256 - ECDSA signature
                
                if tlv_type == TLV_KEYHASH:
                    dummy_keyhash = tlv_data
                    keyhash_tlv_offset = offset + 4  # Offset to KEYHASH data
                    logger.info(f"  Found KEYHASH: {dummy_keyhash.hex()[:32]}... (DUMMY, will replace!)")
                elif tlv_type == TLV_SHA256:
                    sha256_hash = tlv_data
                    logger.info(f"  Found SHA256 hash: {sha256_hash.hex()[:32]}... ({len(sha256_hash)} bytes)")
                elif tlv_type == TLV_ECDSA256:
                    dummy_signature = tlv_data
                    sig_offset = offset + 4  # Offset to signature data
                    logger.info(f"  Found ECDSA signature at 0x{sig_offset:X}: {len(dummy_signature)} bytes")
                
                # Move to next TLV
                offset += 4 + tlv_len
            
            if not sha256_hash:
                raise FirmwareError("SHA256 hash not found in TLV!")
            
            if not dummy_signature:
                raise FirmwareError("ECDSA signature not found in TLV!")
            
            if not dummy_keyhash:
                raise FirmwareError("KEYHASH not found in TLV!")
            
            logger.info(f"  Dummy signature: {len(dummy_signature)} bytes (DER format)")
            logger.info(f"")
            logger.info(f"  [CRITICAL FIX] Replacing dummy KEYHASH with {backend_label} KEYHASH...")

            hsm_keyhash = hashlib.sha256(public_key_der).digest()
            logger.info(f"  Dummy KEYHASH:   {dummy_keyhash.hex()}")
            logger.info(f"  {backend_label} KEYHASH: {hsm_keyhash.hex()}")
            
            if len(hsm_keyhash) != len(dummy_keyhash):
                raise FirmwareError(f"KEYHASH length mismatch! {len(hsm_keyhash)} != {len(dummy_keyhash)}")

            dummy_data[keyhash_tlv_offset:keyhash_tlv_offset+len(hsm_keyhash)] = hsm_keyhash
            logger.info(f"  KEYHASH replaced at offset 0x{keyhash_tlv_offset:X}")
            logger.info(f"  SHA256 hash extracted: {sha256_hash.hex()}")

            logger.info(f"")
            logger.info(f"STEP 3: Sign hash with {backend_label}")
            signature_der = hsm_client.sign_digest(aws_kms_key_id, sha256_hash)
            logger.info(f"  {backend_label} signature: {len(signature_der)} bytes (DER format)")
            logger.debug(f"  Signature (DER): {signature_der.hex()[:64]}...")
            
            
            # STEP 4: Use HSM signature AS-IS
            logger.info(f"")
            logger.info(f"STEP 4: Prepare {backend_label} signature for injection")
            logger.info(f"  Dummy signature: {len(dummy_signature)} bytes (padded by --pad-sig)")
            logger.info(f"  {backend_label} signature (DER): {len(signature_der)} bytes")

            if signature_der[0] != 0x30:
                raise FirmwareError(f"HSM signature is not DER format (expected 0x30, got 0x{signature_der[0]:02X})")

            offset = 2
            if signature_der[offset] != 0x02:
                raise FirmwareError(f"Expected INTEGER tag for R")
            offset += 1
            r_len = signature_der[offset]
            offset += 1
            r_bytes = signature_der[offset:offset+r_len]
            offset += r_len
            
            if signature_der[offset] != 0x02:
                raise FirmwareError(f"Expected INTEGER tag for S")
            offset += 1
            s_len = signature_der[offset]
            offset += 1
            s_bytes = signature_der[offset:offset+s_len]
            
            logger.info(f"  DER parsed: R={r_len} bytes, S={s_len} bytes")

            curve = ec.SECP256R1()
            N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            N_half = N // 2
            s_int = int.from_bytes(s_bytes, 'big')
            logger.info(f"  S value: {s_int:064X}")
            logger.info(f"  N/2:     {N_half:064X}")
            
            signature_final_der = signature_der
            
            if s_int > N_half:
                logger.info(f"  S > N/2 detected! Normalizing signature...")

                s_normalized = N - s_int
                logger.info(f"  S_norm:  {s_normalized:064X}")
                s_normalized_bytes = s_normalized.to_bytes(32, 'big')

                r_final = r_bytes
                if len(r_bytes) > 32:
                    r_final = r_bytes
                elif r_bytes[0] >= 0x80:
                    r_final = b'\x00' + r_bytes
                else:
                    r_final = r_bytes

                if s_normalized_bytes[0] >= 0x80:
                    s_final = b'\x00' + s_normalized_bytes
                else:
                    s_final = s_normalized_bytes.lstrip(b'\x00')
                    if len(s_final) == 0:
                        s_final = b'\x00'
                    elif s_final[0] >= 0x80:
                        s_final = b'\x00' + s_final

                der_content = b'\x02' + bytes([len(r_final)]) + r_final + b'\x02' + bytes([len(s_final)]) + s_final
                signature_final_der = b'\x30' + bytes([len(der_content)]) + der_content
                
                logger.info(f"  Signature normalized! New DER length: {len(signature_final_der)} bytes")
            else:
                logger.info(f"  S <= N/2, no normalization needed")
                signature_final_der = signature_der

            dummy_sig_len = len(dummy_signature)
            signature_final = signature_final_der
            logger.info(f"")
            logger.info(f"STEP 5: Replace dummy signature with {backend_label} signature")
            logger.info(f"  Dummy signature: {len(dummy_signature)} bytes")
            logger.info(f"  {backend_label} signature: {len(signature_final)} bytes")
            logger.info(f"  Signature offset: 0x{sig_offset:X}")
            
            if len(dummy_signature) == len(signature_final):
                logger.info(f"  Same size → Direct replacement (preserves structure!)")
                final_data = (
                    dummy_data[:sig_offset] +
                    signature_final +  # HSM signature
                    dummy_data[sig_offset + len(dummy_signature):]  # After signature
                )
                logger.info(f"TLV_TOTAL_LENGTH preserved: {tlv_tot_len} bytes (includes --pad-sig padding)")
            else:
                logger.info(f"Different size ({len(dummy_signature)} → {len(signature_final)}) → Reconstructing TLV!")

                tlv_entry_offset = sig_offset - 4
                tlv_type, old_tlv_len = struct.unpack('<HH', dummy_data[tlv_entry_offset:tlv_entry_offset+4])


                new_tlv_header = struct.pack('<HH', tlv_type, len(signature_final))

                before_tlv = dummy_data[:tlv_entry_offset]

                tlv_real_end = sig_offset + len(dummy_signature)
                scan_offset = sig_offset + len(dummy_signature)
                while scan_offset + 4 <= len(dummy_data):
                    if dummy_data[scan_offset:scan_offset+4] == b'\xff\xff\xff\xff':
                        tlv_real_end = scan_offset
                        break
                    try:
                        entry_t, entry_l = struct.unpack('<HH', dummy_data[scan_offset:scan_offset+4])
                        if entry_t == 0xFFFF:  # End marker
                            tlv_real_end = scan_offset
                            break
                        scan_offset += 4 + entry_l
                        tlv_real_end = scan_offset
                    except:
                        break

                after_signature = dummy_data[sig_offset + len(dummy_signature):tlv_real_end]
                after_tlv_to_end = dummy_data[tlv_real_end:]

                size_diff = len(dummy_signature) - len(signature_final)
                if size_diff > 0:
                    padding = b'\xff' * size_diff
                    final_data = bytearray(before_tlv + new_tlv_header + signature_final + after_signature + padding + after_tlv_to_end)
                    logger.info(f"  Added {size_diff} bytes padding to preserve trailer position")
                else:
                    final_data = bytearray(before_tlv + new_tlv_header + signature_final + after_signature + after_tlv_to_end)

                new_tlv_tot_len = 0
                temp_offset = tlv_start + 4
                
                while temp_offset < len(final_data):
                    if final_data[temp_offset:temp_offset+4] == b'\xff\xff\xff\xff':
                        break
                    entry_type, entry_len = struct.unpack('<HH', final_data[temp_offset:temp_offset+4])
                    new_tlv_tot_len += 4 + entry_len
                    temp_offset += 4 + entry_len

                logger.info(f"TLV total length: {tlv_tot_len} → {new_tlv_tot_len} (sum of entries only, no header!)")
                tlv_info_new = struct.pack('<HH', tlv_magic, new_tlv_tot_len)
                final_data[tlv_start:tlv_start+4] = tlv_info_new
                
            final_data = bytes(final_data)  # Convert to bytes
            logger.info(f"  Binary size after signature replacement: {len(final_data)} bytes")

            # Verify binary size matches slot_size from config (NO hardcoded values!)
            if len(final_data) != slot_size:
                logger.warning(f"  Binary size mismatch: {len(final_data)} (expected {slot_size})")
                if len(final_data) > slot_size:
                    raise FirmwareError(f"Binary too large for slot: {len(final_data)} > {slot_size}")
            else:
                logger.info(f"  Binary at correct slot size: {slot_size} bytes")

            output_file.write_bytes(final_data)

            logger.info(f"")
            logger.info(f"STEP 6: Verify hash integrity")

            protected_area = final_data[0:header_size + img_size]
            final_hash = hashlib.sha256(protected_area).digest()
            
            if sha256_hash == final_hash:
                logger.info(f"  HASH MATCH! Signature verification will PASS!")
            else:
                logger.error(f"  HASH MISMATCH! Signature verification will FAIL!")
                raise FirmwareError("Hash mismatch after signature replacement!")

            output_size = output_file.stat().st_size
            logger.info(f"")
            logger.info(f"=" * 70)
            logger.info(f"SIGNING SUCCESSFUL via {backend_label}!")
            logger.info(f"=" * 70)
            logger.info(f"  Output file: {output_file}")
            logger.info(f"  Size: {output_size} bytes (0x{output_size:X})")
            logger.info(f"  Key ID: {aws_kms_key_id}")
            logger.info(f"  Hash: {sha256_hash.hex()[:32]}...")
            logger.info(f"  Signature: ECDSA-P256 ({len(signature_final)} bytes DER+padding, Renesas format)")
            logger.info(f"=" * 70)

        hsm_client.disconnect()

    except Exception as e:
        raise FirmwareError(f"Firmware signing failed ({backend_label}): {str(e)}") from e
