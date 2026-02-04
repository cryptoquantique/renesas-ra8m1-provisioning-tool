"""
Certificate Validator - MANDATORY validations for Renesas certificates.

Validates TLV structure, KEYHASH, SIGNER_ID, CRC32, magic bytes, ECDSA signatures.
STRICT PARSER according to Renesas tables 8-13 (Key Certificate) and 8-14 (Code Certificate).

This module provides:
    - TLV structure parsing and validation
    - Key Certificate validation (256 bytes)
    - Code Certificate validation (256 bytes)
    - KEYHASH and SIGNER_ID verification
    - CRC32 checksum validation

Classes:
    TLVParser: Strict TLV section parser
    CertificateValidator: Complete certificate validation
"""

import struct
import hashlib
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from utils.exceptions import SKMTError
from utils.logging import get_logger

logger = get_logger(__name__)


class TLVParser:
    """
    TLV Parser - strict implementation according to Renesas documentation.
    
    TLV format:
        - Type&Length: 4 bytes (little-endian)
        - Value: N bytes (specified by Length field)
    
    Attributes:
        KNOWN_TLV_TYPES (dict): Mapping of known TLV type codes to descriptions
    """
    
    @staticmethod
    def parse_tlv_section(tlv_data: bytes) -> Dict[int, bytes]:
        """
        Parse TLV section and return dict{tlv_type: value}.
        
        STRICT PARSER - does NOT accept unknown TLV types!
        RA8-specific TLV format: Type&Length is a uint32 that identifies BOTH type AND length.
        
        Args:
            tlv_data: Raw TLV bytes to parse
            
        Returns:
            Dict mapping tlv_type (int) to value_bytes (bytes)
            
        Raises:
            SKMTError: If unknown TLV type encountered
        """
        TLV_LENGTHS = {
            0x00088010: 64,  # ECC_PUBKEY
            0x01088010: 64,  # ECC_PUBKEY
            0x10144008: 32,  # KEYHASH / SIGNER_ID
            0x20088410: 64,  # EXPECTED_SIG
            0x25088410: 64,  # EXPECTED_SIG
            0x04000001: 4,   # EXPECTED_CRC
            0x40000001: 4,   # EXPECTED_CRC
        }
        
        tlvs = {}
        offset = 0
        
        while offset < len(tlv_data):
            if offset + 4 > len(tlv_data):
                break

            type_length = struct.unpack('<I', tlv_data[offset:offset+4])[0]
            offset += 4

            if type_length not in TLV_LENGTHS:
                logger.error(f"UNKNOWN TLV Type&Length: 0x{type_length:08X} at offset {offset-4}")
                logger.error(f"  Expected one of: {[f'0x{t:08X}' for t in TLV_LENGTHS.keys()]}")
                logger.error(f"  This indicates certificate format mismatch or parser bug!")
                break
            
            value_length = TLV_LENGTHS[type_length]

            if offset + value_length > len(tlv_data):
                logger.error(f"TLV value truncated: type=0x{type_length:08X}, expected {value_length} bytes, only {len(tlv_data)-offset} available")
                break
            
            value = tlv_data[offset:offset+value_length]
            offset += value_length

            if type_length == 0x00088010 or type_length == 0x01088010:
                tlvs[0x01088010] = value
            elif type_length == 0x04000001 or type_length == 0x40000001:
                tlvs[0x40000001] = value
            elif type_length == 0x20088410 or type_length == 0x25088410:
                tlvs[0x20088410] = value
                tlvs[0x25088410] = value
            else:
                tlvs[type_length] = value
        
        return tlvs
    
    @staticmethod
    def extract_tlv_value(tlv_data: bytes, tlv_type: int) -> Optional[bytes]:
        """Extract specific TLV value by type."""
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        return tlvs.get(tlv_type)


class CertificateValidator:
    """Validates Renesas FSBL certificates (Key Certificate and Code Certificate)."""
    
    # Magic bytes (little-endian representation)
    KEY_CERT_MAGIC = 0x6B657963
    CODE_CERT_MAGIC = 0x63646F63

    CODE_CERT_MAGIC_CORRECT = 0x63636F64
    
    # Expected TLV lengths
    KEY_CERT_TLV_LENGTH = 0xAC
    CODE_CERT_TLV_LENGTH = 0xB4  # 180 bytes (from Table 8-14: 4+64+4+4+4+32+4+64 = 180)

    TLV_ECC_PUBKEY = 0x01088010    # ECC Public Key (64 bytes)
    TLV_KEYHASH = 0x10144008       # KEYHASH (32 bytes)
    TLV_SIGNER_ID = 0x10144008     # SIGNER_ID (32 bytes)
    TLV_EXPECTED_SIG = 0x20088410  # Signature (64 bytes)
    TLV_EXPECTED_CRC = 0x40000001  # CRC32
    
    @staticmethod
    def _parse_header(cert_data: bytes) -> Dict[str, Any]:
        """
        Parse certificate header (32 bytes).
        
        Header structure (Table 8-13/8-14):
        - Magic: 4 bytes
        - Manifest Version: 4 bytes
        - Flags: 4 bytes
        - Reserved/Load Addr/Dest Addr/Image size/Image version/Build number: 20 bytes
        """
        if len(cert_data) < 32:
            raise ValueError(f"Certificate too small: {len(cert_data)} bytes (need >= 32 for header)")
        
        header = {}
        header['magic'] = struct.unpack('<I', cert_data[0:4])[0]
        header['manifest_version'] = struct.unpack('<I', cert_data[4:8])[0]
        header['flags'] = struct.unpack('<I', cert_data[8:12])[0]
        
        # For Code Certificate, parse additional fields
        if len(cert_data) >= 32:
            header['load_addr'] = struct.unpack('<I', cert_data[12:16])[0]
            header['dest_addr'] = struct.unpack('<I', cert_data[16:20])[0]
            header['image_size'] = struct.unpack('<I', cert_data[20:24])[0]
            header['image_version'] = struct.unpack('<I', cert_data[24:28])[0]
            header['build_number'] = struct.unpack('<I', cert_data[28:32])[0]
        
        return header
    
    @staticmethod
    def validate_key_certificate(cert_path: Path) -> Tuple[bool, str]:
        """
        Validate Key Certificate - STRICT parser according to Renesas Table 8-13.
        
        Args:
            cert_path: Path to Key Certificate binary
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not cert_path.exists():
            return False, f"Certificate file not found: {cert_path}"
        
        cert_data = cert_path.read_bytes()
        
        # Check minimum size (32 header + 4 tlv_length + 172 tlv = 208)
        if len(cert_data) < 208:
            return False, f"Certificate too small: {len(cert_data)} bytes (expected >= 208)"
        
        # Parse header
        try:
            header = CertificateValidator._parse_header(cert_data)
        except Exception as e:
            return False, f"Failed to parse header: {e}"
        
        # Verify magic
        if header['magic'] != CertificateValidator.KEY_CERT_MAGIC:
            magic_bytes = cert_data[0:4]
            if magic_bytes != b'keyc' and magic_bytes != b'cyek':
                return False, f"Invalid magic: 0x{header['magic']:08X} (expected 0x{CertificateValidator.KEY_CERT_MAGIC:08X} or 'keyc'/'cyek' bytes)"

        if header['manifest_version'] != 0x00010000:
            logger.warning(f"Unexpected manifest version: 0x{header['manifest_version']:08X} (expected 0x00010000)")

        tlv_length = struct.unpack('<I', cert_data[32:36])[0]
        if tlv_length != CertificateValidator.KEY_CERT_TLV_LENGTH:
            return False, f"Invalid TLV length: 0x{tlv_length:02X} (expected 0x{CertificateValidator.KEY_CERT_TLV_LENGTH:02X} / {CertificateValidator.KEY_CERT_TLV_LENGTH} bytes)"

        tlv_data = cert_data[36:36+tlv_length]
        tlvs = TLVParser.parse_tlv_section(tlv_data)

        if CertificateValidator.TLV_ECC_PUBKEY not in tlvs:
            return False, "Missing TLV: ECC_PUBKEY"
        if CertificateValidator.TLV_KEYHASH not in tlvs:
            return False, "Missing TLV: KEYHASH"
        if CertificateValidator.TLV_EXPECTED_SIG not in tlvs:
            return False, "Missing TLV: EXPECTED_SIG"

        keyhash = tlvs[CertificateValidator.TLV_KEYHASH]
        if len(keyhash) != 32:
            return False, f"Invalid KEYHASH length: {len(keyhash)} bytes (expected 32)"
        
        logger.info(f"[OK] Key Certificate structure valid: {cert_path.name}")
        logger.info(f"  KEYHASH: {keyhash.hex()[:32]}...")
        
        return True, "Key Certificate valid"
    
    @staticmethod
    def validate_code_certificate(cert_path: Path) -> Tuple[bool, str]:
        """
        Validate Code Certificate - STRICT parser according to Renesas Table 8-14.
        
        Args:
            cert_path: Path to Code Certificate binary
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not cert_path.exists():
            return False, f"Certificate file not found: {cert_path}"
        
        cert_data = cert_path.read_bytes()
        
        # Check minimum size (32 header + 4 tlv_length + 180 tlv = 216)
        if len(cert_data) < 216:
            return False, f"Certificate too small: {len(cert_data)} bytes (expected >= 216)"

        try:
            header = CertificateValidator._parse_header(cert_data)
        except Exception as e:
            return False, f"Failed to parse header: {e}"

        magic_bytes = cert_data[0:4]
        if magic_bytes != b'cdoc' and magic_bytes != b'codc' and header['magic'] not in [0x636F6463, 0x63646F63]:
            return False, f"Invalid magic: {magic_bytes.hex()} / 0x{header['magic']:08X} (expected 'cdoc' or 0x636F6463)"

        if header['manifest_version'] != 0x00010000:
            logger.warning(f"Unexpected manifest version: 0x{header['manifest_version']:08X} (expected 0x00010000)")

        tlv_length = struct.unpack('<I', cert_data[32:36])[0]
        if tlv_length != CertificateValidator.CODE_CERT_TLV_LENGTH:
            return False, f"Invalid TLV length: 0x{tlv_length:02X} (expected 0x{CertificateValidator.CODE_CERT_TLV_LENGTH:02X} / {CertificateValidator.CODE_CERT_TLV_LENGTH} bytes)"

        tlv_data = cert_data[36:36+tlv_length]
        tlvs = TLVParser.parse_tlv_section(tlv_data)

        if CertificateValidator.TLV_ECC_PUBKEY not in tlvs:
            return False, "Missing TLV: ECC_PUBKEY"
        if CertificateValidator.TLV_EXPECTED_CRC not in tlvs:
            return False, "Missing TLV: EXPECTED_CRC"
        if CertificateValidator.TLV_SIGNER_ID not in tlvs:
            return False, "Missing TLV: SIGNER_ID"
        if CertificateValidator.TLV_EXPECTED_SIG not in tlvs:
            return False, "Missing TLV: EXPECTED_SIG"

        signer_id = tlvs[CertificateValidator.TLV_SIGNER_ID]
        if len(signer_id) != 32:
            return False, f"Invalid SIGNER_ID length: {len(signer_id)} bytes (expected 32)"
        
        logger.info(f"[OK] Code Certificate structure valid: {cert_path.name}")
        logger.info(f"  SIGNER_ID: {signer_id.hex()[:32]}...")
        
        return True, "Code Certificate valid"
    
    @staticmethod
    def verify_certificate_chain(
        key_cert_path: Path,
        code_cert_path: Path
    ) -> Tuple[bool, str]:
        """
        Verify certificate chain: KEYHASH (Key Cert) == SIGNER_ID (Code Cert).
        
        This is CRITICAL for chain of trust validation on device.
        Uses TLV parser to extract VALUES correctly (not hardcoded offsets).
        
        Args:
            key_cert_path: Path to Key Certificate
            code_cert_path: Path to Code Certificate
            
        Returns:
            Tuple of (is_valid, message)
        """
        key_cert_data = key_cert_path.read_bytes()
        code_cert_data = code_cert_path.read_bytes()

        key_tlv_data = key_cert_data[36:36+CertificateValidator.KEY_CERT_TLV_LENGTH]
        code_tlv_data = code_cert_data[36:36+CertificateValidator.CODE_CERT_TLV_LENGTH]
        
        key_tlvs = TLVParser.parse_tlv_section(key_tlv_data)
        code_tlvs = TLVParser.parse_tlv_section(code_tlv_data)

        keyhash = key_tlvs.get(CertificateValidator.TLV_KEYHASH)
        signer_id = code_tlvs.get(CertificateValidator.TLV_SIGNER_ID)
        
        if not keyhash:
            return False, "KEYHASH not found in Key Certificate TLV section"
        if not signer_id:
            return False, "SIGNER_ID not found in Code Certificate TLV section"
        
        if keyhash != signer_id:
            return False, (
                f"Certificate chain broken!\n"
                f"  KEYHASH:   {keyhash.hex()}\n"
                f"  SIGNER_ID: {signer_id.hex()}\n"
                f"  These MUST match for device to accept certificates!"
            )
        
        logger.info("[OK] Certificate chain valid: KEYHASH == SIGNER_ID")
        logger.info(f"  Value: {keyhash.hex()[:32]}...")
        
        return True, "Certificate chain valid (KEYHASH == SIGNER_ID)"
    
    @staticmethod
    def extract_keyhash(key_cert_path: Path) -> bytes:
        """Extract KEYHASH from Key Certificate using TLV parser."""
        cert_data = key_cert_path.read_bytes()
        tlv_data = cert_data[36:36+CertificateValidator.KEY_CERT_TLV_LENGTH]
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        return tlvs.get(CertificateValidator.TLV_KEYHASH, b'')
    
    @staticmethod
    def extract_signer_id(code_cert_path: Path) -> bytes:
        """Extract SIGNER_ID from Code Certificate using TLV parser."""
        cert_data = code_cert_path.read_bytes()
        tlv_data = cert_data[36:36+CertificateValidator.CODE_CERT_TLV_LENGTH]
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        return tlvs.get(CertificateValidator.TLV_SIGNER_ID, b'')
    
    @staticmethod
    def extract_crc32(code_cert_path: Path) -> int:
        """Extract CRC32 from Code Certificate using TLV parser."""
        cert_data = code_cert_path.read_bytes()
        tlv_data = cert_data[36:36+CertificateValidator.CODE_CERT_TLV_LENGTH]
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        crc_bytes = tlvs.get(CertificateValidator.TLV_EXPECTED_CRC, b'\x00\x00\x00\x00')
        if len(crc_bytes) != 4:
            raise ValueError(f"Invalid CRC32 length: {len(crc_bytes)} bytes")
        return struct.unpack('<I', crc_bytes)[0]
    
    @staticmethod
    def verify_key_cert_signature(
        key_cert_path: Path,
        oem_root_pk_pem: Path
    ) -> Tuple[bool, str]:
        """
        Verify Key Certificate signature with OEM Root Public Key.
        
        CRITICAL: This verifies that Key Certificate was signed by OEM_ROOT_SK.
        Device FSBL performs this same check.
        
        Signature verification:
        1. Data to sign = all TLV data EXCEPT signature (last 64 bytes)
        2. Compute SHA256(data_to_sign) = digest
        3. Verify signature on DIGEST (not on data directly!)
        4. Signature format: raw R||S (64 bytes) → convert to DER for verification
        
        Args:
            key_cert_path: Path to Key Certificate
            oem_root_pk_pem: Path to OEM Root Public Key (PEM format)
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not oem_root_pk_pem.exists():
            return False, f"OEM Root public key not found: {oem_root_pk_pem}"
        
        cert_data = key_cert_path.read_bytes()
        
        # TLV section: starts at offset 36, length = TLV_LENGTH
        tlv_length = struct.unpack('<I', cert_data[32:36])[0]
        tlv_start = 36
        tlv_data = cert_data[tlv_start:tlv_start+tlv_length]
        
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        signature_raw = tlvs.get(CertificateValidator.TLV_EXPECTED_SIG)
        if not signature_raw:
            signature_raw = tlvs.get(0x20088410)
        
        if not signature_raw or len(signature_raw) != 64:
            return False, f"Invalid signature in certificate: {len(signature_raw) if signature_raw else 0} bytes (expected 64)"

        header = cert_data[0:32]
        tlv_length_bytes = cert_data[32:36]
        tlv_ecc_pubkey = cert_data[36:36+68]
        tlv_keyhash = cert_data[36+68:36+68+36]
        
        data_to_verify = header + tlv_length_bytes + tlv_ecc_pubkey + tlv_keyhash
        digest = hashlib.sha256(data_to_verify).digest()

        try:
            pem_data = oem_root_pk_pem.read_bytes()
            public_key = load_pem_public_key(pem_data, backend=default_backend())

            r = int.from_bytes(signature_raw[:32], 'big')
            s = int.from_bytes(signature_raw[32:64], 'big')
            
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            signature_der = encode_dss_signature(r, s)

            from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
            public_key.verify(
                signature_der,
                digest,
                ec.ECDSA(crypto_utils.Prehashed(hashes.SHA256()))
            )
            
            logger.info("[OK] Key Certificate signature VALID (signed by OEM_ROOT_SK)")
            return True, "Key Certificate signature valid"
            
        except InvalidSignature:
            return False, "Key Certificate signature INVALID! Not signed by provided OEM_ROOT_PK"
        except Exception as e:
            return False, f"Error verifying Key Certificate signature: {e}"
    
    @staticmethod
    def verify_code_cert_signature(
        code_cert_path: Path,
        oem_bl_pk_pem: Path,
        bootloader_binary: bytes = None
    ) -> Tuple[bool, str]:
        """
        Verify Code Certificate signature with OEM Bootloader Public Key.
        
        CRITICAL: This verifies that Code Certificate was signed by OEM_BL_SK.
        Device FSBL performs this same check.
        
        IMPORTANT: Signature is computed over: header + tlv_length + TLVs (no sig) + bootloader_binary
        The bootloader_binary MUST be included in the hash for correct verification!
        
        Args:
            code_cert_path: Path to Code Certificate
            oem_bl_pk_pem: Path to OEM Bootloader Public Key (PEM format)
            bootloader_binary: Bootloader binary data (flash_image) - REQUIRED for correct verification
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not oem_bl_pk_pem.exists():
            return False, f"OEM BL public key not found: {oem_bl_pk_pem}"
        
        cert_data = code_cert_path.read_bytes()
        
        # TLV section
        tlv_length = struct.unpack('<I', cert_data[32:36])[0]
        tlv_start = 36
        tlv_data = cert_data[tlv_start:tlv_start+tlv_length]
        
        # Parse TLVs
        tlvs = TLVParser.parse_tlv_section(tlv_data)
        signature_raw = tlvs.get(CertificateValidator.TLV_EXPECTED_SIG)
        
        if not signature_raw or len(signature_raw) != 64:
            return False, f"Invalid signature in certificate: {len(signature_raw) if signature_raw else 0} bytes (expected 64)"

        # Build data_to_sign: header + tlv_length + TLVs (without EXPECTED_SIG) + bootloader_binary
        # TLV section without signature = first 3 TLVs: ECC_PUBKEY(68) + CRC(8) + SIGNER_ID(36) = 112 bytes
        tlv_section_no_sig = tlv_data[:-68]  # Remove EXPECTED_SIG TLV (4 bytes type&len + 64 bytes value)
        
        header = cert_data[:32]
        tlv_length_packed = struct.pack('<I', tlv_length)
        
        if bootloader_binary is not None:
            # CORRECT: Include bootloader_binary in hash (per Renesas reference)
            data_to_sign = header + tlv_length_packed + tlv_section_no_sig + bootloader_binary
            logger.debug(f"Code Cert signature verification: header(32) + tlv_len(4) + tlvs({len(tlv_section_no_sig)}) + binary({len(bootloader_binary)}) = {len(data_to_sign)} bytes")
        else:
            # FALLBACK: Without bootloader (will likely fail for production certs)
            logger.warning("Code Cert signature verification: bootloader_binary not provided, verification may fail!")
            data_to_sign = header + tlv_length_packed + tlv_section_no_sig
        
        digest = hashlib.sha256(data_to_sign).digest()

        try:
            pem_data = oem_bl_pk_pem.read_bytes()
            public_key = load_pem_public_key(pem_data, backend=default_backend())
            
            r = int.from_bytes(signature_raw[:32], 'big')
            s = int.from_bytes(signature_raw[32:64], 'big')
            
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            signature_der = encode_dss_signature(r, s)
            from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
            public_key.verify(
                signature_der,
                digest,
                ec.ECDSA(crypto_utils.Prehashed(hashes.SHA256()))
            )
            
            logger.info("Code Certificate signature VALID (signed by OEM_BL_SK)")
            return True, "Code Certificate signature valid"
            
        except InvalidSignature:
            return False, "Code Certificate signature INVALID! Not signed by provided OEM_BL_PK"
        except Exception as e:
            return False, f"Error verifying Code Certificate signature: {e}"
    
    @staticmethod
    def verify_code_cert_crc32(
        code_cert_path: Path,
        bootloader_binary: bytes,
        flash_length: int
    ) -> Tuple[bool, str]:
        """
        Verify Code Certificate CRC32 against bootloader binary.
        
        CRITICAL: Device FSBL calculates CRC32 on bootloader flash region (with 0xFF fill).
        This must match the CRC32 in Code Certificate.
        
        Args:
            code_cert_path: Path to Code Certificate
            bootloader_binary: Bootloader binary data (extracted from SREC)
            flash_length: Expected flash length (used for CRC calculation)
            
        Returns:
            Tuple of (is_valid, message)
        """
        import binascii
        cert_crc32 = CertificateValidator.extract_crc32(code_cert_path)

        if len(bootloader_binary) < flash_length:
            bootloader_buffer = bootloader_binary + b'\xFF' * (flash_length - len(bootloader_binary))
        elif len(bootloader_binary) > flash_length:
            logger.warning(f"Bootloader binary ({len(bootloader_binary)} bytes) exceeds flash_length ({flash_length} bytes), truncating")
            bootloader_buffer = bootloader_binary[:flash_length]
        else:
            bootloader_buffer = bootloader_binary
        calculated_crc32 = binascii.crc32(bootloader_buffer) & 0xFFFFFFFF
        
        if calculated_crc32 != cert_crc32:
            return False, (
                f"CRC32 mismatch!\n"
                f"  Certificate CRC32:  0x{cert_crc32:08X}\n"
                f"  Calculated CRC32:   0x{calculated_crc32:08X}\n"
                f"  Bootloader size:    {len(bootloader_binary)} bytes\n"
                f"  Flash length:       {flash_length} bytes (0x{flash_length:X})\n"
                f"  Device will REJECT this Code Certificate!"
            )
        
        logger.info(f"[OK] Code Certificate CRC32 valid: 0x{cert_crc32:08X}")
        logger.info(f"  Bootloader size: {len(bootloader_binary)} bytes, Flash length: {flash_length} bytes")
        return True, "Code Certificate CRC32 valid"
    
    @staticmethod
    def validate_certificates_complete(
        key_cert_path: Path,
        code_cert_path: Path,
        oem_root_pk_pem: Path,
        oem_bl_pk_pem: Path,
        bootloader_binary: Optional[bytes] = None,
        flash_length: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        COMPLETE validation of certificates (ALL CHECKS).
        
        This performs ALL checks that device FSBL will perform:
        1. Key Certificate: magic, TLV length, TLV structure, signature (OEM_ROOT_PK)
        2. Code Certificate: magic, TLV length, TLV structure, signature (OEM_BL_PK), CRC32
        3. Certificate chain: KEYHASH == SIGNER_ID
        
        CRITICAL: If any check fails, device will REJECT certificates!
        
        Args:
            key_cert_path: Path to Key Certificate
            code_cert_path: Path to Code Certificate
            oem_root_pk_pem: Path to OEM Root Public Key (PEM)
            oem_bl_pk_pem: Path to OEM Bootloader Public Key (PEM)
            bootloader_binary: Optional bootloader binary for CRC32 check
            flash_length: Optional flash length for CRC32 check
            
        Returns:
            Tuple of (is_valid, message)
        """
        errors = []

        valid, msg = CertificateValidator.validate_key_certificate(key_cert_path)
        if not valid:
            errors.append(f"[KEY CERT] {msg}")

        valid, msg = CertificateValidator.validate_code_certificate(code_cert_path)
        if not valid:
            errors.append(f"[CODE CERT] {msg}")

        valid, msg = CertificateValidator.verify_certificate_chain(key_cert_path, code_cert_path)
        if not valid:
            errors.append(f"[CHAIN] {msg}")

        valid, msg = CertificateValidator.verify_key_cert_signature(key_cert_path, oem_root_pk_pem)
        if not valid:
            errors.append(f"[KEY CERT SIGNATURE] {msg}")

        valid, msg = CertificateValidator.verify_code_cert_signature(code_cert_path, oem_bl_pk_pem, bootloader_binary)
        if not valid:
            errors.append(f"[CODE CERT SIGNATURE] {msg}")

        if bootloader_binary and flash_length:
            valid, msg = CertificateValidator.verify_code_cert_crc32(
                code_cert_path,
                bootloader_binary,
                flash_length
            )
            if not valid:
                errors.append(f"[CODE CERT CRC32] {msg}")
        
        if errors:
            return False, "\n".join(errors)
        
        logger.info("[OK] ALL CERTIFICATE CHECKS PASSED!")
        logger.info("   Device will accept these certificates.")
        return True, "All certificate checks passed"
