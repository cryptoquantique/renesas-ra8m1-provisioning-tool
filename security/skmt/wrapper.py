"""
SKMT tool wrapper.

This module provides a Python interface to the Renesas Security Key
Management Tool (SKMT) for key wrapping and certificate generation.

ALL hardcoded values are read from project_config.json - SINGLE SOURCE OF TRUTH!
"""

import struct
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

from models.certificates import CodeCertificate, KeyCertificate
from models.keys import KeyType, WrappedKey
from utils.exceptions import SKMTError
from utils.logging import get_logger
logger = get_logger(__name__)


def parse_srec(srec_file: Path, base_addr: int, cfsize: int) -> bytes:
    """
    Parse SREC file and extract binary data.
    EXACT copy from reference script - returns ACTUAL data size, NOT cfsize!
    
    Args:
        srec_file: Path to SREC file
        base_addr: Base address (e.g., 0x02000000) - used to filter data
        cfsize: Code flash size (e.g., 0x200000 = 2MB) - used to filter data range
        
    Returns:
        Binary data from min_addr to max_addr (actual data), padded to 16-byte alignment
    """
    end_addr = base_addr + cfsize
    memory = {}

    with open(srec_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line.startswith('S'):
                continue

            record_type = line[1]
            if record_type not in '123':
                continue

            addr_len = {'1': 4, '2': 6, '3': 8}[record_type]
            addr = int(line[4:4+addr_len], 16)

            if not (base_addr <= addr < end_addr):
                continue

            data_start = 4 + addr_len
            data_end = -2
            data_bytes = bytes.fromhex(line[data_start:data_end])

            for i, b in enumerate(data_bytes):
                mem_addr = addr + i
                if base_addr <= mem_addr < end_addr:
                    memory[mem_addr] = b

    if not memory:
        raise SKMTError(f"No data found in SREC at address range 0x{base_addr:X}-0x{end_addr:X}")

    # EXACT as reference: use min/max of ACTUAL data, not full cfsize!
    min_addr = min(memory.keys())
    max_addr = max(memory.keys())
    
    bin_data = bytearray()
    for offset in range(min_addr, max_addr + 1):
        bin_data.append(memory.get(offset, 0xFF))

    # Pad to next multiple of 16
    padding = (16 - (len(bin_data) % 16)) % 16
    if padding:
        bin_data.extend([0xFF] * padding)

    return bytes(bin_data)


def _get_certificate_config() -> Dict[str, Any]:
    """
    Load certificate configuration from project_config.json.
    
    Returns:
        Dictionary with certificate configuration values
        
    Raises:
        SKMTError: If config cannot be loaded
    """
    try:
        config_path = Path(__file__).parent.parent.parent / "project_config.json"
        
        # Load raw JSON for nested certificate config
        import json
        with open(config_path, 'r') as f:
            raw_config = json.load(f)
        
        return raw_config.get("certificates", {})
    except Exception as e:
        raise SKMTError(f"Failed to load certificate config from project_config.json: {e}")

_RENESAS_CRC32_TABLE = None


def _init_renesas_crc32_table():
    """
    Initialize CRC32 lookup table for Renesas specification.
    
    Renesas CRC32 parameters (from documentation):
        - Polynomial: 0xEDB88320 (reflected)
        - Shift direction: right
        - Input data inversion: No
        - Output data inversion: Yes
        - Initial Value: 0xFFFFFFFF
    """
    global _RENESAS_CRC32_TABLE
    if _RENESAS_CRC32_TABLE is not None:
        return
    
    POLYNOMIAL = 0xEDB88320
    table = []
    
    for byte in range(256):
        crc = byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ POLYNOMIAL
            else:
                crc >>= 1
        table.append(crc)
    
    _RENESAS_CRC32_TABLE = table


def _renesas_crc32(data: bytes) -> int:
    """
    Calculate CRC32 according to Renesas specification.
    
    Renesas CRC32 parameters (from documentation):
        - Polynomial: 0xEDB88320 (reflected form of 0x04C11DB7)
        - Shift direction: right
        - Input data inversion: No
        - Output data inversion: Yes
        - Initial Value: 0xFFFFFFFF
    
    This is equivalent to CRC-32/ISO-HDLC (standard Ethernet CRC).
    
    Args:
        data: Input bytes to calculate CRC32 on
        
    Returns:
        32-bit CRC value as unsigned integer
    """
    _init_renesas_crc32_table()
    
    crc = 0xFFFFFFFF
    
    for byte in data:
        table_index = (crc ^ byte) & 0xFF
        crc = (crc >> 8) ^ _RENESAS_CRC32_TABLE[table_index]

    return crc ^ 0xFFFFFFFF


def extract_raw_public_key_qxqy(key_bytes: bytes) -> bytes:
    """
    Extract raw public key as Qx||Qy (64 bytes) from PEM or DER format.
    
    CRITICAL: This function MUST be used for both Key Certificate KEYHASH
    and Code Certificate SIGNER_ID to ensure they are identical!
    
    Format: Qx (32 bytes big-endian) || Qy (32 bytes big-endian) = 64 bytes total
    NO DER, NO PEM, NO prefix 0x04, NO other encoding!
    
    Args:
        key_bytes: Public key in PEM or DER format
        
    Returns:
        Raw public key as Qx||Qy (64 bytes)
        
    Raises:
        SKMTError: If extraction fails or result is not exactly 64 bytes
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
        from cryptography.hazmat.backends import default_backend

        try:
            pk = load_pem_public_key(key_bytes, backend=default_backend())
        except Exception:
            try:
                pk = load_der_public_key(key_bytes, backend=default_backend())
            except Exception as der_e:
                raise SKMTError(f"Failed to load public key as PEM or DER: {str(der_e)}") from der_e
        
        # Get raw uncompressed point (65 bytes: 0x04 || Qx(32) || Qy(32))
        raw = pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Remove 0x04 prefix to get Qx||Qy (64 bytes)
        if len(raw) == 65 and raw[0] == 0x04:
            qxqy = raw[1:]  # Return Qx||Qy (64 bytes)
        elif len(raw) == 64:
            qxqy = raw  # Already Qx||Qy
        else:
            raise SKMTError(f"Unexpected raw key length: {len(raw)} bytes, expected 64 or 65")
        
        if len(qxqy) != 64:
            raise SKMTError(f"Extracted key must be exactly 64 bytes (Qx||Qy), got {len(qxqy)} bytes")
        
        return qxqy
    except Exception as e:
        raise SKMTError(f"Failed to extract raw public key (Qx||Qy): {str(e)}") from e


def calculate_oem_bl_pk_hash(oem_bl_pk_bytes: bytes) -> bytes:
    """
    Calculate SHA-256 hash of OEM_BL public key (Qx||Qy).
    
    CRITICAL: This function MUST be used for both Key Certificate KEYHASH
    and Code Certificate SIGNER_ID to ensure they are identical!
    
    Args:
        oem_bl_pk_bytes: OEM Bootloader public key in PEM or DER format
        
    Returns:
        SHA-256 hash of Qx||Qy (32 bytes)
    """
    import hashlib
    
    oem_bl_pk_raw = extract_raw_public_key_qxqy(oem_bl_pk_bytes)
    return hashlib.sha256(oem_bl_pk_raw).digest()


def convert_rkey_to_pem_format(rkey_path: Path) -> None:
    """
    Convert binary RKEY file to Base64 PEM-like format with Renesas headers.
    
    The device expects format:
    -----BEGIN RENESAS KEY-----
    <base64 encoded data>
    -----END RENESAS KEY-----
    
    Args:
        rkey_path: Path to the binary RKEY file to convert
    """
    import base64
    
    # Read binary data
    binary_data = rkey_path.read_bytes()
    
    # Check if already in PEM format
    if binary_data.startswith(b'-----BEGIN'):
        logger.debug(f"RKEY already in PEM format: {rkey_path}")
        return
    
    # Convert to Base64
    b64_data = base64.b64encode(binary_data).decode('ascii')
    lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]
    b64_formatted = '\n'.join(lines)

    pem_content = f"-----BEGIN RENESAS KEY-----\n{b64_formatted}\n-----END RENESAS KEY-----\n"
    rkey_path.write_text(pem_content, encoding='utf-8')
    
    logger.info(f"Converted RKEY to PEM format: {rkey_path}")


class SKMTWrapper:
    """
    Wrapper for Renesas SKMT tool.

    This class provides a Python interface to interact with the SKMT
    command-line tool for key wrapping and certificate generation.
    """

    def __init__(self, skmt_path: str = None, working_directory: str = "./skmt_work"):
        """
        Initialize SKMT wrapper.

        Args:
            skmt_path: Path to SKMT executable (optional, only needed for legacy SKMT operations)
            working_directory: Working directory for SKMT operations

        Raises:
            SKMTError: If SKMT path is invalid when provided

        """
        self.skmt_path = Path(skmt_path) if skmt_path else None
        self.working_directory = Path(working_directory)

        if self.skmt_path and not self.skmt_path.exists():
            raise SKMTError(f"SKMT executable not found: {skmt_path}")

        self.working_directory.mkdir(parents=True, exist_ok=True)

    def wrap_oem_root_public_key(
        self, oem_root_pk: bytes, ufpk: str, plain_ufpk: Optional[str] = None, output_file: Optional[str] = None
    ) -> WrappedKey:
        """
        Wrap OEM Root Public Key with W-UFPK to create RKEY using SKMT.

        Uses SKMT /genkey command with correct parameters for RA8 RKEY format.
        SKMT requires BOTH plain UFPK and wrapped UFPK for /genkey.

        Args:
            oem_root_pk: OEM Root Public Key bytes (PEM format)
            ufpk: Path to W-UFPK file (wrapped UFPK from DLM)
            plain_ufpk: Path to plain UFPK file (optional, for SKMT /genkey)
            output_file: Optional output file path

        Returns:
            WrappedKey object with wrapped key data

        Raises:
            SKMTError: If wrapping fails
        """
        try:
            if output_file is None:
                output_file = str(self.working_directory / "oem_root_pk.rkey")

            output_path = Path(output_file).resolve()
            
            # Write OEM Root PK to temp file (SKMT needs file path)
            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as temp_pk:
                temp_pk.write(oem_root_pk)
                temp_pk_path = Path(temp_pk.name)
            
            try:
                cmd = [
                    str(self.skmt_path),
                    "/genkey",
                    "/mcu", "RA-RSIP-E51A",
                    "/keytype", "OEM_ROOT_PK",
                    "/filetype", "rfp",
                    "/key", f"file={temp_pk_path}",
                    "/output", str(output_path),
                ]
                
                # Add UFPK parameters (SKMT needs both for /genkey)
                if plain_ufpk and Path(plain_ufpk).exists():
                    cmd.extend(["/ufpk", f"file={Path(plain_ufpk).resolve()}"])
                cmd.extend(["/wufpk", f"file={Path(ufpk).resolve()}"])
                
                logger.debug(f"Running SKMT /genkey: {' '.join(cmd)}")
                result = self._run_command(cmd)
                
                logger.info(f"SKMT /genkey return code: {result.returncode}")
                logger.debug(f"SKMT /genkey STDOUT: {result.stdout.decode()}")
                logger.debug(f"SKMT /genkey STDERR: {result.stderr.decode()}")
                
                if result.returncode != 0:
                    raise SKMTError(
                        f"SKMT /genkey failed (rc={result.returncode}): "
                        f"STDOUT={result.stdout.decode()} STDERR={result.stderr.decode()}"
                    )

                if not output_path.exists():
                    raise SKMTError(f"SKMT /genkey succeeded but output file not found: {output_path}")
                
                logger.info(f"RKEY generated: {output_path}")

                rkey_data = output_path.read_bytes()
                
                return WrappedKey(
                    key_type="OEM_ROOT_PK",
                    wrapped_data=rkey_data,
                    file_path=str(output_path),
                )
            
            finally:
                # Cleanup temp file
                if temp_pk_path.exists():
                    temp_pk_path.unlink()

        except Exception as e:
            raise SKMTError(f"Failed to wrap OEM Root PK: {str(e)}") from e


        except Exception as e:
            raise SKMTError(f"Failed to wrap OEM Root Public Key: {str(e)}") from e

    def generate_key_certificate(
        self,
        oem_root_sk_handle: str,
        oem_root_pk: bytes,
        oem_bl_pk: bytes,
        output_file: Optional[str] = None,
        hsm_client = None,
    ) -> KeyCertificate:
        """
        Generate Key Certificate.

        The Key Certificate authenticates the OEM Bootloader Public Key
        using the OEM Root Secret Key. Uses AWS KMS for signing since
        private keys cannot be exported.

        Args:
            oem_root_sk_handle: HSM Key ID for OEM Root Secret Key
            oem_root_pk: OEM Root Public Key bytes (PEM)
            oem_bl_pk: OEM Bootloader Public Key bytes (PEM)
            output_file: Optional output file path
            hsm_client: HSM client for signing (required for AWS KMS)

        Returns:
            KeyCertificate object

        Raises:
            SKMTError: If certificate generation fails
        """
        try:
            import struct
            import hashlib
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            
            if output_file is None:
                output_file = str(self.working_directory / "oem_key_cert.bin")

            output_path = Path(output_file)

            try:
                oem_root_pk_raw = extract_raw_public_key_qxqy(oem_root_pk)
                oem_bl_pk_raw = extract_raw_public_key_qxqy(oem_bl_pk)
            except SKMTError as e:
                raise SKMTError(
                    f"STRICT KEY EXTRACTION FAILED! Cannot generate Key Certificate.\n"
                    f"Reason: {e}\n"
                    f"FIX: Ensure public keys are valid PEM/DER format with P-256 curve."
                )

            logger.info(f"OEM_BL public key (raw, extracted STRICT): {len(oem_bl_pk_raw)} bytes")
            logger.info(f"OEM_BL public key (raw, first 16 bytes): {oem_bl_pk_raw[:16].hex()}...")
            logger.info(f"OEM_BL public key (raw, last 16 bytes): ...{oem_bl_pk_raw[-16:].hex()}")

            # Load ALL values from project_config.json - NO HARDCODED VALUES!
            cert_config = _get_certificate_config()
            key_cert_config = cert_config.get("key_certificate", {})
            
            MAGIC_U32 = int(key_cert_config.get("magic"), 16)
            MANIFEST_VERSION = int(key_cert_config.get("manifest_version"), 16)
            FLAGS = int(key_cert_config.get("flags"), 16)
            RESERVED = b'\x00' * 20

            header = struct.pack('<I', MAGIC_U32) + struct.pack('<I', MANIFEST_VERSION) + struct.pack('<I', FLAGS) + RESERVED
            
            # Verify header size
            if len(header) != 32:
                raise SKMTError(f"Key Certificate header must be 32 bytes, got {len(header)} bytes")

            TLV_ECC_PUBKEY_TYPE_LENGTH = int(key_cert_config.get("tlv_ecc_pubkey_type_length"), 16)
            tlv_ecc_pubkey = struct.pack('<I', TLV_ECC_PUBKEY_TYPE_LENGTH) + oem_root_pk_raw[:64].ljust(64, b'\x00')

            TLV_KEYHASH_TYPE_LENGTH = int(key_cert_config.get("tlv_keyhash_type_length"), 16)
            oem_bl_pk_hash = calculate_oem_bl_pk_hash(oem_bl_pk)

            tlv_keyhash = struct.pack('<I', TLV_KEYHASH_TYPE_LENGTH) + oem_bl_pk_hash

            TLV_EXPECTED_SIG_TYPE_LENGTH = int(key_cert_config.get("tlv_expected_sig_type_length"), 16)

            tlv_section_for_signing = tlv_ecc_pubkey + tlv_keyhash
            tlv_expected_sig_placeholder = struct.pack('<I', TLV_EXPECTED_SIG_TYPE_LENGTH) + (b'\x00' * 64)
            tlv_section_full = tlv_section_for_signing + tlv_expected_sig_placeholder
            tlv_length = len(tlv_section_full)

            data_to_sign = header + struct.pack('<I', tlv_length) + tlv_section_for_signing

            if hsm_client is None:
                raise SKMTError("HSM client required for signing Key Certificate")

            digest = hashlib.sha256(data_to_sign).digest()
            signature = hsm_client.sign_digest(oem_root_sk_handle, digest)

            if len(signature) > 64:
                signature = self._der_to_raw_signature(signature)

            signature = signature[:64].ljust(64, b'\x00')
            tlv_expected_sig = struct.pack('<I', TLV_EXPECTED_SIG_TYPE_LENGTH) + signature
            tlv_section_final = tlv_section_for_signing + tlv_expected_sig

            cert_data = header + struct.pack('<I', tlv_length) + tlv_section_final
            self._validate_certificate_structure(cert_data, "key", cert_config)
            output_path.write_bytes(cert_data)

            # Detailed validation logging
            logger.info(f"Generated Key Certificate: {output_file} ({len(cert_data)} bytes) [OK]")
            logger.debug(f"Magic: {cert_data[0:4].hex()} ({cert_data[0:4].decode('ascii', errors='replace')})")
            logger.debug(f"Header size: 32 bytes")
            logger.debug(f"TLV length: {tlv_length} bytes")
            logger.debug(f"Total size: {len(cert_data)} bytes (expected: 208)")

            return self._parse_key_certificate(cert_data, str(output_path))

        except Exception as e:
            raise SKMTError(f"Failed to generate Key Certificate: {str(e)}") from e
    
    def _der_to_raw_signature(self, der_sig: bytes) -> bytes:
        """Convert DER-encoded ECDSA signature to raw R||S format."""
        try:
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
            r, s = decode_dss_signature(der_sig)
            # Convert to 32-byte big-endian
            r_bytes = r.to_bytes(32, 'big')
            s_bytes = s.to_bytes(32, 'big')
            return r_bytes + s_bytes
        except Exception:
            return der_sig[:64]
    
    def _validate_certificate_structure(self, cert_data: bytes, cert_type: str, cert_config: dict = None) -> None:
        """
        Validate certificate structure matches Renesas specification exactly.
        
        Args:
            cert_data: Certificate binary data
            cert_type: "key" or "code"
            cert_config: Certificate config from project_config.json
        
        Raises:
            SKMTError: If structure is invalid
        """
        import struct
        
        # Load config if not provided
        if cert_config is None:
            cert_config = _get_certificate_config()
        
        if cert_type == "key":
            key_cert_config = cert_config.get("key_certificate", {})
            expected_size = 208
            expected_magic_u32 = int(key_cert_config.get("magic", "0x6B657963"), 16)
            expected_manifest = int(key_cert_config.get("manifest_version", "0x00010000"), 16)
            expected_flags = int(key_cert_config.get("flags", "0x00000000"), 16)
            expected_magic = struct.pack('<I', expected_magic_u32)
            
            if len(cert_data) != expected_size:
                raise SKMTError(
                    f"Key Certificate size mismatch: got {len(cert_data)} bytes, "
                    f"expected {expected_size} bytes"
                )
            
            # Verify magic (must match little-endian format)
            magic = cert_data[0:4]
            if magic != expected_magic:
                magic_u32 = struct.unpack('<I', magic)[0]
                raise SKMTError(
                    f"Key Certificate magic mismatch: got {magic.hex()} (uint32: 0x{magic_u32:08X}), "
                    f"expected {expected_magic.hex()} (uint32: 0x{expected_magic_u32:08X})"
                )
            
            # Verify header structure (32 bytes)
            manifest_version = struct.unpack('<I', cert_data[4:8])[0]
            flags = struct.unpack('<I', cert_data[8:12])[0]
            
            if manifest_version != expected_manifest:
                logger.warning(f"Key Certificate manifest version: 0x{manifest_version:08X} (expected 0x{expected_manifest:08X})")
            
            if flags != expected_flags:
                logger.warning(f"Key Certificate flags: 0x{flags:08X} (expected 0x{expected_flags:08X})")

            tlv_length = struct.unpack('<I', cert_data[32:36])[0]
            expected_tlv_length = 172  # 68 + 36 + 68
            if tlv_length != expected_tlv_length:
                raise SKMTError(
                    f"Key Certificate TLV length mismatch: got {tlv_length}, "
                    f"expected {expected_tlv_length}"
                )
            
            logger.debug(f"Key Certificate structure validated: [OK]")
            
        elif cert_type == "code":
            code_cert_config = cert_config.get("code_certificate", {})
            expected_size = 216
            expected_magic_u32 = int(code_cert_config.get("magic", "0x636F6463"), 16)
            expected_manifest = int(code_cert_config.get("manifest_version", "0x00010000"), 16)
            expected_flags = int(code_cert_config.get("flags", "0x00000000"), 16)
            expected_magic = struct.pack('<I', expected_magic_u32)
            
            if len(cert_data) != expected_size:
                raise SKMTError(
                    f"Code Certificate size mismatch: got {len(cert_data)} bytes, "
                    f"expected {expected_size} bytes"
                )
            
            # Verify magic (must match little-endian format)
            magic = cert_data[0:4]
            if magic != expected_magic:
                magic_u32 = struct.unpack('<I', magic)[0]
                raise SKMTError(
                    f"Code Certificate magic mismatch: got {magic.hex()} (uint32: 0x{magic_u32:08X}), "
                    f"expected {expected_magic.hex()} (uint32: 0x{expected_magic_u32:08X})"
                )
            
            # Verify header structure (32 bytes)
            manifest_version = struct.unpack('<I', cert_data[4:8])[0]
            flags = struct.unpack('<I', cert_data[8:12])[0]
            load_addr = struct.unpack('<I', cert_data[12:16])[0]
            dest_addr = struct.unpack('<I', cert_data[16:20])[0]
            image_size = struct.unpack('<I', cert_data[20:24])[0]
            image_version = struct.unpack('<I', cert_data[24:28])[0]
            
            if manifest_version != expected_manifest:
                logger.warning(f"Code Certificate manifest version: 0x{manifest_version:08X} (expected 0x{expected_manifest:08X})")
            
            if flags != expected_flags:
                logger.warning(f"Code Certificate flags: 0x{flags:08X} (expected 0x{expected_flags:08X})")
            
            # Verify TLV length (at offset 32)
            tlv_length = struct.unpack('<I', cert_data[32:36])[0]
            expected_tlv_length = 180  # 68 + 8 + 36 + 68
            if tlv_length != expected_tlv_length:
                raise SKMTError(
                    f"Code Certificate TLV length mismatch: got {tlv_length}, "
                    f"expected {expected_tlv_length}"
                )
            
            logger.debug(f"Code Certificate structure validated: [OK]")
            logger.debug(f"  Load addr: 0x{load_addr:08X}, Dest addr: 0x{dest_addr:08X}")
            logger.debug(f"  Image size: {image_size} bytes, Version: {image_version}")
        
        else:
            raise ValueError(f"Invalid certificate type: {cert_type}")

    def generate_code_certificate(
        self,
        oem_bl_sk_handle: str,
        oem_bl_pk: bytes,
        oem_bl_binary: bytes,
        output_file: Optional[str] = None,
        version: int = None,
        oem_root_pk: Optional[bytes] = None,
        oem_root_sk_handle: Optional[str] = None,
        hsm_client = None,
        load_addr: int = None,
        dest_addr: int = None,
        oem_bl_pk_hash: Optional[bytes] = None,
    ) -> CodeCertificate:
        """
        Generate Code Certificate using HSM signing (NO local private keys!).
        EXACT as reference script - uses ACTUAL binary size, not fixed flash_length!

        The Code Certificate authenticates the OEM Bootloader (MCUboot) binary
        using the OEM Bootloader Secret Key stored in HSM.

        Args:
            oem_bl_sk_handle: HSM Key ID for OEM Bootloader Secret Key
            oem_bl_pk: OEM Bootloader Public Key bytes (PEM)
            oem_bl_binary: OEM Bootloader binary data (from parse_srec - actual size!)
            output_file: Optional output file path
            version: Certificate version for anti-rollback protection (1-64)
            oem_root_pk: OEM Root Public Key bytes (PEM) - DEPRECATED, not used
            hsm_client: HSM client for signing (required!)
            load_addr: Load address (default from config: 0x02000000)
            dest_addr: Destination address (default from config: 0x02000000)
            oem_bl_pk_hash: KEYHASH from Key Certificate (SHA256(OEM_BL_PK)) - REQUIRED

        Returns:
            CodeCertificate object

        Raises:
            SKMTError: If certificate generation fails
        """
        try:
            import struct
            import hashlib
            from zlib import crc32 as zlib_crc32
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            
            if output_file is None:
                output_file = str(self.working_directory / "oem_code_cert.bin")

            output_path = Path(output_file)

            if hsm_client is None:
                raise SKMTError("HSM client required for signing Code Certificate")

            oem_bl_pk_raw = extract_raw_public_key_qxqy(oem_bl_pk)
            logger.info(f"OEM_BL public key (raw, extracted): {len(oem_bl_pk_raw)} bytes")

            # Load ALL values from project_config.json - NO HARDCODED VALUES!
            cert_config = _get_certificate_config()
            code_cert_config = cert_config.get("code_certificate", {})
            
            # Read addresses from config if not provided
            if load_addr is None:
                load_addr = int(cert_config.get("load_addr"), 16)
            if dest_addr is None:
                dest_addr = int(cert_config.get("dest_addr"), 16)
            if version is None:
                version = cert_config.get("version", 1)

            bl_binary = bytearray(oem_bl_binary)
            img_size = len(bl_binary)
            
            if img_size == 0:
                raise SKMTError("Bootloader binary is empty!")
            
            if img_size < 64:
                bl_binary += b'\xFF' * (64 - img_size)
                img_size = 64
            if img_size % 16 != 0:
                pad = 16 - (img_size % 16)
                bl_binary += b'\xFF' * pad
                img_size += pad

            bl_crc32 = zlib_crc32(bytes(bl_binary)) & 0xFFFFFFFF
            image_size = img_size

            if oem_bl_pk_hash is not None:
                signer_id = oem_bl_pk_hash
            else:
                error_msg = (
                    "OBLIGATORY ASSERT FAILED: oem_bl_pk_hash is None! "
                    "SIGNER_ID must equal KEYHASH from Key Certificate. "
                    "Provisioning stopped - device will reject certificates with AAAA0204!"
                )
                logger.error(error_msg)
                raise SKMTError(error_msg)

            MAGIC_U32 = int(code_cert_config.get("magic"), 16)
            MANIFEST_VERSION = int(code_cert_config.get("manifest_version"), 16)
            FLAGS = int(code_cert_config.get("flags"), 16)
            BUILD_NUMBER = cert_config.get("build_number", 0)
            

            header = struct.pack('<I', MAGIC_U32) + struct.pack('<I', MANIFEST_VERSION) + struct.pack('<I', FLAGS)  # 12 bytes
            header += struct.pack('<IIII', load_addr, dest_addr, image_size, version)  # 16 bytes
            header += struct.pack('<I', BUILD_NUMBER)  # 4 bytes

            TLV_ECC_PUBKEY_TYPE_LENGTH = int(code_cert_config.get("tlv_ecc_pubkey_type_length"), 16)
            tlv_ecc_pubkey = struct.pack('<I', TLV_ECC_PUBKEY_TYPE_LENGTH) + oem_bl_pk_raw[:64].ljust(
                64, b'\x00')

            TLV_EXPECTED_CRC_TYPE_LENGTH = int(code_cert_config.get("tlv_expected_crc_type_length"), 16)
            tlv_expected_crc = struct.pack('<I', TLV_EXPECTED_CRC_TYPE_LENGTH) + struct.pack(
                '<I', bl_crc32)

            TLV_SIGNER_ID_TYPE_LENGTH = int(code_cert_config.get("tlv_signer_id_type_length"), 16)
            tlv_signer_id = struct.pack('<I', TLV_SIGNER_ID_TYPE_LENGTH) + signer_id

            TLV_EXPECTED_SIG_TYPE_LENGTH = int(code_cert_config.get("tlv_expected_sig_type_length"), 16)
            tlv_expected_sig_placeholder = struct.pack(
                '<I', TLV_EXPECTED_SIG_TYPE_LENGTH) + (b'\x00' * 64)
            

            if len(tlv_ecc_pubkey) != 68:
                raise SKMTError(f"TLV ECC_PUBKEY has wrong size: "
                                f"{len(tlv_ecc_pubkey)} bytes, expected 68 bytes")

            first_tlv_type = struct.unpack('<I', tlv_ecc_pubkey[0:4])[0]
            if first_tlv_type != TLV_ECC_PUBKEY_TYPE_LENGTH:
                raise SKMTError(f"First TLV Type&Length is wrong: 0x{first_tlv_type:08X}, "
                                f"expected 0x{TLV_ECC_PUBKEY_TYPE_LENGTH:08X} (from config)")

            # TLV section (without signature for now)
            tlv_section = tlv_ecc_pubkey + tlv_expected_crc + tlv_signer_id + tlv_expected_sig_placeholder
            tlv_length = len(tlv_section)

            tlv_section_for_signing = tlv_ecc_pubkey + tlv_expected_crc + tlv_signer_id

            data_to_sign = header + struct.pack('<I', tlv_length) + tlv_section_for_signing + bytes(bl_binary)
            logger.info(f"Code Certificate payload to sign: {len(data_to_sign)} bytes")
            logger.info(f"  Header: 32 bytes, TLV: 4 + {len(tlv_section_for_signing)} bytes")
            logger.info(f"  Bootloader binary (padded): {len(bl_binary)} bytes")
            

            digest = hashlib.sha256(data_to_sign).digest()
            signature = hsm_client.sign_digest(oem_bl_sk_handle, digest)
            logger.info(f"Code Certificate signed with OEM_BL_SK: {len(signature)} bytes")
            
            # Ensure signature is 64 bytes (R || S for P-256)
            if len(signature) > 64:
                signature = self._der_to_raw_signature(signature)

            signature = signature[:64].ljust(64, b'\x00')
            tlv_expected_sig = struct.pack('<I', TLV_EXPECTED_SIG_TYPE_LENGTH) + signature
            tlv_section_final = tlv_ecc_pubkey + tlv_expected_crc + tlv_signer_id + tlv_expected_sig
            cert_data = header + struct.pack('<I', tlv_length) + tlv_section_final

            signer_id_offset = 32 + 4 + 68 + 8 + 4  # Header(32) + TLV_Length(4) + ECC_PUBKEY(68) + EXPECTED_CRC(8) + SIGNER_ID_TypeLength(4) = 116
            cert_signer_id = cert_data[signer_id_offset:signer_id_offset + 32]

            if oem_bl_pk_hash is not None and cert_signer_id != oem_bl_pk_hash:
                error_msg = (
                    f"SIGNER_ID in Code Certificate ({cert_signer_id.hex()[:16]}...) "
                    f"!= KEYHASH from Key Certificate ({oem_bl_pk_hash.hex()[:16]}...). ")
                logger.error(error_msg)
                raise SKMTError(error_msg)


            tlv1_offset = 32 + 4
            tlv1_type_length = cert_data[tlv1_offset:tlv1_offset + 4]
            tlv1_value = cert_data[tlv1_offset + 4:tlv1_offset + 4 + 64]  # 64 bytes Qx||Qy
            tlv1_hash = hashlib.sha256(tlv1_value).digest()

            self._validate_certificate_structure(cert_data, "code", cert_config)
            output_path.write_bytes(cert_data)

            # Detailed validation logging
            logger.info(f"Generated Code Certificate (version {version}): {output_file} ({len(cert_data)} bytes) [OK]")
            logger.debug(f"Magic: {cert_data[0:4].hex()} ({cert_data[0:4].decode('ascii', errors='replace')})")
            logger.debug(f"Header size: 32 bytes")
            logger.debug(f"TLV length: {tlv_length} bytes")
            logger.debug(f"Load addr: 0x{load_addr:08X}, Dest addr: 0x{dest_addr:08X}")
            logger.debug(f"Image size: {image_size} bytes (FLASH_LENGTH), Version: {version}")
            logger.debug(f"Total size: {len(cert_data)} bytes (expected: 216)")

            return self._parse_code_certificate(cert_data, str(output_path))

        except Exception as e:
            raise SKMTError(f"Failed to generate Code Certificate: {str(e)}") from e

    def _run_command(self, cmd: list) -> subprocess.CompletedProcess:
        """
        Run SKMT command.

        Args:
            cmd: Command and arguments

        Returns:
            CompletedProcess result

        Raises:
            SKMTError: If command execution fails
        """
        try:
            logger.debug(f"Running SKMT command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                cwd=self.working_directory,
                capture_output=True,
                timeout=300,
                check=False,
            )

            return result

        except subprocess.TimeoutExpired as e:
            raise SKMTError(f"SKMT command timed out: {str(e)}") from e
        except Exception as e:
            raise SKMTError(f"Failed to execute SKMT command: {str(e)}") from e

    def parse_key_certificate(self, cert_file_path: str) -> KeyCertificate:
        """
        Parse Key Certificate from file.
        
        Args:
            cert_file_path: Path to Key Certificate binary file
            
        Returns:
            KeyCertificate object
            
        Raises:
            SKMTError: If parsing fails
        """
        cert_path = Path(cert_file_path)
        if not cert_path.exists():
            raise SKMTError(f"Key Certificate file not found: {cert_file_path}")
        
        cert_data = cert_path.read_bytes()
        return self._parse_key_certificate(cert_data, str(cert_path))

    def _parse_key_certificate(
        self, cert_data: bytes, file_path: str
    ) -> KeyCertificate:
        """
        Parse Key Certificate binary data according to Renesas format.
        
        Format (Table 8-13):
        - Header (32 bytes):
          - Magic: 0x6B657963 (4 bytes)
          - Manifest Version: 0x00010000 (4 bytes)
          - Flags: 0x00000000 (4 bytes)
          - Reserved: 0x00000000... (20 bytes)
        - TLV Length: 4 bytes
        - TLV ECC PUBKEY: Type&Length (4 bytes) + Value (64 bytes)
        - TLV KEYHASH: Type&Length (4 bytes) + Value (32 bytes)
        - TLV EXPECTED_SIG: Type&Length (4 bytes) + Value (64 bytes)

        Args:
            cert_data: Certificate binary data
            file_path: Path to certificate file

        Returns:
            KeyCertificate object

        Raises:
            SKMTError: If parsing fails
        """
        try:
            if len(cert_data) < 32:
                raise SKMTError("Invalid Key Certificate: data too short")

            # Parse header (32 bytes)
            magic = cert_data[0:4]
            manifest_version = cert_data[4:8]
            flags = cert_data[8:12]
            reserved = cert_data[12:32]

            cert_config = _get_certificate_config()
            key_cert_config = cert_config.get("key_certificate", {})
            expected_magic_u32 = int(key_cert_config.get("magic", "0x6B657963"), 16)
            expected_magic = struct.pack('<I', expected_magic_u32)
            if magic != expected_magic:
                logger.warning(f"Key Certificate magic mismatch: expected {expected_magic.hex()}, got {magic.hex()}")
            
            # Parse TLV Length (at offset 32)
            if len(cert_data) < 36:
                raise SKMTError("Invalid Key Certificate: missing TLV length")
            tlv_length = int.from_bytes(cert_data[32:36], byteorder="little")

            
            offset = 36  # After header + TLV length
            if len(cert_data) < offset + 172:
                raise SKMTError("Invalid Key Certificate: incomplete TLV data")

            oem_root_pk = cert_data[offset + 4:offset + 68]
            oem_bl_pk_hash = cert_data[offset + 68 + 4:offset + 68 + 36]
            expected_signature = cert_data[offset + 68 + 36 + 4:offset + 68 + 36 + 68]
            header = cert_data[0:32]

            return KeyCertificate(
                header=header,
                tlv_length=tlv_length,
                oem_root_pk=oem_root_pk,
                oem_bl_pk_hash=oem_bl_pk_hash,
                expected_signature=expected_signature,
                file_path=file_path,
            )

        except Exception as e:
            raise SKMTError(f"Failed to parse Key Certificate: {str(e)}") from e

    def _parse_code_certificate(
        self, cert_data: bytes, file_path: str
    ) -> CodeCertificate:
        """
        Parse Code Certificate binary data according to Renesas format.
        
        Format (Table 8-14):
        - Header (32 bytes):
          - Magic: 0x636F6463 (4 bytes)
          - Manifest Version: 0x00010000 (4 bytes)
          - Flags: 0x00000000 (4 bytes)
          - Load Addr: 4 bytes
          - Dest Addr: 4 bytes
          - Image size: 4 bytes
          - Image version: 4 bytes
          - Build number: 4 bytes
        - TLV Length: 4 bytes
        - TLV ECC PUBKEY: Type&Length (4 bytes) + Value (64 bytes)
        - TLV EXPECTED_CRC: Type&Length (4 bytes) + Value (4 bytes)
        - TLV SIGNER_ID: Type&Length (4 bytes) + Value (32 bytes)
        - TLV EXPECTED_SIG: Type&Length (4 bytes) + Value (64 bytes)

        Args:
            cert_data: Certificate binary data
            file_path: Path to certificate file

        Returns:
            CodeCertificate object

        Raises:
            SKMTError: If parsing fails
        """
        try:
            if len(cert_data) < 32:
                raise SKMTError("Invalid Code Certificate: data too short")

            # Parse header (32 bytes)
            magic = cert_data[0:4]
            manifest_version = cert_data[4:8]
            flags = cert_data[8:12]
            load_addr = cert_data[12:16]
            dest_addr = cert_data[16:20]
            image_size = cert_data[20:24]
            image_version = cert_data[24:28]
            build_number = cert_data[28:32]
            
            # Verify magic number from config
            cert_config = _get_certificate_config()
            code_cert_config = cert_config.get("code_certificate", {})
            expected_magic_u32 = int(code_cert_config.get("magic", "0x636F6463"), 16)
            expected_magic = struct.pack('<I', expected_magic_u32)
            if magic != expected_magic:
                logger.warning(f"Code Certificate magic mismatch: expected {expected_magic.hex()}, got {magic.hex()}")
            
            # Parse TLV Length (at offset 32)
            if len(cert_data) < 36:
                raise SKMTError("Invalid Code Certificate: missing TLV length")
            tlv_length = int.from_bytes(cert_data[32:36], byteorder="little")

            
            offset = 36  # After header + TLV length
            if len(cert_data) < offset + 180:
                raise SKMTError("Invalid Code Certificate: incomplete TLV data")

            # TLV structure: ECC_PUBKEY(68) + CRC(8) + SIGNER_ID(36) + SIG(68) = 180
            oem_bl_pk = cert_data[offset + 4:offset + 68]  # 64 bytes after type&len
            oem_bl_crc = cert_data[offset + 68 + 4:offset + 68 + 8]  # 4 bytes CRC32
            signer_id = cert_data[offset + 68 + 8 + 4:offset + 68 + 8 + 36]  # 32 bytes SIGNER_ID
            expected_signature = cert_data[offset + 68 + 8 + 36 + 4:offset + 68 + 8 + 36 + 68]  # 64 bytes

            header = cert_data[0:32]

            return CodeCertificate(
                header=header,
                tlv_length=tlv_length,
                oem_bl_pk=oem_bl_pk,
                oem_bl_crc=oem_bl_crc,
                signer_id=signer_id,
                expected_signature=expected_signature,
                file_path=file_path,
                oem_bl_hash=oem_bl_crc,
            )

        except Exception as e:
            raise SKMTError(f"Failed to parse Code Certificate: {str(e)}") from e

    def generate_ufpk(
        self, ufpk_hex: Optional[str] = None, output_file: Optional[str] = None
    ) -> Path:
        """
        Generate UFPK (User Factory Programming Key) file.

        Args:
            ufpk_hex: Optional 32-byte hex string for UFPK (default: random)
            output_file: Optional output file path

        Returns:
            Path to generated UFPK file

        Raises:
            SKMTError: If generation fails
        """
        try:
            if output_file is None:
                output_file = str(self.working_directory / "ufpk.key")

            output_path = Path(output_file).resolve()  # Use absolute path

            cmd = [str(self.skmt_path), "-genufpk", "-output", str(output_path)]

            if ufpk_hex:
                cmd.extend(["-ufpk", ufpk_hex])

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT UFPK generation failed: {result.stderr.decode()}"
                )

            logger.info(f"Generated UFPK: {output_file}")
            return output_path

        except Exception as e:
            raise SKMTError(f"Failed to generate UFPK: {str(e)}") from e

    def generate_kuk(
        self, kuk_hex: Optional[str] = None, output_file: Optional[str] = None
    ) -> Path:
        """
        Generate KUK (Key Update Key) file.

        Args:
            kuk_hex: Optional 32-byte hex string for KUK (default: random)
            output_file: Optional output file path

        Returns:
            Path to generated KUK file

        Raises:
            SKMTError: If generation fails
        """
        try:
            if output_file is None:
                output_file = str(self.working_directory / "kuk.key")

            output_path = Path(output_file).resolve()  # Use absolute path

            cmd = [str(self.skmt_path), "-genkuk", "-output", str(output_path)]

            if kuk_hex:
                cmd.extend(["-kuk", kuk_hex])

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT KUK generation failed: {result.stderr.decode()}"
                )

            logger.info(f"Generated KUK: {output_file}")
            return output_path

        except Exception as e:
            raise SKMTError(f"Failed to generate KUK: {str(e)}") from e

    def encrypt_tsip(
        self,
        program_file: Path,
        mode: str,
        output_file: Optional[str] = None,
        secure_boot_file: Optional[Path] = None,
        encrypt_key: Optional[str] = None,
        session_key: Optional[str] = None,
        iv_fw: Optional[str] = None,
        start_addr: Optional[str] = None,
        end_addr: Optional[str] = None,
        dest_addr: Optional[str] = None,
        filetype: str = "mot",
        version: int = 1,
        **kwargs,
    ) -> Path:
        """
        Encrypt program for TSIP (Trusted Secure IP) update.

        Args:
            program_file: User program file (*.mot)
            mode: FirmUpdate mode
            output_file: Optional output file path
            secure_boot_file: Optional secure boot file (*.mot)
            encrypt_key: Key to encrypt the session key
            session_key: Key to encrypt the program file (default: random)
            iv_fw: Initialization Vector (default: random)
            start_addr: Start address for encryption
            end_addr: End address for encryption
            dest_addr: Destination address (default: start_addr)
            filetype: Output file type (mot or rsu)
            version: RSU header version (default: 1)
            **kwargs: Additional TSIP options

        Returns:
            Path to encrypted file

        Raises:
            SKMTError: If encryption fails
        """
        try:
            if output_file is None:
                output_file = str(
                    self.working_directory / f"encrypted_tsip.{filetype}"
                )

            output_path = Path(output_file)

            cmd = [
                str(self.skmt_path),
                "-enctsip",
                "-mode",
                mode,
                "-prg",
                str(program_file),
                "-output",
                str(output_path),
                "-ver",
                str(version),
                "-filetype",
                filetype,
            ]

            if secure_boot_file:
                cmd.extend(["-prg_sb", str(secure_boot_file)])

            if encrypt_key:
                cmd.extend(["-enckey", encrypt_key])

            if session_key:
                cmd.extend(["-session_key", session_key])

            if iv_fw:
                cmd.extend(["-iv_fw", iv_fw])

            if start_addr:
                cmd.extend(["-startaddr", start_addr])

            if end_addr:
                cmd.extend(["-endaddr", end_addr])

            if dest_addr:
                cmd.extend(["-destaddr", dest_addr])

            # Add additional options from kwargs
            for key, value in kwargs.items():
                if value is not None:
                    cmd.extend([f"-{key}", str(value)])

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT TSIP encryption failed: {result.stderr.decode()}"
                )

            logger.info(f"Encrypted TSIP file: {output_file}")
            return output_path

        except Exception as e:
            raise SKMTError(f"Failed to encrypt TSIP: {str(e)}") from e

    def encrypt_sfp(
        self,
        program_file: Path,
        mcu: str,
        output_file: Optional[str] = None,
        encrypt_key: Optional[str] = None,
        ufpk: Optional[Path] = None,
        wrapped_ufpk: Optional[Path] = None,
        **kwargs,
    ) -> Path:
        """
        Encrypt program for Secure Factory Programming (SFP).

        Args:
            program_file: Program file to encrypt (*.mot)
            mcu: MCU type
            output_file: Optional output file path
            encrypt_key: AES 128-bit key
            ufpk: UFPK key file
            wrapped_ufpk: Wrapped UFPK key file
            **kwargs: Additional SFP options (al1key, al2key, nonce_prg, etc.)

        Returns:
            Path to encrypted file

        Raises:
            SKMTError: If encryption fails
        """
        try:
            if output_file is None:
                output_file = str(self.working_directory / "encrypted_sfp.mot")

            output_path = Path(output_file)

            cmd = [
                str(self.skmt_path),
                "-encsfp",
                "-mcu",
                mcu,
                "-prg",
                str(program_file),
                "-output",
                str(output_path),
            ]

            if encrypt_key:
                cmd.extend(["-enckey", encrypt_key])

            if ufpk:
                cmd.extend(["-ufpk", str(ufpk)])

            if wrapped_ufpk:
                cmd.extend(["-wufpk", str(wrapped_ufpk)])

            # Add additional options from kwargs
            for key, value in kwargs.items():
                if value is not None:
                    if isinstance(value, Path):
                        cmd.extend([f"-{key}", str(value)])
                    else:
                        cmd.extend([f"-{key}", str(value)])

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT SFP encryption failed: {result.stderr.decode()}"
                )

            logger.info(f"Encrypted SFP file: {output_file}")
            return output_path

        except Exception as e:
            raise SKMTError(f"Failed to encrypt SFP: {str(e)}") from e

    def encrypt_dotf(
        self,
        program_file: Path,
        key_type: str,
        encrypt_key: str,
        output_file: Optional[str] = None,
        nonce: Optional[str] = None,
        start_addr: Optional[str] = None,
        end_addr: Optional[str] = None,
        dest_addr: Optional[str] = None,
        **kwargs,
    ) -> Path:
        """
        Encrypt program for Decryption On-The-Fly (DOTF).

        Args:
            program_file: Program file to encrypt (*.mot)
            key_type: Key type
            encrypt_key: AES 128/192/256 bit key
            output_file: Optional output file path
            nonce: Nonce (default: random)
            start_addr: Start address to encrypt
            end_addr: End address to encrypt
            dest_addr: Destination address (default: same as plaintext)
            **kwargs: Additional DOTF options

        Returns:
            Path to encrypted file

        Raises:
            SKMTError: If encryption fails
        """
        try:
            if output_file is None:
                output_file = str(self.working_directory / "encrypted_dotf.mot")

            output_path = Path(output_file)

            cmd = [
                str(self.skmt_path),
                "-encdotf",
                "-keytype",
                key_type,
                "-enckey",
                encrypt_key,
                "-prg",
                str(program_file),
                "-output",
                str(output_path),
            ]

            if nonce:
                cmd.extend(["-nonce", nonce])

            if start_addr:
                cmd.extend(["-startaddr", start_addr])

            if end_addr:
                cmd.extend(["-endaddr", end_addr])

            if dest_addr:
                cmd.extend(["-destaddr", dest_addr])

            # Add additional options from kwargs
            for key, value in kwargs.items():
                if value is not None:
                    cmd.extend([f"-{key}", str(value)])

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT DOTF encryption failed: {result.stderr.decode()}"
                )

            logger.info(f"Encrypted DOTF file: {output_file}")
            return output_path

        except Exception as e:
            raise SKMTError(f"Failed to encrypt DOTF: {str(e)}") from e

    def calculate_response(
        self,
        challenge: str,
        key: str,
        algorithm: str = "AES128",
    ) -> str:
        """
        Calculate response value for Challenge & Response authentication.

        Args:
            challenge: Challenge value (hex string)
            key: DLM key data (hex string)
            algorithm: Algorithm for response calculation (default: AES128)

        Returns:
            Response value as hex string

        Raises:
            SKMTError: If calculation fails
        """
        try:
            cmd = [
                str(self.skmt_path),
                "-calcresponse",
                "-challenge",
                challenge,
                "-key",
                key,
                "-algorithm",
                algorithm,
            ]

            result = self._run_command(cmd)

            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT response calculation failed: {result.stderr.decode()}"
                )

            # Parse response from stdout
            output = result.stdout.decode().strip()
            # SKMT typically outputs the response value
            # Format may vary, so we return the full output
            logger.info(f"Calculated response for challenge: {challenge[:16]}...")
            return output

        except Exception as e:
            raise SKMTError(f"Failed to calculate response: {str(e)}") from e

    def generate_certificates_with_cli(
        self,
        bootloader_file: Path,
        oem_root_private_key: Path,
        oem_bl_private_key: Path,
        output_key_cert: Path,
        output_code_cert: Path,
        mode: str = "signature",
        loadaddr: str = "02000000",
        cfsize: str = "200000",
        oembl_size: str = None,
        version: int = 1,
    ) -> tuple[Path, Path]:
        """
        Generate Key Certificate and Code Certificate using SKMT CLI.
        
        Uses SKMT /gencert command with correct syntax from Renesas documentation
        R20UT5349EJ0111.
        
        Args:
            bootloader_file: Path to bootloader SREC/MOT file
            oem_root_private_key: Path to OEM Root private key (PEM)
            oem_bl_private_key: Path to OEM Bootloader private key (PEM)
            output_key_cert: Output path for Key Certificate
            output_code_cert: Output path for Code Certificate
            mode: Certificate mode ("signature" for standard secure boot)
            loadaddr: Load address in hex without 0x prefix (default: "02000000")
            cfsize: Code flash size in hex without 0x prefix (default: "200000" = 2MB)
            oembl_size: CRITICAL! Bootloader size in hex (16-byte aligned). If specified,
                       SKMT calculates MAC only on [loadaddr, loadaddr+oembl_size].
                       If omitted, SKMT calculates MAC on entire cfsize (includes app!).
                       Example: "10000" = 64KB
            version: Certificate version (default: 1)
            
        Returns:
            Tuple of (key_cert_path, code_cert_path)
            
        Raises:
            SKMTError: If certificate generation fails
        """
        if not bootloader_file.exists():
            raise SKMTError(f"Bootloader file not found: {bootloader_file}")
        if not oem_root_private_key.exists():
            raise SKMTError(f"OEM Root private key not found: {oem_root_private_key}")
        if not oem_bl_private_key.exists():
            raise SKMTError(f"OEM Bootloader private key not found: {oem_bl_private_key}")
        
        try:
            cmd = [
                str(self.skmt_path),
                "/gencert",
                "/mode", mode,
                "/loadaddr", loadaddr,
                "/cfsize", cfsize,
            ]

            if oembl_size:
                cmd.extend(["/oembl_size", oembl_size])
            
            cmd.extend([
                "/ver", str(version),
                "/oembl", str(bootloader_file),
                "/oembl_private", f'file="{oem_bl_private_key}"',
                "/oemroot_private", f'file="{oem_root_private_key}"',
                "/output_keycert", str(output_key_cert),
                "/output_codecert", str(output_code_cert),
            ])
            
            logger.info(f"Running SKMT /gencert: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                raise SKMTError(
                    f"SKMT /gencert failed (exit {result.returncode}): "
                    f"{result.stderr or result.stdout}"
                )

            if not output_key_cert.exists():
                raise SKMTError(f"Key Certificate not generated: {output_key_cert}")
            if not output_code_cert.exists():
                raise SKMTError(f"Code Certificate not generated: {output_code_cert}")
            
            logger.info(f"Generated Key Certificate: {output_key_cert}")
            logger.info(f"Generated Code Certificate: {output_code_cert}")
            
            return (output_key_cert, output_code_cert)
            
        except subprocess.TimeoutExpired as e:
            raise SKMTError(f"SKMT /gencert timed out: {str(e)}") from e
        except Exception as e:
            if isinstance(e, SKMTError):
                raise
            raise SKMTError(f"Failed to generate certificates: {str(e)}") from e

