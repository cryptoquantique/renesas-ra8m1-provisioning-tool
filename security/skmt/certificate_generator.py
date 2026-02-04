"""
Certificate generation workflow.

This module provides a complete workflow for generating Key Certificate
and Code Certificate using SKMT with HSM keys.
"""

from pathlib import Path
from typing import Optional

from config.settings import SKMTConfig
from security.hsm.factory import create_hsm_client
from utils.exceptions import HSMError, SKMTError
from utils.logging import get_logger
from config.settings import HSMConfig
from .wrapper import SKMTWrapper
from models.certificates import KeyCertificate, CodeCertificate

logger = get_logger(__name__)


class CertificateGenerator:
    """
    Complete workflow for generating certificates.

    This class orchestrates:
    1. Get public keys from HSM (or use provided PEM files)
    2. Generate Key Certificate using OEM_ROOT_SK from HSM
    3. Generate Code Certificate using OEM_BL_SK from HSM
    """

    def __init__(
        self,
        skmt_config: SKMTConfig,
        hsm_config: HSMConfig,
    ):
        """
        Initialize certificate generator.

        Args:
            skmt_config: SKMT configuration (skmt_path is optional, only for legacy operations)
            hsm_config: HSM configuration for accessing secret keys
        
        Note:
            Certificate generation does NOT use SKMT for signing!
            All signing is done via AWS KMS (sign_digest).
            SKMT path is optional and only needed for legacy operations.
        """
        self.skmt_config = skmt_config
        self.hsm_config = hsm_config
        self.skmt_wrapper = SKMTWrapper(
            skmt_path=None,
            working_directory=skmt_config.working_directory,
        )

    def generate_key_certificate(
        self,
        oem_root_sk_key_id: str,
        oem_bl_pk_file: Path,
        output_file: Path,
        oem_root_pk_file: Optional[Path] = None,
    ) -> KeyCertificate:
        """
        Generate Key Certificate.

        The Key Certificate authenticates the OEM Bootloader Public Key
        using the OEM Root Secret Key stored in HSM.

        Args:
            oem_root_sk_key_id: HSM Key ID for OEM Root Secret Key
            oem_bl_pk_file: Path to OEM Bootloader public key file (PEM)
            output_file: Path to output Key Certificate file
            oem_root_pk_file: Optional path to OEM Root public key file (PEM).
                             If not provided, will be exported from HSM.

        Returns:
            KeyCertificate object

        Raises:
            SKMTError: If certificate generation fails
            HSMError: If HSM operations fail
        """
        try:
            hsm_client = create_hsm_client(self.hsm_config)
            hsm_client.connect()

            try:
                # Get OEM Root public key
                if oem_root_pk_file and oem_root_pk_file.exists():
                    logger.info(f"Using provided OEM Root public key: {oem_root_pk_file}")
                    oem_root_pk_bytes = oem_root_pk_file.read_bytes()
                else:
                    logger.info(f"Exporting OEM Root public key from HSM: {oem_root_sk_key_id}")
                    oem_root_pk_bytes = hsm_client.get_public_key(oem_root_sk_key_id)

                # Get OEM Bootloader public key
                if oem_bl_pk_file and oem_bl_pk_file.exists():
                    logger.info(f"Using provided OEM Bootloader public key: {oem_bl_pk_file}")
                    oem_bl_pk_bytes = oem_bl_pk_file.read_bytes()
                else:
                    raise SKMTError(
                        "OEM Bootloader public key file is required. "
                        "Please provide oem_bl_pk_file or export it first."
                    )

                logger.info("Generating Key Certificate...")
                certificate = self.skmt_wrapper.generate_key_certificate(
                    oem_root_sk_handle=oem_root_sk_key_id,
                    oem_root_pk=oem_root_pk_bytes,
                    oem_bl_pk=oem_bl_pk_bytes,
                    output_file=str(output_file),
                    hsm_client=hsm_client,
                )

                logger.info(f"Key Certificate generated successfully: {output_file}")
                return certificate

            finally:
                hsm_client.disconnect()

        except Exception as e:
            if isinstance(e, (SKMTError, HSMError)):
                raise
            raise SKMTError(f"Failed to generate Key Certificate: {str(e)}") from e

    def generate_code_certificate(
        self,
        oem_bl_sk_key_id: str,
        oem_bl_pk_file: Path,
        output_file: Path,
        bootloader_binary: bytes = None,
        bootloader_binary_file: Path = None,
        oem_root_sk_key_id: Optional[str] = None,
        oem_root_pk_file: Optional[Path] = None,
        version: int = 1,
        oem_bl_pk_hash: Optional[bytes] = None,
    ) -> CodeCertificate:
        """
        Generate Code Certificate using HSM signing (NO local private keys!).
        EXACT as reference - uses ACTUAL bootloader size, not fixed flash_length!

        The Code Certificate authenticates the OEM Bootloader binary
        using the OEM Bootloader Secret Key stored in HSM.

        Args:
            oem_bl_sk_key_id: HSM Key ID for OEM Bootloader Secret Key
            oem_bl_pk_file: Path to OEM Bootloader public key file (PEM)
            output_file: Path to output Code Certificate file
            bootloader_binary: Bootloader binary data (from parse_srec - ACTUAL size)
            bootloader_binary_file: Path to bootloader binary/SREC file (alternative)
            oem_root_sk_key_id: HSM Key ID for OEM Root Secret Key (optional)
            oem_root_pk_file: Path to OEM Root public key file (optional)
            version: Certificate version for anti-rollback protection (1-64)
            oem_bl_pk_hash: KEYHASH from Key Certificate - REQUIRED

        Returns:
            CodeCertificate object

        Raises:
            SKMTError: If certificate generation fails
            HSMError: If HSM operations fail
        """
        if bootloader_binary is None and bootloader_binary_file is None:
            raise SKMTError("Either bootloader_binary or bootloader_binary_file must be provided")

        try:
            hsm_client = create_hsm_client(self.hsm_config)
            hsm_client.connect()

            try:
                if oem_bl_pk_file and oem_bl_pk_file.exists():
                    oem_bl_pk_bytes = oem_bl_pk_file.read_bytes()
                else:
                    oem_bl_pk_bytes = hsm_client.get_public_key(oem_bl_sk_key_id)

                oem_root_pk_bytes = None
                if oem_root_pk_file and oem_root_pk_file.exists():
                    oem_root_pk_bytes = oem_root_pk_file.read_bytes()
                elif oem_root_sk_key_id:
                    oem_root_pk_bytes = hsm_client.get_public_key(oem_root_sk_key_id)

                if bootloader_binary is not None:
                    bootloader_binary_bytes = bootloader_binary
                else:
                    bootloader_binary_bytes = bootloader_binary_file.read_bytes()

                logger.info(f"Generating Code Certificate (version {version}) with HSM signing...")
                logger.info(f"Bootloader binary size: {len(bootloader_binary_bytes)} bytes (ACTUAL size from parse_srec)")
                
                certificate = self.skmt_wrapper.generate_code_certificate(
                    oem_bl_sk_handle=oem_bl_sk_key_id,
                    oem_bl_pk=oem_bl_pk_bytes,
                    oem_bl_binary=bootloader_binary_bytes,
                    output_file=str(output_file),
                    version=version,
                    hsm_client=hsm_client,
                    oem_bl_pk_hash=oem_bl_pk_hash,
                )

                logger.info(f"Code Certificate generated successfully: {output_file}")
                return certificate

            finally:
                hsm_client.disconnect()

        except Exception as e:
            if isinstance(e, (SKMTError, HSMError)):
                raise
            raise SKMTError(f"Failed to generate Code Certificate: {str(e)}") from e
    
    def _extract_binary_from_srec(self, srec_file: Path, start_addr: int = 0x02000000, image_size: Optional[int] = None) -> bytes:
        """
        Extract binary data from SREC file and reconstruct buffer for CRC32 calculation.
        
        CRITICAL: For combined.srec, this extracts ONLY Code Flash region (FSBL + MCUboot + App),
        NOT OSM records or Data Flash. The extracted binary MUST match exactly what Boot Firmware
        will read from flash for CRC32 calculation.
        
        Args:
            srec_file: Path to SREC file
            start_addr: Start address for extraction (default: 0x02000000)
            image_size: Size of image buffer to create (default: None, will use max address found)
            
        Returns:
            Binary data as bytes (buffer of image_size bytes, initialized with 0xFF, with SREC data applied)
        """
        IMAGE_START = start_addr
        
        # OSM regions to exclude
        CF_OSM_START = 0x0300A100
        CF_OSM_END = 0x0300A2FF
        DF_OSM_START = 0x27030000
        DF_OSM_END = 0x2703FFFF

        max_addr_with_data = IMAGE_START - 1

        with open(srec_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('S3'):
                    continue
                
                count = int(line[2:4], 16)
                addr = int(line[4:12], 16)
                data_len = count - 5
                end_addr = addr + data_len - 1

                if addr >= IMAGE_START:
                    if (CF_OSM_START <= addr <= CF_OSM_END) or (DF_OSM_START <= addr <= DF_OSM_END):
                        continue
                    
                    if end_addr > max_addr_with_data:
                        max_addr_with_data = end_addr
        
        # Determine buffer size
        if image_size is None:
            buffer_size = max_addr_with_data - IMAGE_START + 1
        else:
            buffer_size = image_size
        
        if buffer_size <= 0:
            raise ValueError(f"Invalid buffer size: {buffer_size} (max_addr: 0x{max_addr_with_data:08X})")

        binary_data = bytearray(b'\xFF' * buffer_size)

        with open(srec_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('S3'):
                    continue
                
                count = int(line[2:4], 16)
                addr = int(line[4:12], 16)
                data_len = count - 5

                if addr >= IMAGE_START:
                    if (CF_OSM_START <= addr <= CF_OSM_END) or (DF_OSM_START <= addr <= DF_OSM_END):
                        continue

                    hex_data = line[12:12 + data_len * 2]
                    data = bytes.fromhex(hex_data)

                    offset = addr - IMAGE_START

                    if offset + len(data) <= len(binary_data):
                        binary_data[offset:offset + len(data)] = data
                    else:
                        logger.warning(
                            f"SREC data at 0x{addr:08X} exceeds buffer size "
                            f"(offset: {offset}, data_len: {len(data)}, buffer_size: {len(binary_data)})"
                        )
        
        logger.info(
            f"Extracted binary from SREC: {len(binary_data)} bytes (0x{len(binary_data):X}) "
            f"from SREC, address range: 0x{IMAGE_START:08X} - 0x{IMAGE_START + len(binary_data) - 1:08X} "
            f"(Code Flash region only, OSM/Data Flash excluded, buffer initialized with 0xFF)"
        )
        
        return bytes(binary_data)

