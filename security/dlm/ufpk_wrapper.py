"""
UFPK wrapping workflow with DLM and PGP integration.

This module provides a high-level interface for the complete UFPK wrapping
workflow: encrypt -> DLM wrap -> decrypt.
"""

from pathlib import Path
from typing import Optional

from config.settings import DLMConfig, PGPConfig
from utils.exceptions import DLMError, PGPError
from utils.logging import get_logger
from security.dlm.client import DLMClient
from security.pgp.client import PGPClient

logger = get_logger(__name__)


class UFPKWrapper:
    """
    High-level UFPK wrapping workflow.

    This class orchestrates the complete UFPK wrapping process:
    1. Encrypt UFPK with Renesas public key (PGP)
    2. Send to DLM server for wrapping
    3. Download wrapped UFPK
    4. Decrypt wrapped UFPK with customer private key (PGP)
    """

    def __init__(
        self, pgp_config: PGPConfig, dlm_config: DLMConfig, auto_connect: bool = True
    ):
        """
        Initialize UFPK wrapper.

        Args:
            pgp_config: PGP configuration
            dlm_config: DLM server configuration
            auto_connect: Whether to automatically test DLM connection on init
        """
        self.pgp_config = pgp_config
        self.dlm_config = dlm_config
        self.pgp_client = PGPClient(pgp_config)
        self.dlm_client = DLMClient(dlm_config, auto_connect=auto_connect)

    def wrap_ufpk_complete(
        self,
        ufpk_file: Path,
        output_file: Path,
        device_id: Optional[str] = None,
        temp_dir: Optional[Path] = None,
    ) -> Path:
        """
        Complete UFPK wrapping workflow.

        This method performs the complete workflow:
        1. Encrypt UFPK with Renesas public key
        2. Send encrypted UFPK to DLM server
        3. Wait for wrapping completion
        4. Download wrapped UFPK
        5. Decrypt wrapped UFPK with customer private key

        Args:
            ufpk_file: Path to plain UFPK file
            output_file: Path to save final wrapped UFPK file
            device_id: Optional device ID
            temp_dir: Optional temporary directory for intermediate files

        Returns:
            Path to wrapped UFPK file

        Raises:
            DLMError: If DLM operations fail
            PGPError: If PGP operations fail
        """
        import tempfile
        import shutil

        if temp_dir is None:
            temp_dir = Path(tempfile.mkdtemp(prefix="ufpk_wrap_"))
            cleanup_temp = True
        else:
            temp_dir = Path(temp_dir)
            temp_dir.mkdir(parents=True, exist_ok=True)
            cleanup_temp = False

        try:
            logger.info("Starting complete UFPK wrapping workflow")

            if not ufpk_file.exists():
                raise DLMError(f"UFPK file not found: {ufpk_file}")

            if not self.pgp_config.renesas_public_key:
                raise PGPError("Renesas public key not configured")

            if not self.pgp_config.customer_private_key:
                raise PGPError("Customer private key not configured")

            renesas_key = Path(self.pgp_config.renesas_public_key)
            customer_key = Path(self.pgp_config.customer_private_key)

            if not renesas_key.exists():
                raise PGPError(
                    f"Renesas public key not found: {renesas_key}"
                )

            if not customer_key.exists():
                raise PGPError(
                    f"Customer private key not found: {customer_key}"
                )

            encrypted_ufpk = temp_dir / "encrypted_ufpk.gpg"
            wrapped_encrypted_ufpk = temp_dir / "wrapped_encrypted_ufpk.gpg"

            logger.info("Step 1: Encrypting UFPK with Renesas public key")
            self.pgp_client.encrypt_file(
                input_file=ufpk_file,
                recipient_key_file=renesas_key,
                output_file=encrypted_ufpk,
            )

            logger.info("Step 2: Sending encrypted UFPK to DLM server")
            self.dlm_client.wrap_ufpk_complete(
                encrypted_ufpk_file=encrypted_ufpk,
                output_file=wrapped_encrypted_ufpk,
                device_id=device_id,
            )

            logger.info("Step 3: Decrypting wrapped UFPK with customer private key")
            wrapped_ufpk = self.pgp_client.decrypt_file(
                input_file=wrapped_encrypted_ufpk,
                private_key_file=customer_key,
                output_file=output_file,
            )

            logger.info(f"UFPK wrapping completed: {wrapped_ufpk}")
            return wrapped_ufpk

        except Exception as e:
            if isinstance(e, (DLMError, PGPError)):
                raise
            raise DLMError(f"UFPK wrapping workflow failed: {str(e)}") from e

        finally:
            if cleanup_temp and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as e:
                    logger.warning(
                        f"Failed to clean up temporary directory: {e}"
                    )


