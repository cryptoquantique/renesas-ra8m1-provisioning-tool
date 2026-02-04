"""
HSM client factory.

This module provides a factory for creating HSM client instances
based on configuration.
"""

from typing import Optional

from config.settings import HSMConfig
from utils.exceptions import HSMError
from utils.logging import get_logger
from .base import HSMClient
from .aws_kms import AWSKMSClient

logger = get_logger(__name__)


def create_hsm_client(config: HSMConfig) -> HSMClient:
    """
    Create HSM client based on configuration.

    AWS KMS for key management and signing!

    Args:
        config: HSMConfig instance

    Returns:
        Initialized HSMClient instance

    Raises:
        HSMError: If HSM client creation fails
    """
    hsm_config_dict = {
        "key_prefix": config.key_label_prefix,
    }

    hsm_type = config.hsm_type.lower() if config.hsm_type else "aws_kms"

    if hsm_type == "aws_kms":
        logger.info("Creating AWS KMS client")
        from utils.aws_credentials import get_aws_credentials

        aws_creds = get_aws_credentials(fallback_to_env=True)
        hsm_config_dict.update({
            "aws_region": config.aws_region or aws_creds.get("aws_region", "eu-central-1"),
            "aws_access_key_id": config.aws_access_key_id or aws_creds.get("aws_access_key_id"),
            "aws_secret_access_key": config.aws_secret_access_key or aws_creds.get("aws_secret_access_key"),
        })
        return AWSKMSClient(hsm_config_dict)
    elif hsm_type == "cloudhsm" or hsm_type == "cloudhsm_pkcs11":
        logger.info("Creating CloudHSM PKCS#11 client")
        from .cloudhsm_pkcs11 import CloudHSMClient
        
        hsm_config_dict.update({
            "pkcs11_library": config.pkcs11_library,
            "slot_id": config.slot_id or 0,
            "pin": config.pin,
        })
        return CloudHSMClient(hsm_config_dict)

    raise HSMError(f"Unknown HSM type: {hsm_type}. Supported: 'aws_kms', 'cloudhsm_pkcs11'")
