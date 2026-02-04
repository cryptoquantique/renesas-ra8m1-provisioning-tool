"""
AWS credentials loader.

This module provides centralized loading of AWS credentials from a JSON file.
All AWS credential usage should go through this module for centralized management.
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict

from utils.exceptions import ConfigurationError
from utils.logging import get_logger

logger = get_logger(__name__)

# Default credentials file path
DEFAULT_CREDENTIALS_FILE = Path("project_config.json")


class AWSCredentials:
    """
    AWS credentials container.

    Loads credentials from JSON file with fallback to environment variables.
    """

    def __init__(
        self,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        region: Optional[str] = None,
        kms_config: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize AWS credentials.

        Args:
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            region: AWS region
            kms_config: KMS key IDs configuration (oem_root_key_id, bootloader_key_id, customer_key_id)
        """
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.kms_config = kms_config or {}

    def to_dict(self) -> Dict[str, Optional[str]]:
        """
        Convert credentials to dictionary format.

        Returns:
            Dictionary with aws_access_key_id, aws_secret_access_key, aws_region
        """
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_region": self.region,
        }

    def is_complete(self) -> bool:
        """
        Check if credentials are complete.

        Returns:
            True if both access_key_id and secret_access_key are set
        """
        return bool(self.access_key_id and self.secret_access_key)


def load_aws_credentials(
    credentials_file: Optional[Path] = None,
    fallback_to_env: bool = True,
) -> AWSCredentials:
    """
    Load AWS credentials from JSON file.

    Priority order:
    1. JSON file (if provided and exists)
    2. Environment variables (if fallback_to_env is True)
    3. Default credentials file (aws_credentials.json in current directory)

    Args:
        credentials_file: Path to credentials JSON file (optional)
        fallback_to_env: If True, fall back to environment variables if file not found

    Returns:
        AWSCredentials object with loaded credentials

    Raises:
        ConfigurationError: If credentials cannot be loaded and fallback is disabled
    """
    credentials = AWSCredentials()

    # Try to load from provided file
    if credentials_file and credentials_file.exists():
        try:
            logger.info(f"Loading AWS credentials from {credentials_file}")
            with open(credentials_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support both old format (flat) and new format (nested with "aws" key)
            if "aws" in data:
                aws_data = data["aws"]
                credentials.access_key_id = aws_data.get("access_key_id") or aws_data.get("aws_access_key_id")
                credentials.secret_access_key = aws_data.get("secret_access_key") or aws_data.get("aws_secret_access_key")
                credentials.region = aws_data.get("region") or aws_data.get("aws_region", "eu-central-1")
                # Load KMS configuration if present
                if "kms" in aws_data:
                    credentials.kms_config = aws_data["kms"]
            else:
                # Old format (flat structure)
                credentials.access_key_id = data.get("access_key_id") or data.get("aws_access_key_id")
                credentials.secret_access_key = data.get("secret_access_key") or data.get("aws_secret_access_key")
                credentials.region = data.get("region") or data.get("aws_region", "eu-central-1")

            if credentials.is_complete():
                logger.info("AWS credentials loaded from file")
                return credentials
            else:
                logger.warning("Incomplete credentials in file, falling back to environment variables")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in credentials file: {str(e)}")
            if not fallback_to_env:
                raise ConfigurationError(f"Invalid JSON in credentials file: {str(e)}") from e
        except Exception as e:
            logger.error(f"Error loading credentials file: {str(e)}")
            if not fallback_to_env:
                raise ConfigurationError(f"Error loading credentials file: {str(e)}") from e

    # Try default credentials file
    if not credentials.is_complete() and DEFAULT_CREDENTIALS_FILE.exists():
        try:
            logger.info(f"Loading AWS credentials from default file: {DEFAULT_CREDENTIALS_FILE}")
            with open(DEFAULT_CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support both old format (flat) and new format (nested with "aws" key)
            if "aws" in data:
                aws_data = data["aws"]
                credentials.access_key_id = aws_data.get("access_key_id") or aws_data.get("aws_access_key_id")
                credentials.secret_access_key = aws_data.get("secret_access_key") or aws_data.get("aws_secret_access_key")
                credentials.region = aws_data.get("region") or aws_data.get("aws_region", "eu-central-1")
                # Load KMS configuration if present
                if "kms" in aws_data:
                    credentials.kms_config = aws_data["kms"]
            else:
                # Old format (flat structure)
                credentials.access_key_id = data.get("access_key_id") or data.get("aws_access_key_id")
                credentials.secret_access_key = data.get("secret_access_key") or data.get("aws_secret_access_key")
                credentials.region = data.get("region") or data.get("aws_region", "eu-central-1")

            if credentials.is_complete():
                logger.info("AWS credentials loaded from default file")
                return credentials

        except Exception as e:
            logger.warning(f"Could not load default credentials file: {str(e)}")

    # Fall back to environment variables
    if fallback_to_env:
        logger.info("Loading AWS credentials from environment variables")
        credentials.access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        credentials.secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        credentials.region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION", "eu-central-1")

        if credentials.is_complete():
            logger.info("AWS credentials loaded from environment variables")
            return credentials

    # No credentials found
    if not credentials.is_complete():
        error_msg = (
            "AWS credentials not found. "
            "Please provide credentials via:\n"
            "1. JSON file: project_config.json\n"
            "2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n"
            "3. AWS CLI configuration: aws configure"
        )
        logger.error(error_msg)
        raise ConfigurationError(error_msg)

    return credentials


def get_aws_credentials(
    credentials_file: Optional[Path] = None,
    fallback_to_env: bool = True,
) -> Dict[str, Optional[str]]:
    """
    Get AWS credentials as dictionary.

    Convenience function that returns credentials in the format expected by boto3.

    Args:
        credentials_file: Path to credentials JSON file (optional)
        fallback_to_env: If True, fall back to environment variables

    Returns:
        Dictionary with aws_access_key_id, aws_secret_access_key, aws_region
    """
    credentials = load_aws_credentials(credentials_file, fallback_to_env)
    return credentials.to_dict()



