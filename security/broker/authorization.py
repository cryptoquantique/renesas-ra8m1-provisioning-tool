"""
Authorization manager for the crypto broker service.

This module provides policy-based authorization for broker clients,
controlling which operations and keys each client can access.
"""

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

from security.broker.auth import ClientIdentity
from security.broker.exceptions import AuthorizationError
from utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ClientPolicy:
    """
    Authorization policy for a client.

    Attributes:
        client_id: Client identifier (UID for Linux, SID for Windows)
        platform: Target platform ("linux" or "windows")
        allowed_operations: Set of allowed operation names
        allowed_key_arns: List of allowed key ARN patterns (supports wildcards)
        denied_key_arns: List of explicitly denied key ARN patterns
        max_requests_per_minute: Rate limit (0 for unlimited)
        description: Human-readable policy description
    """

    client_id: str
    platform: str = "linux"
    allowed_operations: Set[str] = field(default_factory=set)
    allowed_key_arns: List[str] = field(default_factory=list)
    denied_key_arns: List[str] = field(default_factory=list)
    max_requests_per_minute: int = 0
    description: str = ""

    def allows_operation(self, operation: str) -> bool:
        """
        Check if operation is allowed by this policy.

        Args:
            operation: Operation name to check

        Returns:
            True if operation is allowed
        """
        if not self.allowed_operations:
            return True  # No restriction = all allowed
        return operation in self.allowed_operations

    def allows_key(self, key_arn: str) -> bool:
        """
        Check if key ARN is allowed by this policy.

        Args:
            key_arn: Key ARN to check

        Returns:
            True if key is allowed
        """
        # Check explicit denials first
        for pattern in self.denied_key_arns:
            if self._matches_arn_pattern(key_arn, pattern):
                return False

        # If no allowed patterns, all keys allowed (subject to denials)
        if not self.allowed_key_arns:
            return True

        # Check against allowed patterns
        for pattern in self.allowed_key_arns:
            if self._matches_arn_pattern(key_arn, pattern):
                return True

        return False

    @staticmethod
    def _matches_arn_pattern(arn: str, pattern: str) -> bool:
        """
        Check if ARN matches pattern with wildcard support.

        Supports:
        - * matches any sequence of characters
        - ? matches any single character
        - ARN components can use wildcards individually

        Args:
            arn: Key ARN to match
            pattern: Pattern with optional wildcards

        Returns:
            True if ARN matches pattern
        """
        # Convert glob-style pattern to regex
        regex_pattern = fnmatch.translate(pattern)
        return bool(re.match(regex_pattern, arn, re.IGNORECASE))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClientPolicy":
        """
        Create policy from dictionary.

        Args:
            data: Policy dictionary

        Returns:
            ClientPolicy instance
        """
        return cls(
            client_id=str(data["client_id"]),
            platform=data.get("platform", "linux"),
            allowed_operations=set(data.get("allowed_operations", [])),
            allowed_key_arns=data.get("allowed_key_arns", []),
            denied_key_arns=data.get("denied_key_arns", []),
            max_requests_per_minute=data.get("max_requests_per_minute", 0),
            description=data.get("description", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return {
            "client_id": self.client_id,
            "platform": self.platform,
            "allowed_operations": list(self.allowed_operations),
            "allowed_key_arns": self.allowed_key_arns,
            "denied_key_arns": self.denied_key_arns,
            "max_requests_per_minute": self.max_requests_per_minute,
            "description": self.description,
        }


class AuthorizationManager:
    """
    Manages authorization policies for broker clients.

    Loads policies from a configuration file and enforces
    access control for operations and keys.
    """

    def __init__(self, policies_file: Optional[str] = None):
        """
        Initialize authorization manager.

        Args:
            policies_file: Path to JSON policies file
        """
        self._policies: Dict[str, ClientPolicy] = {}
        self._default_policy: Optional[ClientPolicy] = None
        self._policies_file = policies_file

        if policies_file:
            self.load_policies(policies_file)

    def load_policies(self, policies_file: str) -> None:
        """
        Load policies from JSON file.

        Args:
            policies_file: Path to policies JSON file

        Raises:
            BrokerError: If file cannot be loaded
        """
        path = Path(policies_file)
        if not path.exists():
            logger.warning(f"Policies file not found: {policies_file}")
            return

        try:
            with open(path, "r") as f:
                data = json.load(f)

            # Load individual policies
            for policy_data in data.get("policies", []):
                policy = ClientPolicy.from_dict(policy_data)
                key = f"{policy.platform}:{policy.client_id}"
                self._policies[key] = policy
                logger.debug(f"Loaded policy for {key}: {policy.description}")

            # Load default policy if present
            if "default_policy" in data:
                self._default_policy = ClientPolicy.from_dict(data["default_policy"])
                logger.debug("Loaded default policy")

            logger.info(f"Loaded {len(self._policies)} policies from {policies_file}")

        except Exception as e:
            logger.error(f"Failed to load policies from {policies_file}: {e}")
            raise

    def save_policies(self, policies_file: Optional[str] = None) -> None:
        """
        Save policies to JSON file.

        Args:
            policies_file: Path to save to (uses loaded file if not specified)
        """
        path = Path(policies_file or self._policies_file)

        data = {
            "policies": [p.to_dict() for p in self._policies.values()],
        }
        if self._default_policy:
            data["default_policy"] = self._default_policy.to_dict()

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(self._policies)} policies to {path}")

    def get_policy(self, client_identity: ClientIdentity) -> Optional[ClientPolicy]:
        """
        Get policy for a client.

        Matching order:
        1. Exact match on platform + client_id
        2. Wildcard pattern match on client_id (fnmatch syntax, e.g. "S-1-5-*")
        3. Default policy

        Args:
            client_identity: Client identity

        Returns:
            ClientPolicy or None if no policy found
        """
        key = f"{client_identity.platform}:{client_identity.client_id}"
        policy = self._policies.get(key)
        if policy:
            return policy

        for stored_key, stored_policy in self._policies.items():
            parts = stored_key.split(":", 1)
            if len(parts) != 2:
                continue
            stored_platform, stored_pattern = parts
            if stored_platform != client_identity.platform:
                continue

            if stored_pattern == client_identity.client_id:
                continue
            if fnmatch.fnmatch(client_identity.client_id, stored_pattern):
                logger.debug(
                    f"Client {client_identity.client_id} matched "
                    f"wildcard policy '{stored_pattern}'"
                )
                return stored_policy

        return self._default_policy

    def add_policy(self, policy: ClientPolicy) -> None:
        """
        Add or update a policy.

        Args:
            policy: Policy to add
        """
        key = f"{policy.platform}:{policy.client_id}"
        self._policies[key] = policy
        logger.info(f"Added policy for {key}")

    def remove_policy(self, platform: str, client_id: str) -> bool:
        """
        Remove a policy.

        Args:
            platform: Client platform
            client_id: Client identifier

        Returns:
            True if policy was removed
        """
        key = f"{platform}:{client_id}"
        if key in self._policies:
            del self._policies[key]
            logger.info(f"Removed policy for {key}")
            return True
        return False

    def set_default_policy(self, policy: ClientPolicy) -> None:
        """
        Set the default policy for unregistered clients.

        Args:
            policy: Default policy
        """
        self._default_policy = policy
        logger.info("Set default policy")

    def check_client_allowed(self, client_identity: ClientIdentity) -> None:
        """
        Check if client is allowed to use the broker.

        Args:
            client_identity: Client identity

        Raises:
            AuthorizationError: If client is not allowed
        """
        policy = self.get_policy(client_identity)
        if policy is None:
            raise AuthorizationError(
                "No authorization policy found for client",
                client_id=client_identity.client_id,
            )

    def check_authorization(
        self,
        client_identity: ClientIdentity,
        operation: str,
        key_arn: Optional[str] = None,
    ) -> None:
        """
        Check if client is authorized for operation.

        Args:
            client_identity: Client identity
            operation: Operation name
            key_arn: Optional key ARN for key-specific operations

        Raises:
            AuthorizationError: If not authorized
        """
        policy = self.get_policy(client_identity)

        if policy is None:
            raise AuthorizationError(
                "No authorization policy found",
                client_id=client_identity.client_id,
                operation=operation,
                resource=key_arn,
            )

        # Check operation
        if not policy.allows_operation(operation):
            raise AuthorizationError(
                f"Operation '{operation}' not allowed",
                client_id=client_identity.client_id,
                operation=operation,
            )

        # Check key ARN if provided
        if key_arn and not policy.allows_key(key_arn):
            raise AuthorizationError(
                f"Access to key '{key_arn}' not allowed",
                client_id=client_identity.client_id,
                operation=operation,
                resource=key_arn,
            )

        logger.debug(
            f"Authorized: client={client_identity.client_id}, "
            f"op={operation}, key={key_arn}"
        )

    def list_policies(self) -> List[Dict[str, Any]]:
        """
        List all policies.

        Returns:
            List of policy dictionaries
        """
        return [p.to_dict() for p in self._policies.values()]


def create_default_policies_file(path: str) -> None:
    """
    Create a default policies file with example configuration.

    Args:
        path: File path to create
    """
    default_config = {
        "policies": [
            {
                "client_id": "1000",
                "platform": "linux",
                "allowed_operations": [
                    "sign",
                    "sign_digest",
                    "verify",
                    "get_public_key",
                    "hash",
                    "list_keys",
                ],
                "allowed_key_arns": [
                    "arn:aws:kms:*:*:key/*",
                    "alias/*",
                ],
                "denied_key_arns": [],
                "max_requests_per_minute": 0,
                "description": "Default user policy - full access",
            },
        ],
        "default_policy": {
            "client_id": "*",
            "platform": "linux",
            "allowed_operations": [
                "ping",
                "get_info",
                "initialize",
                "finalize",
                "open_session",
                "close_session",
            ],
            "allowed_key_arns": [],
            "denied_key_arns": ["*"],
            "description": "Default policy - session management only",
        },
    }

    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)

    with open(path_obj, "w") as f:
        json.dump(default_config, f, indent=2)

    logger.info(f"Created default policies file: {path}")
