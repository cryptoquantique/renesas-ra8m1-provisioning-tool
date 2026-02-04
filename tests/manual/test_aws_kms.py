"""
AWS KMS Integration Test

Tests AWS KMS functionality with an existing key.
Verifies connection, signing, verification, and key operations.

Run: python test_aws_kms.py
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from security.hsm.aws_kms import AWSKMSClient
from utils.aws_credentials import get_aws_credentials
from utils.exceptions import HSMError
from utils.logging import get_logger

logger = get_logger(__name__)


class AWSKMSTest:
    """
    AWS KMS integration test suite.

    Tests all AWS KMS operations including connection, key operations,
    signing, verification, and hashing.
    """

    def __init__(self, key_id: str, region: str = "eu-central-1"):
        """
        Initialize test suite.

        Args:
            key_id: Existing KMS key ID to use for testing
            region: AWS region
        """
        self.key_id = key_id
        self.region = region
        self.kms_client: Optional[AWSKMSClient] = None
        self.test_results = {
            "connection": False,
            "get_public_key": False,
            "signing": False,
            "verification": False,
            "hashing": False,
            "key_status": False,
        }

    def setup(self) -> bool:
        """
        Setup test environment and connect to AWS KMS.

        Returns:
            True if setup successful, False otherwise
        """
        print("=" * 70)
        print("AWS KMS Integration Test")
        print("=" * 70)
        print()

        try:
            print("[1/6] Initializing AWS KMS client...")
            config = {
                "aws_region": self.region,
                "key_prefix": "RA8M1_TEST_",
            }

            aws_creds = get_aws_credentials(fallback_to_env=True)
            config.update(aws_creds)

            self.kms_client = AWSKMSClient(config)
            print("    [+] Client initialized")

            print("[2/6] Connecting to AWS KMS...")
            self.kms_client.connect()
            self.test_results["connection"] = True
            print("    [+] Connected successfully")
            print()

            return True

        except Exception as e:
            print(f"     Setup failed: {str(e)}")
            return False

    def test_get_public_key(self) -> bool:
        """
        Test retrieving public key from KMS.

        Returns:
            True if test passed, False otherwise
        """
        print("[3/6] Testing Get Public Key...")
        try:
            public_key = self.kms_client.get_public_key(self.key_id)
            self.test_results["get_public_key"] = True
            print(f"    [+] Retrieved public key: {len(public_key)} bytes")
            print()
            return True
        except Exception as e:
            print(f"     Failed: {str(e)}")
            print()
            return False

    def test_signing(self) -> tuple[bool, Optional[bytes], Optional[bytes]]:
        """
        Test signing data with KMS key.

        Returns:
            Tuple of (success, test_data, signature)
        """
        print("[4/6] Testing Signing Operation...")
        try:
            test_data = b"Hello AWS KMS! Test signing operation."
            signature = self.kms_client.sign_data(self.key_id, test_data)
            self.test_results["signing"] = True
            print(f"    [+] Signed data: {len(signature)} bytes")
            print()
            return True, test_data, signature
        except Exception as e:
            print(f"     Failed: {str(e)}")
            print()
            return False, None, None

    def test_verification(self, public_key: bytes, test_data: bytes, signature: bytes) -> bool:
        """
        Test signature verification.

        Args:
            public_key: Public key bytes
            test_data: Original test data
            signature: Signature to verify

        Returns:
            True if verification passed, False otherwise
        """
        print("[5/6] Testing Signature Verification...")
        try:
            is_valid = self.kms_client.verify_signature(
                public_key, test_data, signature, self.key_id
            )
            if is_valid:
                self.test_results["verification"] = True
                print("    [+] Verification: VALID")
            else:
                print("     Verification: INVALID")
            print()
            return is_valid
        except Exception as e:
            print(f"     Failed: {str(e)}")
            print()
            return False

    def test_hashing(self) -> bool:
        """
        Test hash computation.

        Returns:
            True if test passed, False otherwise
        """
        print("[6/6] Testing Hash Computation...")
        try:
            test_data = b"Hello AWS KMS! Test signing operation."
            hash_result = self.kms_client.hash_data(test_data, "SHA256")
            self.test_results["hashing"] = True
            print(f"    [+] Hash computed: {len(hash_result)} bytes")
            print(f"    [+] Hash (hex): {hash_result.hex()[:32]}...")
            print()
            return True
        except Exception as e:
            print(f"     Failed: {str(e)}")
            print()
            return False

    def test_key_status(self) -> bool:
        """
        Test retrieving key status information.

        Returns:
            True if test passed, False otherwise
        """
        print("[7/7] Testing Key Status Retrieval...")
        try:
            status = self.kms_client.get_key_status(self.key_id)
            self.test_results["key_status"] = True

            print("    [+] Key Status Information:")
            print(f"       State: {status.get('state', 'N/A')}")
            print(f"       Key Spec: {status.get('key_spec', 'N/A')}")
            print(f"       Key Usage: {status.get('key_usage', 'N/A')}")

            if 'aliases' in status and status['aliases']:
                print(f"       Aliases: {', '.join(status['aliases'])}")

            print()
            return True
        except Exception as e:
            print(f"     Failed: {str(e)}")
            print()
            return False

    def cleanup(self) -> None:
        """Cleanup test resources."""
        if self.kms_client:
            try:
                self.kms_client.disconnect()
            except Exception:
                pass

    def print_summary(self) -> None:
        """Print test summary."""
        print("=" * 70)
        print("Test Summary")
        print("=" * 70)
        print()

        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)

        for test_name, result in self.test_results.items():
            status = "[+] PASS" if result else " FAIL"
            print(f"  {test_name.replace('_', ' ').title():.<50} {status}")

        print()
        print(f"Results: {passed_tests}/{total_tests} tests passed")
        print()

        if passed_tests == total_tests:
            print("=" * 70)
            print("SUCCESS! All AWS KMS operations working correctly.")
            print("=" * 70)
        else:
            print("=" * 70)
            print("PARTIAL SUCCESS. Some operations failed.")
            print("=" * 70)

        print()

    def run_all_tests(self) -> int:
        """
        Run all tests in sequence.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            if not self.setup():
                return 1

            print(f"Using test key: {self.key_id}")
            print()

            if not self.test_get_public_key():
                self.print_summary()
                return 1

            public_key = self.kms_client.get_public_key(self.key_id)

            success, test_data, signature = self.test_signing()
            if not success:
                self.print_summary()
                return 1

            if not self.test_verification(public_key, test_data, signature):
                self.print_summary()
                return 1

            if not self.test_hashing():
                self.print_summary()
                return 1

            if not self.test_key_status():
                self.print_summary()
                return 1

            self.print_summary()
            return 0

        except Exception as e:
            print()
            print("=" * 70)
            print("ERROR!")
            print("=" * 70)
            print(f"Unexpected error: {str(e)}")
            print()
            self._print_troubleshooting()
            logger.exception("Test execution failed")
            return 1
        finally:
            self.cleanup()

    def _print_troubleshooting(self) -> None:
        """Print troubleshooting information."""
        print("Troubleshooting:")
        print("1. Verify credentials in aws_credentials.json or environment variables")
        print("2. Check key ID exists: f43f3ec3-6056-4a5d-b23a-1f4a94b7a69b")
        print("3. Verify you have permissions:")
        print("   - kms:GetPublicKey")
        print("   - kms:Sign")
        print("   - kms:Verify")
        print("   - kms:DescribeKey")
        print()


def main() -> int:
    """Main test function."""
    test_key_id = "f43f3ec3-6056-4a5d-b23a-1f4a94b7a69b"
    test_region = "eu-central-1"

    test_suite = AWSKMSTest(test_key_id, test_region)
    return test_suite.run_all_tests()


if __name__ == "__main__":
    sys.exit(main())
