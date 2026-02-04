"""Test delete key permission."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from security.hsm.aws_kms import AWSKMSClient
from utils.aws_credentials import get_aws_credentials

# Use a test key ID (you can change this to a key you want to test deletion on)
# NOTE: This will schedule the key for deletion! Use with caution!
test_key_id = None  # Set to a key ID if you want to test deletion

config = {
    "aws_region": "eu-central-1",
    "key_prefix": "RA8M1_",
}
aws_creds = get_aws_credentials(fallback_to_env=True)
config.update(aws_creds)

try:
    kms = AWSKMSClient(config)
    kms.connect()

    print("=" * 70)
    print("Testing kms:ScheduleKeyDeletion Permission")
    print("=" * 70)
    print()

    if not test_key_id:
        print("No test key ID specified.")
        print("To test deletion, set 'test_key_id' in this script.")
        print()
        print("Available keys:")
        try:
            keys = kms.list_keys()
            for i, key_metadata in enumerate(keys[:5], 1):  # Show first 5
                key_id = key_metadata.get('KeyId')
                key_spec = key_metadata.get('KeySpec', 'Unknown')
                state = key_metadata.get('KeyState', 'Unknown')
                print(f"{i}. Key ID: {key_id}")
                print(f"   Key Spec: {key_spec}")
                print(f"   State: {state}")
                print()
        except Exception as e:
            print(f"Error listing keys: {e}")
    else:
        print(f"Testing deletion for key: {test_key_id}")
        print()
        
        # First check key status
        try:
            status = kms.get_key_status(test_key_id)
            print(f"Current key status:")
            print(f"  Key Spec: {status.get('key_spec', 'Unknown')}")
            print(f"  State: {status.get('state', 'Unknown')}")
            print()
        except Exception as e:
            print(f"Error getting key status: {e}")
            kms.disconnect()
            sys.exit(1)

        # Test deletion (with 7 days pending window)
        print("Attempting to schedule key for deletion (7 days pending window)...")
        try:
            kms.delete_key(test_key_id, pending_days=7)
            print("[+] SUCCESS! Key scheduled for deletion")
            print()
            print("The key will be permanently deleted after 7 days.")
            print("You can cancel the deletion using cancel_key_deletion() if needed.")
        except Exception as e:
            error_msg = str(e)
            print(f" FAILED: {error_msg}")
            print()
            
            if "AccessDeniedException" in error_msg:
                print("=" * 70)
                print("MISSING PERMISSION: kms:ScheduleKeyDeletion")
                print("=" * 70)
                print()
                print("Your AWS IAM user/role needs the following permission:")
                print()
                print("  {")
                print('    "Effect": "Allow",')
                print('    "Action": [')
                print('      "kms:ScheduleKeyDeletion"')
                print('    ],')
                print('    "Resource": "*"')
                print("  }")
            elif "KMSInvalidStateException" in error_msg:
                print("Key is already scheduled for deletion or in invalid state.")
            else:
                print(f"Unexpected error: {error_msg}")

    kms.disconnect()

except Exception as e:
    print(f"Error: {e}")



