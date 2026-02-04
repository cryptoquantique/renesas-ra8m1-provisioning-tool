"""Test ListKeys permission."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from security.hsm.aws_kms import AWSKMSClient
from utils.aws_credentials import get_aws_credentials

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
    print("Testing kms:ListKeys Permission")
    print("=" * 70)
    print()

    print("Attempting to list keys...")
    try:
        keys = kms.list_keys()
        print(f"[+] SUCCESS! Found {len(keys)} key(s) in AWS KMS")
        print()
        for i, key_metadata in enumerate(keys, 1):
            key_id = key_metadata.get('KeyId')
            aliases = key_metadata.get('AliasNames', [])
            key_spec = key_metadata.get('KeySpec', 'Unknown')
            state = key_metadata.get('KeyState', 'Unknown')
            
            print(f"{i}. Key ID: {key_id}")
            if aliases:
                print(f"   Aliases: {', '.join(aliases)}")
            print(f"   Key Spec: {key_spec}")
            print(f"   State: {state}")
            print()
    except Exception as e:
        error_msg = str(e)
        print(f" FAILED: {error_msg}")
        print()
        
        if "AccessDeniedException" in error_msg:
            print("=" * 70)
            print("MISSING PERMISSION: kms:ListKeys")
            print("=" * 70)
            print()
            print("Your AWS IAM user/role needs the following permission:")
            print()
            print("  {")
            print('    "Effect": "Allow",')
            print('    "Action": [')
            print('      "kms:ListKeys"')
            print('    ],')
            print('    "Resource": "*"')
            print("  }")
            print()
            print("Or for specific keys:")
            print()
            print("  {")
            print('    "Effect": "Allow",')
            print('    "Action": [')
            print('      "kms:ListKeys"')
            print('    ],')
            print('    "Resource": "arn:aws:kms:eu-central-1:357288438654:key/*"')
            print("  }")
            print()
            print("To add this permission:")
            print("1. Go to AWS IAM Console")
            print("2. Find your user/role: cq-kms-service-account")
            print("3. Add the permission to the policy")
            print("4. Wait a few seconds for the change to propagate")
        elif "ListAliases" in error_msg:
            print("Also missing: kms:ListAliases permission")
            print("Add both kms:ListKeys and kms:ListAliases to your IAM policy")

    kms.disconnect()

except Exception as e:
    print(f"Error: {e}")



