"""
Test imgtool integration.

This script demonstrates how to test imgtool with a test binary file.
Uses imgtool_runner which runs imgtool directly from imgtool/ folder.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware.imgtool_runner import sign_image, verify_image
from security.key_utils import generate_local_key_pair
from models.keys import KeyType, KeyCurve
from utils.exceptions import FirmwareError

def create_test_binary(output_path: Path, size_kb: int = 64) -> None:
    """Create a simple test binary file."""
    size_bytes = size_kb * 1024
    data = bytearray()
    for i in range(size_bytes):
        data.append(i % 256)
    output_path.write_bytes(data)
    print(f"[+] Created test binary: {output_path} ({size_bytes} bytes)")

def main():
    """Test imgtool with a generated binary."""
    print("=" * 70)
    print("Testing imgtool Integration (using imgtool_runner)")
    print("=" * 70)
    print()

    # Step 1: Create test binary
    print("[1/4] Creating test binary file...")
    test_binary = Path("test_app.bin")
    create_test_binary(test_binary, size_kb=64)
    print()

    # Step 2: Generate test key (local, for testing)
    print("[2/4] Generating test signing key...")
    try:
        key_pair, private_key_path, public_key_path = generate_local_key_pair(
            KeyType.CUSTOMER,
            KeyCurve.SECP256R1,
            output_dir=Path(".")
        )
        print(f"[+] Generated key pair:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key: {public_key_path}")
        print()
    except Exception as e:
        print(f" Failed to generate key: {e}")
        print("\nYou can use an existing key instead:")
        print("  python -m provisioning_tool.cli key generate-local --type customer")
        return 1

    # Step 3: Sign the binary
    print("[3/4] Signing firmware with imgtool...")
    signed_binary = Path("test_app.signed.bin")
    try:
        sign_image(
            input_file=test_binary,
            output_file=signed_binary,
            key_file=private_key_path,
            header_size=0x200,
            align=128,
            max_align=128,
            slot_size=0x20000,
            max_sectors=4,
            version="1.0.0",
            pad_header=True,
            confirm=True,
        )
        print(f"[+] Firmware signed successfully: {signed_binary}")
        print(f"  Original size: {test_binary.stat().st_size} bytes")
        print(f"  Signed size: {signed_binary.stat().st_size} bytes")
        print()
    except FirmwareError as e:
        print(f" Signing failed: {e}")
        return 1
    except Exception as e:
        print(f" Unexpected error: {e}")
        return 1

    # Step 4: Verify the signed binary
    print("[4/4] Verifying signed firmware...")
    try:
        is_valid = verify_image(signed_binary, public_key_path)
        if is_valid:
            print("[+] Verification passed! Signed firmware is valid.")
        else:
            print("[-] Verification failed!")
            return 1
        print()
    except FirmwareError as e:
        print(f" Verification failed: {e}")
        return 1
    except Exception as e:
        print(f" Unexpected error: {e}")
        return 1

    print("=" * 70)
    print("SUCCESS! imgtool test completed successfully.")
    print("=" * 70)
    print()
    print("Files created:")
    print(f"  - Test binary: {test_binary}")
    print(f"  - Signed binary: {signed_binary}")
    print(f"  - Private key: {private_key_path}")
    print(f"  - Public key: {public_key_path}")
    print()
    print("You can also test via CLI:")
    print(f"  python -m provisioning_tool.cli firmware sign {test_binary} --key {private_key_path}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
