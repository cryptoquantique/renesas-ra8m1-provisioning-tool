"""
Quick SKMT test script.
Run this to quickly verify SKMT is working.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.loader import ConfigLoader
from security.skmt.wrapper import SKMTWrapper

def main():
    print("=" * 60)
    print("Quick SKMT Test")
    print("=" * 60)
    print()
    
    # Load config
    loader = ConfigLoader()
    config = loader.load()
    
    if not config.skmt.skmt_path:
        print(" SKMT path not configured!")
        print("  Please configure SKMT path in config.yaml or environment")
        return 1
    
    skmt_path = Path(config.skmt.skmt_path)
    if not skmt_path.exists():
        print(f" SKMT not found at: {config.skmt.skmt_path}")
        return 1
    
    print(f"[+] SKMT found: {config.skmt.skmt_path}")
    print()
    
    # Initialize wrapper
    try:
        wrapper = SKMTWrapper(
            skmt_path=config.skmt.skmt_path,
            working_directory=config.skmt.working_directory,
        )
        print("[+] SKMT wrapper initialized")
    except Exception as e:
        print(f" Failed to initialize wrapper: {e}")
        return 1
    
    # Test UFPK generation
    print("\nTesting UFPK generation...")
    try:
        work_dir = Path(config.skmt.working_directory)
        work_dir.mkdir(parents=True, exist_ok=True)
        ufpk_file = work_dir / "quick_test_ufpk.key"
        
        result = wrapper.generate_ufpk(output_file=str(ufpk_file))
        if result.exists():
            print(f"[+] UFPK generated: {result}")
        else:
            print(f" UFPK file not created")
            return 1
    except Exception as e:
        print(f" UFPK generation failed: {e}")
        return 1
    
    # Test KUK generation
    print("\nTesting KUK generation...")
    try:
        kuk_file = work_dir / "quick_test_kuk.key"
        result = wrapper.generate_kuk(output_file=str(kuk_file))
        if result.exists():
            print(f"[+] KUK generated: {result}")
        else:
            print(f" KUK file not created")
            return 1
    except Exception as e:
        print(f" KUK generation failed: {e}")
        return 1
    
    print("\n" + "=" * 60)
    print("[+] All SKMT tests passed!")
    print("=" * 60)
    print("\nSKMT is working correctly. You can now use the CLI workflow commands.")
    print("  - Example: invoke prepare-ufpk, generate-rkey, gen-fsbl-certs, program-device")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

