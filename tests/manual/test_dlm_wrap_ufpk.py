"""
Test DLM UFPK wrapping functionality with actual upload.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.loader import ConfigLoader
from security.dlm.client import DLMClient
from utils.dlm_credentials import load_dlm_credentials
from utils.exceptions import DLMError
from utils.logging import get_logger

logger = get_logger(__name__)


def test_dlm_wrap_ufpk():
    """Test DLM UFPK wrapping."""
    print("\n" + "="*60)
    print("Testing DLM UFPK Wrapping")
    print("="*60 + "\n")
    
    # Load config
    try:
        config_loader = ConfigLoader()
        config = config_loader.load()
    except Exception as e:
        print(f"[ERROR] Error loading config: {e}")
        return False
    
    # Load DLM credentials
    credentials_file = Path(__file__).parent.parent / "aws_credentials.json"
    try:
        dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
        config.dlm.username = dlm_creds.username or dlm_creds.email
        config.dlm.password = dlm_creds.password
        # Use session cookie if available, otherwise will login automatically
        config.dlm.session_cookie = dlm_creds.session_cookie
        if not config.dlm.server_url:
            config.dlm.server_url = "https://dlm.renesas.com"
        print(f"[+] Loaded DLM credentials for: {config.dlm.username}")
        print(f"[+] DLM server URL: {config.dlm.server_url}")
        if config.dlm.session_cookie and len(config.dlm.session_cookie) > 20:
            print(f"[+] DLM session cookie found (will use for authentication)")
        else:
            print(f"ℹ  No valid DLM session cookie - will login automatically")
    except Exception as e:
        print(f"[ERROR] Error loading DLM credentials: {e}")
        return False
    
    # Check encrypted UFPK file
    encrypted_ufpk = Path("test_ufpk_encrypted.pgp")
    if not encrypted_ufpk.exists():
        print(f"[ERROR] Encrypted UFPK file not found: {encrypted_ufpk}")
        print("   Please run 'prepare_dlm_upload.py' first to generate it.")
        return False
    
    print(f"[+] Found encrypted UFPK: {encrypted_ufpk}")
    
    # Test DLM wrapping
    try:
        dlm_client = DLMClient(config.dlm)
        
        print("\nTesting DLM connection...")
        if not dlm_client.test_connection():
            print("[ERROR] DLM connection test failed")
            return False
        print("[+] DLM connection successful")
        
        print("\nUploading encrypted UFPK to DLM...")
        job_id = dlm_client.wrap_ufpk(encrypted_ufpk)
        
        print(f"\n[OK] UFPK upload successful!")
        print(f"   Request ID: {job_id}")
        print(f"\n[EMAIL] Next steps:")
        print(f"   1. Check your email ({config.dlm.username})")
        print(f"   2. Download the encrypted key data attachment")
        print(f"   3. Decrypt it with your private key:")
        print(f"      gpg --decrypt <attachment> --output wrapped_ufpk.key")
        print(f"   4. Use wrapped_ufpk.key for RKEY generation")
        
        return True
        
    except DLMError as e:
        print(f"\n[ERROR] DLM Error: {str(e)}")
        return False
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'dlm_client' in locals():
            dlm_client.close()


if __name__ == "__main__":
    success = test_dlm_wrap_ufpk()
    sys.exit(0 if success else 1)

