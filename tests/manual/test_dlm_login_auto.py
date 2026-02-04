"""
Test DLM automatic login with correct endpoint and fields.
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


def test_dlm_auto_login():
    """Test DLM automatic login."""
    print("\n" + "="*60)
    print("Testing DLM Automatic Login")
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
        # Clear session cookie to force automatic login
        config.dlm.session_cookie = None
        if not config.dlm.server_url:
            config.dlm.server_url = "https://dlm.renesas.com"
        print(f"[+] Loaded DLM credentials for: {config.dlm.username}")
        print(f"[+] DLM server URL: {config.dlm.server_url}")
        print(f"[+] Session cookie cleared - will test automatic login")
    except Exception as e:
        print(f"[ERROR] Error loading DLM credentials: {e}")
        return False
    
    # Test DLM automatic login
    try:
        print("\nTesting DLM automatic login...")
        dlm_client = DLMClient(config.dlm, auto_connect=False)
        
        # Force login
        print("Attempting login...")
        dlm_client._login()
        
        # Check if we got JSESSIONID
        jsessionid = dlm_client.get_session_cookie()
        if jsessionid:
            print(f"\n[OK] Login successful!")
            print(f"   JSESSIONID: {jsessionid[:30]}...")
            print(f"   Cookie length: {len(jsessionid)} characters")
            
            # Test accessing protected page
            print("\nTesting access to protected page...")
            test_url = f"{config.dlm.server_url}/keywrap/menu/app/"
            test_response = dlm_client.session.post(
                test_url,
                data={'category': 'RA', 'prev': '/menu/select/'},
                timeout=config.dlm.timeout
            )
            
            if 'time out' not in test_response.text.lower():
                print("[OK] Can access protected pages - login verified!")
            else:
                print("[WARN]  Got timeout message - login may not be fully valid")
            
            return True
        else:
            print("[ERROR] Login failed - no JSESSIONID obtained")
            return False
        
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
    success = test_dlm_auto_login()
    sys.exit(0 if success else 1)


