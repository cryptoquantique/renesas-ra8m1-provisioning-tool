"""
Test DLM connection with username/password.

This script tests the DLM server connection using username/password authentication.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import DLMConfig
from security.dlm.client import DLMClient
from utils.exceptions import DLMError
from utils.logging import get_logger

logger = get_logger(__name__)


def test_dlm_connection(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Test DLM server connection.
    
    Args:
        username: DLM username
        password: DLM password
        server_url: DLM server URL (default: https://dlm.renesas.com)
    """
    print(f"\n{'='*60}")
    print("Testing DLM Server Connection")
    print(f"{'='*60}\n")
    
    print(f"Server URL: {server_url}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)}\n")
    
    # Create DLM config
    config = DLMConfig(
        server_url=server_url,
        username=username,
        password=password,
        timeout=30.0,
        verify_ssl=True,
    )
    
    try:
        print("Creating DLM client...")
        # Don't auto-connect, we'll test manually
        client = DLMClient(config, auto_connect=False)
        
        print("Testing connection...")
        is_connected = client.test_connection()
        
        if is_connected:
            print("\n[+] Connection successful!")
            print("DLM server is reachable and credentials are valid.")
        else:
            print("\n[WARN] Connection test completed, but status is uncertain.")
            print("Server may be reachable, but health endpoint might not be available.")
        
        # Try to access a simple endpoint
        print("\nTrying to access DLM endpoints...")
        test_urls = [
            f"{server_url}/api/v1/health",
            f"{server_url}/api/health",
            f"{server_url}/health",
            f"{server_url}/api/v1",
            f"{server_url}/",
        ]
        
        for url in test_urls:
            try:
                response = client.session.get(url, timeout=5.0)
                print(f"  {url}: Status {response.status_code}")
                if response.status_code == 200:
                    print(f"    Response: {response.text[:200]}")
            except Exception as e:
                print(f"  {url}: Error - {str(e)[:100]}")
        
        client.close()
        print("\n[+] Test completed successfully!")
        return True
        
    except DLMError as e:
        print(f"\n DLM Error: {str(e)}")
        return False
    except Exception as e:
        print(f"\n Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Try to load from JSON file first
    credentials_file = Path(__file__).parent.parent / "aws_credentials.json"
    username = None
    password = None
    server_url = "https://dlm.renesas.com"
    
    if credentials_file.exists():
        try:
            from utils.dlm_credentials import load_dlm_credentials
            dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
            username = dlm_creds.username or dlm_creds.email
            password = dlm_creds.password
            print(f"Loaded DLM credentials from {credentials_file}")
        except Exception as e:
            print(f"Could not load from JSON file: {e}")
    
    # Override with command line arguments if provided
    if len(sys.argv) >= 3:
        username = sys.argv[1]
        password = sys.argv[2]
        if len(sys.argv) > 3:
            server_url = sys.argv[3]
    elif not username or not password:
        print("Usage: python test_dlm_connection.py [username] [password] [server_url]")
        print("\nIf username/password not provided, will try to load from aws_credentials.json")
        print("\nExample:")
        print("  python test_dlm_connection.py")
        print("  python test_dlm_connection.py myuser mypass")
        print("  python test_dlm_connection.py myuser mypass https://dlm.renesas.com")
        sys.exit(1)
    
    success = test_dlm_connection(username, password, server_url)
    sys.exit(0 if success else 1)

