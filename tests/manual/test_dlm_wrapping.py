"""
Test DLM UFPK wrapping functionality.

This script tests the complete DLM UFPK wrapping workflow.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import DLMConfig
from security.dlm.client import DLMClient
from utils.exceptions import DLMError
from utils.logging import get_logger
from utils.dlm_credentials import load_dlm_credentials

logger = get_logger(__name__)


def test_dlm_endpoints(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Test DLM server endpoints to see what's available.
    
    Args:
        username: DLM username
        password: DLM password
        server_url: DLM server URL
    """
    print(f"\n{'='*60}")
    print("Testing DLM Server Endpoints")
    print(f"{'='*60}\n")
    
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
        client = DLMClient(config, auto_connect=False)
        
        # Test various endpoints
        test_endpoints = [
            "/",
            "/api/v1",
            "/api/v1/health",
            "/api/health",
            "/health",
            "/api/v1/ufpk",
            "/api/v1/ufpk/wrap",
            "/keywrap",
            "/keywrap/doui",
            "/keywrap/doui/agree",
        ]
        
        print(f"\nTesting endpoints on {server_url}:\n")
        
        for endpoint in test_endpoints:
            url = f"{server_url}{endpoint}"
            try:
                response = client.session.get(url, timeout=5.0, allow_redirects=False)
                print(f"  {endpoint:30} -> Status {response.status_code}")
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type:
                        try:
                            data = response.json()
                            print(f"    Response: {str(data)[:200]}")
                        except:
                            print(f"    Response length: {len(response.content)} bytes")
                    elif 'html' in content_type:
                        print(f"    HTML page (length: {len(response.content)} bytes)")
                    else:
                        print(f"    Content-Type: {content_type}")
                elif response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', 'N/A')
                    print(f"    Redirects to: {location}")
                elif response.status_code == 401:
                    print(f"    Authentication required")
                elif response.status_code == 403:
                    print(f"    Access forbidden")
                elif response.status_code == 404:
                    print(f"    Not found")
                    
            except Exception as e:
                print(f"  {endpoint:30} -> Error: {str(e)[:80]}")
        
        # Try POST to wrap endpoint (without file, just to see response)
        print(f"\n\nTesting POST to /api/v1/ufpk/wrap (without file):")
        try:
            url = f"{server_url}/api/v1/ufpk/wrap"
            response = client.session.post(url, timeout=5.0)
            print(f"  Status: {response.status_code}")
            if response.status_code != 200:
                try:
                    error_data = response.json()
                    print(f"  Response: {error_data}")
                except:
                    print(f"  Response: {response.text[:200]}")
        except Exception as e:
            print(f"  Error: {str(e)[:200]}")
        
        client.close()
        print("\n[+] Endpoint testing completed!")
        return True
        
    except DLMError as e:
        print(f"\n DLM Error: {str(e)}")
        return False
    except Exception as e:
        print(f"\n Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_dlm_wrap_request(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Test DLM wrap request (without actual file, just to see API structure).
    
    Args:
        username: DLM username
        password: DLM password
        server_url: DLM server URL
    """
    print(f"\n{'='*60}")
    print("Testing DLM Wrap Request Structure")
    print(f"{'='*60}\n")
    
    config = DLMConfig(
        server_url=server_url,
        username=username,
        password=password,
        timeout=30.0,
        verify_ssl=True,
    )
    
    try:
        client = DLMClient(config, auto_connect=False)
        
        # Try different possible endpoints
        wrap_endpoints = [
            "/api/v1/ufpk/wrap",
            "/api/ufpk/wrap",
            "/keywrap/api/wrap",
            "/keywrap/doui/wrap",
        ]
        
        for endpoint in wrap_endpoints:
            url = f"{server_url}{endpoint}"
            print(f"\nTesting: {url}")
            
            # Try with minimal data
            try:
                # Try as form data
                response = client.session.post(
                    url,
                    data={"device_id": "test_device"},
                    timeout=5.0
                )
                print(f"  Status: {response.status_code}")
                if response.status_code != 200:
                    try:
                        error_data = response.json()
                        print(f"  Response: {error_data}")
                    except:
                        print(f"  Response: {response.text[:300]}")
                else:
                    print(f"  [+] Success! Response: {response.text[:300]}")
            except Exception as e:
                print(f"  Error: {str(e)[:150]}")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"\n Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Load credentials from JSON
    credentials_file = Path(__file__).parent.parent / "aws_credentials.json"
    username = None
    password = None
    server_url = "https://dlm.renesas.com"
    
    if credentials_file.exists():
        try:
            dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
            username = dlm_creds.username or dlm_creds.email
            password = dlm_creds.password
            print(f"Loaded DLM credentials from {credentials_file}")
        except Exception as e:
            print(f"Could not load from JSON file: {e}")
            sys.exit(1)
    else:
        print("Credentials file not found!")
        sys.exit(1)
    
    # Override with command line arguments if provided
    if len(sys.argv) >= 3:
        username = sys.argv[1]
        password = sys.argv[2]
        if len(sys.argv) > 3:
            server_url = sys.argv[3]
    
    print("\n" + "="*60)
    print("DLM Wrapping Functionality Test")
    print("="*60)
    
    # Test 1: Endpoint discovery
    print("\n[TEST 1] Endpoint Discovery")
    test_dlm_endpoints(username, password, server_url)
    
    # Test 2: Wrap request structure
    print("\n\n[TEST 2] Wrap Request Structure")
    test_dlm_wrap_request(username, password, server_url)
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60)


