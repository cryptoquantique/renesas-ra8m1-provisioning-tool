"""
Test DLM web-based API endpoints.

This script tests if DLM accepts file uploads through web forms.
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


def test_dlm_web_forms(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Test DLM web form endpoints.
    
    Args:
        username: DLM username
        password: DLM password
        server_url: DLM server URL
    """
    print(f"\n{'='*60}")
    print("Testing DLM Web Form Endpoints")
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
        
        # Test getting the form page first
        print("1. Testing form page access...")
        form_urls = [
            "/keywrap/doui/agree",
            "/keywrap/doui",
            "/keywrap/",
        ]
        
        for url in form_urls:
            full_url = f"{server_url}{url}"
            try:
                response = client.session.get(full_url, timeout=5.0)
                print(f"   {url}: Status {response.status_code}")
                if response.status_code == 200:
                    # Check if it's a form page
                    content = response.text.lower()
                    if 'form' in content or 'upload' in content or 'file' in content:
                        print(f"      [+] Contains form/upload elements")
                    if 'ufpk' in content or 'keywrap' in content:
                        print(f"      [+] Contains UFPK/keywrap references")
            except Exception as e:
                print(f"   {url}: Error - {str(e)[:80]}")
        
        # Test POST to various endpoints with form data
        print("\n2. Testing POST with form data...")
        
        # Create a dummy file for testing
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.gpg') as tmp_file:
            tmp_file.write(b"dummy encrypted ufpk data")
            tmp_file_path = tmp_file.name
        
        try:
            test_endpoints = [
                "/keywrap/doui/wrap",
                "/keywrap/api/wrap",
                "/keywrap/doui/api/wrap",
                "/keywrap/doui/upload",
                "/keywrap/doui/submit",
            ]
            
            for endpoint in test_endpoints:
                url = f"{server_url}{endpoint}"
                print(f"\n   Testing: {endpoint}")
                
                try:
                    # Try as multipart form data
                    with open(tmp_file_path, 'rb') as f:
                        files = {
                            'file': ('test_ufpk.gpg', f, 'application/octet-stream'),
                            'ufpk_file': ('test_ufpk.gpg', open(tmp_file_path, 'rb'), 'application/octet-stream'),
                        }
                        data = {
                            'device_id': 'test_device',
                            'product_family': 'RA',
                        }
                        
                        response = client.session.post(url, files=files, data=data, timeout=10.0)
                        print(f"      Status: {response.status_code}")
                        
                        if response.status_code == 200:
                            content = response.text[:500]
                            if 'error' in content.lower() or 'invalid' in content.lower():
                                print(f"      Response: {content}")
                            elif 'success' in content.lower() or 'job' in content.lower():
                                print(f"      [+] Success response!")
                                print(f"      Response: {content}")
                            else:
                                print(f"      Response (first 200 chars): {content[:200]}")
                        elif response.status_code in [301, 302, 303]:
                            location = response.headers.get('Location', 'N/A')
                            print(f"      Redirects to: {location}")
                        else:
                            print(f"      Response: {response.text[:300]}")
                        
                        files['ufpk_file'][1].close()
                        
                except Exception as e:
                    print(f"      Error: {str(e)[:150]}")
        
        finally:
            # Clean up
            Path(tmp_file_path).unlink()
        
        # Test with JSON (in case it's a REST API after all)
        print("\n3. Testing POST with JSON data...")
        json_endpoints = [
            "/keywrap/api/wrap",
            "/keywrap/doui/api/wrap",
        ]
        
        for endpoint in json_endpoints:
            url = f"{server_url}{endpoint}"
            try:
                import json
                json_data = {
                    "device_id": "test_device",
                    "product_family": "RA",
                }
                response = client.session.post(
                    url,
                    json=json_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=5.0
                )
                print(f"   {endpoint}: Status {response.status_code}")
                if response.status_code != 404:
                    print(f"      Response: {response.text[:200]}")
            except Exception as e:
                print(f"   {endpoint}: Error - {str(e)[:80]}")
        
        client.close()
        print("\n[+] Web form testing completed!")
        return True
        
    except Exception as e:
        print(f"\n Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Load credentials from JSON
    credentials_file = Path(__file__).parent.parent / "aws_credentials.json"
    
    if not credentials_file.exists():
        print("Credentials file not found!")
        sys.exit(1)
    
    try:
        dlm_creds = load_dlm_credentials(credentials_file, fallback_to_env=False)
        username = dlm_creds.username or dlm_creds.email
        password = dlm_creds.password
        print(f"Loaded DLM credentials from {credentials_file}")
    except Exception as e:
        print(f"Could not load from JSON file: {e}")
        sys.exit(1)
    
    server_url = "https://dlm.renesas.com"
    
    print("\n" + "="*60)
    print("DLM Web Form API Test")
    print("="*60)
    
    test_dlm_web_forms(username, password, server_url)
    
    print("\n" + "="*60)
    print("Test completed!")
    print("="*60)


