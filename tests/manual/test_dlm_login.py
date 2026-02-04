"""
Test DLM login and session management.

This script tests the DLM login flow to get a valid session.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import DLMConfig
from security.dlm.client import DLMClient
from utils.dlm_credentials import load_dlm_credentials
import requests
from bs4 import BeautifulSoup

def test_dlm_login(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Test DLM login flow.
    
    Args:
        username: DLM username/email
        password: DLM password
        server_url: DLM server URL
    """
    print(f"\n{'='*60}")
    print("Testing DLM Login Flow")
    print(f"{'='*60}\n")
    
    session = requests.Session()
    session.verify = True
    
    try:
        # Step 1: Get login page
        print("1. Getting login page...")
        login_url = f"{server_url}/keywrap/doui/agree"
        response = session.get(login_url, timeout=10.0)
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            # Try to parse HTML to find login form
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                print(f"   Found {len(forms)} form(s) on page")
                
                # Look for login form
                for form in forms:
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    print(f"   Form: method={method}, action={action}")
                    
                    # Find input fields
                    inputs = form.find_all(['input', 'select'])
                    for inp in inputs:
                        inp_type = inp.get('type', '')
                        inp_name = inp.get('name', '')
                        inp_id = inp.get('id', '')
                        if inp_name or inp_id:
                            print(f"      Input: type={inp_type}, name={inp_name}, id={inp_id}")
            except Exception as e:
                print(f"   Could not parse HTML: {e}")
                # Print first 500 chars of response
                print(f"   Response preview: {response.text[:500]}")
        
        # Step 2: Try to find and submit login form
        print("\n2. Attempting login...")
        
        # Common login endpoints
        login_endpoints = [
            "/keywrap/doui/login",
            "/keywrap/login",
            "/login",
            "/keywrap/doui/agree",  # Maybe it's the same page with POST
        ]
        
        login_data = {
            'email': username,
            'username': username,
            'password': password,
            'user': username,
            'userid': username,
        }
        
        for endpoint in login_endpoints:
            url = f"{server_url}{endpoint}"
            try:
                # Try POST
                response = session.post(url, data=login_data, timeout=10.0, allow_redirects=True)
                print(f"   POST {endpoint}: Status {response.status_code}")
                
                if response.status_code == 200:
                    # Check if we're logged in (look for logout link, user info, etc.)
                    content_lower = response.text.lower()
                    if 'logout' in content_lower or 'welcome' in content_lower or 'logged' in content_lower:
                        print(f"      [+] Possible login success!")
                    elif 'error' in content_lower or 'invalid' in content_lower or 'failed' in content_lower:
                        print(f"       Login failed")
                    else:
                        print(f"      ? Unknown response")
                
                # Check cookies
                if session.cookies:
                    print(f"      Cookies: {len(session.cookies)} cookie(s)")
                    for cookie in session.cookies:
                        print(f"         {cookie.name}: {cookie.value[:50]}...")
                
            except Exception as e:
                print(f"   POST {endpoint}: Error - {str(e)[:100]}")
        
        # Step 3: Try accessing protected page with session
        print("\n3. Testing authenticated access...")
        protected_urls = [
            "/keywrap/doui/agree",
            "/keywrap/doui",
            "/keywrap/",
        ]
        
        for url in protected_urls:
            full_url = f"{server_url}{url}"
            try:
                response = session.get(full_url, timeout=5.0)
                print(f"   {url}: Status {response.status_code}")
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    if 'time out' in content_lower:
                        print(f"       Still getting timeout (not logged in)")
                    elif 'login' in content_lower and 'password' in content_lower:
                        print(f"       Redirected to login (not authenticated)")
                    else:
                        print(f"      [+] Possible authenticated access!")
                        # Check for keywrap/upload functionality
                        if 'upload' in content_lower or 'file' in content_lower:
                            print(f"      [+] Page contains upload functionality")
            except Exception as e:
                print(f"   {url}: Error - {str(e)[:80]}")
        
        session.close()
        print("\n[+] Login flow testing completed!")
        return True
        
    except Exception as e:
        print(f"\n Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Load credentials
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
    print("DLM Login Flow Test")
    print("="*60)
    
    test_dlm_login(username, password, server_url)
    
    print("\n" + "="*60)
    print("Test completed!")
    print("="*60)


