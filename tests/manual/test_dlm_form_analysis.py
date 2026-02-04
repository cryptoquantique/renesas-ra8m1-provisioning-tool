"""
Analyze DLM login form structure.

This script analyzes the DLM login form to understand the exact fields needed.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.dlm_credentials import load_dlm_credentials
import requests
from bs4 import BeautifulSoup

def analyze_dlm_form(username: str, password: str, server_url: str = "https://dlm.renesas.com"):
    """
    Analyze DLM login form structure.
    """
    print(f"\n{'='*60}")
    print("Analyzing DLM Login Form")
    print(f"{'='*60}\n")
    
    session = requests.Session()
    session.verify = True
    
    try:
        # Get login page
        login_url = f"{server_url}/keywrap/doui/agree"
        print(f"1. Fetching: {login_url}")
        response = session.get(login_url, timeout=10.0)
        print(f"   Status: {response.status_code}\n")
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            print(f"Found {len(forms)} form(s):\n")
            
            for i, form in enumerate(forms, 1):
                print(f"Form {i}:")
                print(f"  Method: {form.get('method', 'GET')}")
                print(f"  Action: {form.get('action', '(empty - same page)')}")
                print(f"  ID: {form.get('id', 'N/A')}")
                print(f"  Class: {form.get('class', 'N/A')}")
                
                # Find all input fields
                inputs = form.find_all(['input', 'select', 'textarea', 'button'])
                print(f"\n  Input fields ({len(inputs)}):")
                
                form_data = {}
                for inp in inputs:
                    inp_type = inp.get('type', 'text')
                    inp_name = inp.get('name', '')
                    inp_id = inp.get('id', '')
                    inp_value = inp.get('value', '')
                    inp_required = inp.has_attr('required')
                    inp_placeholder = inp.get('placeholder', '')
                    
                    tag_name = inp.name
                    
                    print(f"    - {tag_name}: type={inp_type}, name='{inp_name}', id='{inp_id}'")
                    if inp_value:
                        print(f"      value='{inp_value}'")
                    if inp_placeholder:
                        print(f"      placeholder='{inp_placeholder}'")
                    if inp_required:
                        print(f"      required")
                    
                    if inp_name:
                        form_data[inp_name] = inp_value or ''
                
                # Try to submit with credentials
                if form_data:
                    print(f"\n  Attempting login with form data:")
                    for key, val in form_data.items():
                        if 'pass' in key.lower() or 'pwd' in key.lower():
                            form_data[key] = password
                            print(f"    {key} = [PASSWORD]")
                        elif 'user' in key.lower() or 'email' in key.lower() or 'mail' in key.lower() or 'login' in key.lower():
                            form_data[key] = username
                            print(f"    {key} = {username}")
                        else:
                            print(f"    {key} = {val}")
                    
                    # Submit form
                    action = form.get('action', '')
                    submit_url = f"{server_url}{action}" if action else login_url
                    method = form.get('method', 'GET').upper()
                    
                    print(f"\n  Submitting to: {submit_url} (method: {method})")
                    
                    if method == 'POST':
                        submit_response = session.post(submit_url, data=form_data, timeout=10.0, allow_redirects=True)
                    else:
                        submit_response = session.get(submit_url, params=form_data, timeout=10.0, allow_redirects=True)
                    
                    print(f"  Response status: {submit_response.status_code}")
                    print(f"  Final URL: {submit_response.url}")
                    
                    # Check if login was successful
                    content_lower = submit_response.text.lower()
                    if 'time out' not in content_lower:
                        print(f"  [+] No timeout error!")
                        if 'error' in content_lower or 'invalid' in content_lower:
                            print(f"   But contains error message")
                        elif 'logout' in content_lower or 'welcome' in content_lower:
                            print(f"  [+] Possible login success!")
                        else:
                            print(f"  ? Unknown response")
                    else:
                        print(f"   Still getting timeout")
                    
                    # Check cookies
                    if session.cookies:
                        print(f"  Cookies: {[c.name for c in session.cookies]}")
                
                print("\n" + "-"*60 + "\n")
        
        session.close()
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
    print("DLM Form Analysis")
    print("="*60)
    
    analyze_dlm_form(username, password, server_url)
    
    print("\n" + "="*60)
    print("Analysis completed!")
    print("="*60)


