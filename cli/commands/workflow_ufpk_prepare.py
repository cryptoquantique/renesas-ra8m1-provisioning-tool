"""
Combined UFPK preparation workflow command.

This command combines all UFPK-related steps:
1. Generate/prepare UFPK file
2. Encrypt UFPK with Renesas public key
3. Upload encrypted UFPK to DLM
4. Wait for user to download and save wrapped UFPK from email
5. Decrypt wrapped UFPK

This is a convenience command. Individual steps are still available for debugging.
"""

import sys
import click
from pathlib import Path
from typing import Optional

from config.loader import ConfigLoader
from security.skmt.wrapper import SKMTWrapper
from security.dlm.client import DLMClient
from security.pgp.client import PGPClient
from utils.exceptions import DLMError, PGPError, SKMTError
from utils.logging import get_logger
from cli.commands.workflow import get_flow_folder

logger = get_logger(__name__)


def _is_encrypted_with_renesas_key(pgp_file: Path, config) -> bool:
    """
    Check if a PGP file is encrypted with Renesas key (wrong) or user key (correct).
    
    Returns True if encrypted with Renesas key (wrong file), False if encrypted with user key.
    """
    try:
        import subprocess
        # Try to get encryption key ID from the file
        result = subprocess.run(
            [config.pgp.gpg_path, "--list-packets", str(pgp_file)],
            capture_output=True,
            timeout=10,
            check=False
        )
        
        if result.returncode == 0:
            output = result.stdout.decode() + result.stderr.decode()
            # Look for Renesas key ID in the output
            if "8420039B5F4E4F5E" in output or "keywrap" in output.lower():
                return True
        
        # Also try decrypt to see what key is needed
        result = subprocess.run(
            [config.pgp.gpg_path, "--decrypt", "--dry-run", str(pgp_file)],
            capture_output=True,
            timeout=10,
            check=False
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.decode() or result.stdout.decode()
            if "8420039B5F4E4F5E" in error_msg or "keywrap" in error_msg.lower():
                return True
        
        return False
    except Exception:
        return False  # If we can't determine, assume it's OK


@click.command("prepare-ufpk")
@click.option(
    "--ufpk-hardcoded",
    type=str,
    help="Hardcoded UFPK hex (64 chars). If not provided, will generate random.",
)
@click.option(
    "--ufpk-file",
    type=click.Path(exists=True, path_type=Path),
    help="Use existing UFPK file instead of generating new one.",
)
@click.pass_context
def prepare_ufpk(ctx, ufpk_hardcoded: Optional[str], ufpk_file: Optional[Path]):
    """
    Complete UFPK preparation workflow (all-in-one).
    
    This command:
    1. Generates/prepares UFPK file
    2. Encrypts UFPK with Renesas public key
    3. Uploads encrypted UFPK to DLM server
    4. Waits for you to download and save wrapped UFPK from email
    5. Decrypts wrapped UFPK
    
    All files are saved in the current flow folder.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Complete UFPK Preparation Workflow")
    click.echo("="*70 + "\n")
    
    # Check for existing wrapped keys ONLY in project root (output/flow_* folders)
    output_base = Path("output")
    output_base.mkdir(exist_ok=True)
    flow_folders = [d for d in output_base.iterdir() if d.is_dir() and d.name.startswith("flow_")]
    existing_wrapped_keys = []
    
    if flow_folders:
        for folder in sorted(flow_folders, key=lambda x: x.name, reverse=True):
            # Look for wrapped UFPK files (decrypted or wrapped)
            wrapped_files = []
            # Check for standard names first
            if (folder / "wrapped_ufpk.pgp").exists():
                wrapped_files.append(folder / "wrapped_ufpk.pgp")
            if (folder / "ufpk_wrapped_decrypted.key").exists():
                wrapped_files.append(folder / "ufpk_wrapped_decrypted.key")
            # Also look for DLM wrapped files with different names
            for pattern in ["ufpk_encrypted_enc.key.pgp"]:
                matches = list(folder.glob(pattern))
                wrapped_files.extend(matches)
            
            # Filter out encrypted files that we sent TO DLM (keep only wrapped FROM DLM or decrypted)
            wrapped_files = [f for f in wrapped_files if not (f.name.startswith("ufpk_encrypted.pgp") and "encrypted_enc" not in f.name)]
            
            # Remove duplicates by name (keep first occurrence)
            seen_names = set()
            unique_files = []
            for f in wrapped_files:
                if f.name not in seen_names:
                    seen_names.add(f.name)
                    unique_files.append(f)
            
            # Only add one file per folder
            if unique_files:
                existing_wrapped_keys.append((folder, unique_files[0]))
    
    # Check if we should skip to decryption
    skip_to_decryption = False
    wrapped_file_path = None
    flow_folder = None
    
    # Check if we have an already DECRYPTED file
    for folder, key_file in existing_wrapped_keys:
        if key_file.name == "ufpk_wrapped_decrypted.key":
            flow_folder = folder
            wrapped_file_path = key_file
            skip_to_decryption = True
            click.echo(f"   [+] Found already decrypted UFPK: {wrapped_file_path.name}")
            click.echo(f"   [DIR] Flow folder: {flow_folder.absolute()}\n")
            break
    
    # If not decrypted, check if we have a wrapped file that needs decryption
    if not skip_to_decryption:
        # Get the latest flow folder
        flow_folder = get_flow_folder()
        
        # Check if there's already a wrapped file in the flow folder
        wrapped_files = []
        if flow_folder.exists():
            wrapped_files = list(flow_folder.glob("ufpk_encrypted_enc.key.pgp"))
            wrapped_files.extend(list(flow_folder.glob("wrapped_ufpk.pgp")))
            # Filter out files encrypted with Renesas key (those we sent TO DLM)
            wrapped_files = [f for f in wrapped_files if not _is_encrypted_with_renesas_key(f, config)]
        
        if wrapped_files:
            # Use the most recent wrapped file
            wrapped_file_path = max(wrapped_files, key=lambda f: f.stat().st_mtime)
            skip_to_decryption = True
            click.echo(f"   [+] Found existing wrapped UFPK: {wrapped_file_path.name}")
            click.echo(f"   [DIR] Flow folder: {flow_folder.absolute()}")
            click.echo("   → Skipping to decryption step...\n")
        else:
            click.echo("   [+] Starting new UFPK workflow...\n")
    
    # Get or create flow folder
    if skip_to_decryption:
        # When using existing wrapped key, flow_folder should be set from wrapped_file_path
        if wrapped_file_path:
            flow_folder = wrapped_file_path.parent
        else:
            # Fallback: use latest flow folder
            flow_folder = get_flow_folder()
    else:
        flow_folder = get_flow_folder()
        click.echo(f"[DIR] Flow folder: {flow_folder.absolute()}\n")
    
    # Step 1-4: Generate, encrypt, upload, wait (skip if using existing wrapped key)
    if not skip_to_decryption:
        # Step 1: Generate/prepare UFPK
        click.echo("Step 1/5: Generating/Preparing UFPK file...")
        
        # Check for UFPK in multiple locations (priority order)
        existing_ufpk_flow = flow_folder / "ufpk.key"
        prerequisites_dir = Path("prerequisites")
        existing_ufpk_prereq = prerequisites_dir / "ufpk.key"
        
        if ufpk_file:
            # 1. Use explicitly provided file
            ufpk_path = ufpk_file
            click.echo(f"   [+] Using existing UFPK (from parameter): {ufpk_path}")
        elif existing_ufpk_prereq.exists():
            # 2. Check prerequisites folder FIRST (user's UFPK!)
            ufpk_path = existing_ufpk_prereq
            click.echo(f"   [+] Using existing UFPK from prerequisites: {ufpk_path.name}")
            click.echo(f"   [FILE] {ufpk_path.absolute()}")
            # Copy to flow folder for tracking
            import shutil
            flow_ufpk = flow_folder / "ufpk.key"
            shutil.copy2(ufpk_path, flow_ufpk)
            ufpk_path = flow_ufpk
        elif existing_ufpk_flow.exists():
            # 3. Check flow folder (already used in this workflow)
            ufpk_path = existing_ufpk_flow
            click.echo(f"   [+] Using existing UFPK from flow folder: {ufpk_path.name}")
        elif ufpk_hardcoded:
            ufpk_hex = ufpk_hardcoded.replace(" ", "").replace("-", "")
            if len(ufpk_hex) != 64:
                click.echo(f"   [ERROR] Hardcoded UFPK must be 64 hex characters, got {len(ufpk_hex)}", err=True)
                sys.exit(1)
            ufpk_path = flow_folder / "ufpk.key"
            skmt_wrapper = SKMTWrapper(
                skmt_path=config.skmt.skmt_path,
                working_directory=config.skmt.working_directory,
            )
            ufpk_path = Path(skmt_wrapper.generate_ufpk(ufpk_hex=ufpk_hex, output_file=str(ufpk_path)))
            click.echo(f"   [+] UFPK generated (hardcoded): {ufpk_path.name}")
        else:
            # Default: Generate RANDOM UFPK (256-bit = 32 bytes = 64 hex chars)
            # Per Renesas documentation: "Generate UFPK (256-bit random or specified value)"
            # Reference: r11an0785eu0100 Section 4.2, r11an0496eu0220 Section 3.1
            ufpk_path = flow_folder / "ufpk.key"
            skmt_wrapper = SKMTWrapper(
                skmt_path=config.skmt.skmt_path,
                working_directory=config.skmt.working_directory,
            )
            # Call without ufpk_hex parameter → SKMT generates random
            ufpk_path = Path(skmt_wrapper.generate_ufpk(output_file=str(ufpk_path)))
            click.echo(f"   [+] UFPK generated (RANDOM 256-bit): {ufpk_path.name}")
        
        click.echo(f"   [FILE] Saved to: {ufpk_path.absolute()}\n")
        
        # Step 2: Encrypt UFPK
        click.echo("Step 2/5: Encrypting UFPK with Renesas public key...")
        try:
            renesas_key = Path(config.pgp.renesas_public_key)
            
            # Verify and fix key if needed
            from utils.verify_renesas_key import verify_renesas_public_key, find_renesas_key_files
            
            if not renesas_key.exists() or not renesas_key.is_file():
                click.echo("    Searching for Renesas key files...")
                
                # Check prerequisites folder FIRST (preferred location)
                project_root = Path.cwd()
                prerequisites_dir = project_root / "prerequisites"
                common_names = ["keywrap-pub.key", "keywrap-pub.asc", "Keywrap-pub.key", "Keywrap-pub.asc"]
                found_keys = []
                
                for name in common_names:
                    key_path = prerequisites_dir / name
                    if key_path.exists() and key_path.is_file():
                        found_keys.append(key_path)
                
                # Check project root as fallback
                for name in common_names:
                    key_path = project_root / name
                    if key_path.exists() and key_path.is_file():
                        found_keys.append(key_path)
                
                # Check parent directory (C:\Work\renesas) as fallback
                parent_dir = project_root.parent
                for name in common_names:
                    key_path = parent_dir / name
                    if key_path.exists() and key_path.is_file():
                        found_keys.append(key_path)
                
                # Also use utility function
                utility_keys = find_renesas_key_files()
                for key_path in utility_keys:
                    if key_path.exists() and key_path.is_file() and key_path not in found_keys:
                        found_keys.append(key_path)
                
                if found_keys:
                    # Remove duplicates (same path)
                    unique_keys = []
                    seen_paths = set()
                    for key_path in found_keys:
                        abs_path = str(key_path.resolve())
                        if abs_path not in seen_paths:
                            seen_paths.add(abs_path)
                            unique_keys.append(key_path)
                    found_keys = unique_keys
                    
                    # Filter out customer public key (not Renesas key)
                    found_keys = [k for k in found_keys if "customer" not in k.name.lower()]
                    
                    # Prioritize keywrap-pub.key files
                    prioritized = []
                    others = []
                    for key_path in found_keys:
                        if "keywrap" in key_path.name.lower():
                            prioritized.append(key_path)
                        else:
                            others.append(key_path)
                    found_keys = prioritized + others
                    
                    # If found, use it
                    if found_keys:
                        renesas_key = found_keys[0]
                        click.echo(f"   [+] Using Renesas key: {renesas_key.name}")
                    else:
                        click.echo("   [ERROR] No Renesas key files found!", err=True)
                        click.echo("", err=True)
                        click.echo("   Please:", err=True)
                        click.echo("      1. Download Keywrap-pub.key from Renesas email", err=True)
                        click.echo(f"      2. Save it in: {prerequisites_dir / 'keywrap-pub.key'}", err=True)
                        click.echo("      3. Or update config.yaml with correct path", err=True)
                        sys.exit(1)
                else:
                    click.echo("   [ERROR] No Renesas key files found!", err=True)
                    click.echo("", err=True)
                    click.echo("   Please:", err=True)
                    click.echo("      1. Download Keywrap-pub.key from Renesas email", err=True)
                    click.echo(f"      2. Save it in: {prerequisites_dir / 'keywrap-pub.key'}", err=True)
                    click.echo("      3. Or update config.yaml with correct path", err=True)
                    sys.exit(1)
            
            # Basic validation: check if file exists and has valid PGP format (no user prompt)
            try:
                if not renesas_key.is_file():
                    click.echo(f"   [ERROR] Path is not a file: {renesas_key}", err=True)
                    sys.exit(1)
                key_content = renesas_key.read_text(encoding="utf-8", errors="ignore")
                if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in key_content:
                    click.echo(f"   [ERROR] Invalid PGP key format: {renesas_key}", err=True)
                    sys.exit(1)
                click.echo(f"   [+] Using Renesas public key: {renesas_key.name}")
            except PermissionError as e:
                click.echo(f"   [ERROR] Permission denied reading key file: {e}", err=True)
                sys.exit(1)
            except Exception as e:
                click.echo(f"   [ERROR] Could not read key file: {e}", err=True)
                sys.exit(1)
            
            encrypted_ufpk_path = flow_folder / "ufpk_encrypted.pgp"
            pgp_client = PGPClient(config.pgp)
            pgp_client.encrypt_file(
                input_file=ufpk_path,
                recipient_key_file=renesas_key,
                output_file=encrypted_ufpk_path,
            )
            click.echo(f"   [+] UFPK encrypted: {encrypted_ufpk_path.name}")
            click.echo(f"   [FILE] Saved to: {encrypted_ufpk_path.absolute()}\n")
        except PGPError as e:
            click.echo(f"   [ERROR] Encryption failed: {e}", err=True)
            click.echo("", err=True)
            click.echo("   [TIP] Troubleshooting:", err=True)
            click.echo("      • Verify Renesas public key file is correct", err=True)
            click.echo(f"      • Check key file: {renesas_key}", err=True)
            click.echo("      • Re-download key from Renesas if needed", err=True)
            click.echo("      • Ensure key file is not corrupted", err=True)
            sys.exit(1)
        
        # Step 3: Upload to DLM
        click.echo("Step 3/5: Uploading encrypted UFPK to DLM server...")
        try:
            # Record upload time to ignore old files
            import time
            upload_time = time.time()
            
            dlm_client = DLMClient(config.dlm)
            job_id = dlm_client.wrap_ufpk(encrypted_ufpk_path, device_id=config.dlm.device_id)
            click.echo(f"   [+] Upload successful! Request ID: {job_id[:12] if job_id else 'N/A'}...")
            click.echo(f"   [EMAIL] Check your email ({config.dlm.username}) for the wrapped UFPK file\n")
            
            # Open folder in Explorer
            try:
                import subprocess
                import platform
                if platform.system() == "Windows":
                    subprocess.Popen(f'explorer "{flow_folder.absolute()}"')
                    click.echo(f"   [DIR] Opened folder in Explorer: {flow_folder.absolute()}\n")
            except Exception as e:
                logger.debug(f"Could not open folder in Explorer: {e}")
            
        except DLMError as e:
            click.echo(f"   [ERROR] DLM upload failed: {e}", err=True)
            sys.exit(1)
        
        # Step 4: Wait for user to download and save wrapped UFPK (skip if using existing)
        if not skip_to_decryption:
            click.echo("Step 4/5: Waiting for wrapped UFPK file from email...")
            click.echo("")
            click.echo("   [EMAIL] Please:")
            click.echo("      1. Check your email for the wrapped UFPK file")
            click.echo("      2. Download the wrapped UFPK file")
            click.echo(f"      3. Copy it to the flow folder (already open in Explorer)")
            click.echo("")
            click.echo("   [...] Waiting for file... (checking every 2 seconds)")
            click.echo(f"    Flow folder: {flow_folder.absolute()}")
            click.echo("")
            
            # Auto-detect common DLM filenames
            expected_names = [
                "ufpk_encrypted_enc.key.pgp",
                "wrapped_ufpk.pgp",
                "*.pgp",  # Any .pgp file
            ]
            
            import time
            max_wait_time = 300  # 5 minutes max
            check_interval = 2  # Check every 2 seconds
            start_time = time.time()
            
            wrapped_file_path = None
            
            while time.time() - start_time < max_wait_time:
                # Check for expected filenames
                for pattern in expected_names:
                    matches = list(flow_folder.glob(pattern))
                    # Filter out files we sent TO DLM
                    matches = [f for f in matches if not (f.name.startswith("ufpk_encrypted.pgp") and "encrypted_enc" not in f.name)]
                    # Filter out old files (created before upload)
                    matches = [f for f in matches if f.stat().st_mtime >= upload_time - 10]  # Allow 10 sec margin
                    if matches:
                        # Use the first match that's not encrypted with Renesas key
                        for match in matches:
                            if not _is_encrypted_with_renesas_key(match, config):
                                wrapped_file_path = match
                                break
                        if wrapped_file_path:
                            break
                
                if wrapped_file_path and wrapped_file_path.exists():
                    click.echo(f"   [+] File detected: {wrapped_file_path.name}")
                    break
                
                time.sleep(check_interval)
                click.echo("   [...] Still waiting... (press Ctrl+C to cancel)", nl=False)
                click.echo("\r", nl=False)
            
            click.echo("")  # New line after waiting
            
            if not wrapped_file_path or not wrapped_file_path.exists():
                click.echo("   [ERROR] Timeout: Wrapped UFPK file not found in flow folder", err=True)
                click.echo("", err=True)
                click.echo("   [TIP] Please:", err=True)
                click.echo("      1. Download the wrapped UFPK file from email", err=True)
                click.echo(f"      2. Copy it to: {flow_folder.absolute()}", err=True)
                click.echo("      3. Run this command again", err=True)
                click.echo("", err=True)
                sys.exit(1)
            
            # File detected automatically, proceed to decryption
    
    # Step 5: Decrypt wrapped UFPK
    if skip_to_decryption:
        click.echo("Decrypting wrapped UFPK...")
    else:
        click.echo("Step 5/5: Decrypting wrapped UFPK...")
    
    try:
        # If using existing wrapped key, ensure we have the right path
        if skip_to_decryption:
            expected_wrapped_file = flow_folder / "wrapped_ufpk.pgp"
            # If it's already decrypted, use that
            if wrapped_file_path.name == "ufpk_wrapped_decrypted.key":
                decrypted_wrapped_path = wrapped_file_path
                click.echo(f"   [+] Using already decrypted file: {decrypted_wrapped_path.name}")
            else:
                # Use file directly for decryption, NO copying
                decrypted_wrapped_path = flow_folder / "ufpk_wrapped_decrypted.key"
        else:
            decrypted_wrapped_path = flow_folder / "ufpk_wrapped_decrypted.key"
        
        # Only decrypt if not already decrypted
        if not (skip_to_decryption and wrapped_file_path and wrapped_file_path.name == "ufpk_wrapped_decrypted.key"):
            import subprocess
            # Use the actual wrapped file path - NO copying, NO renaming
            if not wrapped_file_path or not wrapped_file_path.exists():
                raise PGPError(f"Wrapped UFPK file not found: {wrapped_file_path}")
            
            decrypt_input = wrapped_file_path
            
            # First, try to detect which key was used to encrypt the file
            click.echo(f"    Detecting encryption key...")
            detect_cmd = [
                config.pgp.gpg_path,
                "--batch",
                "--yes",
                "--no-tty",
                "--list-packets",
                str(decrypt_input),
            ]
            # Skip key detection if it hangs - just try decryption directly
            try:
                detect_result = subprocess.run(
                    detect_cmd, 
                    capture_output=True, 
                    timeout=5, 
                    check=False,
                    stdin=subprocess.DEVNULL
                )
            except subprocess.TimeoutExpired:
                click.echo(f"   [WARN] Key detection timed out - will try decryption directly")
                detect_result = None
            detected_key_id = None
            if detect_result and detect_result.returncode == 0:
                import re
                output = detect_result.stdout.decode() + detect_result.stderr.decode()
                # Look for key ID in the output (format: keyid: 36370305E87F00ED)
                key_id_match = re.search(r'keyid:\s+([0-9A-F]+)', output, re.IGNORECASE)
                if key_id_match:
                    detected_key_id = key_id_match.group(1).upper()
                    click.echo(f"   [+] File encrypted with key ID: {detected_key_id}")
            
            # Try keyring first (with batch mode to avoid passphrase prompt)
            # Try without passphrase first (key might not have one)
            # Set environment to disable pinentry GUI
            import os
            env = os.environ.copy()
            env['GPG_TTY'] = ''  # Disable TTY
            env['PINENTRY_USER_DATA'] = 'loopback'  # Force loopback mode
            # Disable pinentry program completely
            env['PINENTRY_PROGRAM'] = ''
            
            # CRITICAL FIX: Start gpg-agent if not running (prevents timeout)
            try:
                click.echo(f"    Ensuring GPG agent is running...")
                agent_check = subprocess.run(
                    [config.pgp.gpg_path.replace("gpg.exe", "gpg-connect-agent.exe"), "/bye"],
                    capture_output=True,
                    timeout=5,
                    check=False
                )
                if agent_check.returncode == 0:
                    click.echo(f"    GPG agent ready")
                else:
                    click.echo(f"    [WARN] GPG agent may not be running (continuing anyway...)")
            except Exception as e:
                click.echo(f"    [WARN] Could not verify GPG agent: {e}")
            
            cmd = [
                config.pgp.gpg_path,
                "--batch",
                "--yes",
                "--no-tty",  # Disable TTY to avoid GUI dialogs
                "--pinentry-mode", "loopback",
                "--passphrase-fd", "0",  # Read passphrase from stdin (empty for no passphrase)
                "--decrypt",
                "--output", str(decrypted_wrapped_path),
                str(decrypt_input),
            ]
            
            # If we detected a specific key ID, try to use it explicitly
            if detected_key_id:
                # Try with the specific key ID first
                click.echo(f"    Decrypting using key ID {detected_key_id}...")
            else:
                click.echo(f"    Decrypting using GnuPG keyring...")
            
            # Send empty passphrase through stdin (for keys without passphrase)
            result = subprocess.run(
                cmd,
                input="".encode('utf-8'),  # Empty passphrase
                capture_output=True,
                timeout=30,
                check=False,
                env=env
            )
            
            # Check if decryption succeeded
            if result.returncode == 0 and decrypted_wrapped_path.exists() and decrypted_wrapped_path.stat().st_size > 0:
                click.echo(f"   [+] Wrapped UFPK decrypted: {decrypted_wrapped_path.name}")
                click.echo(f"   [FILE] Saved to: {decrypted_wrapped_path.absolute()}\n")
            else:
                # Keyring failed - check if it's a passphrase issue
                error_msg = result.stderr.decode() if result.stderr else result.stdout.decode()
                
                # If it's a passphrase issue, prompt user for passphrase
                if "No passphrase given" in error_msg or "passphrase" in error_msg.lower():
                    click.echo(f"   [WARN]  Key requires passphrase")
                    passphrase = click.prompt("   Enter passphrase for private key", hide_input=True, default="")
                    # Use --passphrase-fd 0 to read passphrase from stdin
                    cmd_with_passphrase = [
                        config.pgp.gpg_path,
                        "--batch",
                        "--yes",
                        "--no-tty",  # Disable TTY to avoid GUI dialogs
                        "--pinentry-mode", "loopback",
                        "--passphrase-fd", "0",  # Read passphrase from stdin
                        "--decrypt",
                        "--output", str(decrypted_wrapped_path),
                        str(decrypt_input),
                    ]
                    click.echo(f"    Decrypting with passphrase...")
                    # Send passphrase through stdin
                    result_passphrase = subprocess.run(
                        cmd_with_passphrase,
                        input=passphrase.encode('utf-8'),
                        capture_output=True,
                        timeout=30,
                        check=False,
                        env=env
                    )
                    if result_passphrase.returncode == 0 and decrypted_wrapped_path.exists() and decrypted_wrapped_path.stat().st_size > 0:
                        click.echo(f"   [+] Wrapped UFPK decrypted: {decrypted_wrapped_path.name}")
                        click.echo(f"   [FILE] Saved to: {decrypted_wrapped_path.absolute()}\n")
                    else:
                        error_msg_passphrase = result_passphrase.stderr.decode() if result_passphrase.stderr else result_passphrase.stdout.decode()
                        click.echo(f"   [WARN]  Decryption with passphrase failed, trying private key file...")
                        error_msg = error_msg_passphrase
                else:
                    click.echo(f"   [WARN]  Keyring decryption failed, trying private key file...")
                
                # Look for private key file in project root and prerequisites folder
                project_root = Path.cwd()
                prerequisites_dir = project_root / "prerequisites"
                private_key_candidates = [
                    prerequisites_dir / "customer_private_key.asc",
                    prerequisites_dir / "customer_private_key.key",
                    project_root / "customer_private_key.asc",
                    project_root / "customer_private_key.key",
                    project_root / "private_key.asc",
                    project_root / "private_key.key",
                ]
                
                private_key_file = None
                for candidate in private_key_candidates:
                    if candidate.exists() and candidate.is_file():
                        private_key_file = candidate
                        break
                
                if private_key_file:
                    # Use PGPClient to decrypt with private key file
                    click.echo(f"   [KEY] Found private key file: {private_key_file.name}")
                    pgp_client = PGPClient(config.pgp)
                    # Try with empty passphrase first (key might not have one)
                    try:
                        pgp_client.decrypt_file(
                            input_file=decrypt_input,
                            private_key_file=private_key_file,
                            passphrase="",  # Empty passphrase
                            output_file=decrypted_wrapped_path,
                        )
                        click.echo(f"   [+] Wrapped UFPK decrypted: {decrypted_wrapped_path.name}")
                        click.echo(f"   [FILE] Saved to: {decrypted_wrapped_path.absolute()}\n")
                    except PGPError as e:
                        # If empty passphrase fails, try without passphrase parameter
                        # (let GnuPG handle it)
                        pgp_client.decrypt_file(
                            input_file=decrypt_input,
                            private_key_file=private_key_file,
                            output_file=decrypted_wrapped_path,
                        )
                        click.echo(f"   [+] Wrapped UFPK decrypted: {decrypted_wrapped_path.name}")
                        click.echo(f"   [FILE] Saved to: {decrypted_wrapped_path.absolute()}\n")
                else:
                    # No private key found - show error
                    click.echo(f"   [ERROR] Decryption failed!", err=True)
                    click.echo(f"   Error: {error_msg[:300]}", err=True)
                    click.echo("", err=True)
                    click.echo("   [TIP] Private key not found in keyring or project root!", err=True)
                    click.echo("", err=True)
                    click.echo("   Please:", err=True)
                    click.echo("      1. Import private key into GnuPG keyring:", err=True)
                    click.echo("         gpg --import customer_private_key.asc", err=True)
                    click.echo("", err=True)
                    click.echo("      OR", err=True)
                    click.echo("", err=True)
                    click.echo("      2. Save private key file in project root:", err=True)
                    click.echo(f"         {project_root / 'customer_private_key.asc'}", err=True)
                    click.echo("", err=True)
                    click.echo("   The wrapped UFPK file from DLM must be decrypted with YOUR private key", err=True)
                    click.echo("   (the one that corresponds to the public key you sent to Renesas)", err=True)
                    raise PGPError(f"GnuPG decryption failed: {error_msg[:200]}")
    except PGPError as e:
        click.echo(f"   [ERROR] Decryption failed: {e}", err=True)
        sys.exit(1)
    
    # Summary
    click.echo("="*70)
    click.echo("[OK] UFPK Preparation Complete!")
    click.echo("="*70)
    click.echo(f"\n[DIR] All files saved in: {flow_folder.absolute()}")
    click.echo("\nGenerated files:")
    # Show files that exist
    ufpk_file = flow_folder / "ufpk.key"
    encrypted_file = flow_folder / "ufpk_encrypted.pgp"
    decrypted_file = flow_folder / "ufpk_wrapped_decrypted.key"
    if ufpk_file.exists():
        click.echo(f"  • UFPK: {ufpk_file.name}")
    if encrypted_file.exists():
        click.echo(f"  • Encrypted UFPK: {encrypted_file.name}")
    if wrapped_file_path and wrapped_file_path.exists():
        click.echo(f"  • Wrapped UFPK (from email): {wrapped_file_path.name}")
    if decrypted_file.exists():
        click.echo(f"  • Decrypted wrapped UFPK: {decrypted_file.name}")
    click.echo("\n[TIP] Next step: Run 'invoke prepare-all-keys' to generate RKEY and certificates")
    click.echo("          Or run individual steps: 'invoke generate-rkey' -> 'invoke generate-certs'")
    click.echo("")

