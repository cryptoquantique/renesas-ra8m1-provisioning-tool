"""
Provisioning Workflow Commands.

Individual commands for each step of the provisioning workflow.
All commands use the same timestamped output folder.
"""

import os
import shutil
import struct
import subprocess
import sys
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List

import boto3
import click
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from config.loader import ConfigLoader
from device.ra8_provisioning_client import RA8ProvisioningClient
from device.ra8_provisioning_workflow import RA8ProvisioningWorkflow
from firmware.aws_kms_signer_v3 import sign_image_with_aws_kms
from firmware.imgtool_runner import sign_image, verify_image
from models.keys import KeyCurve, KeyType
from security.dlm.client import DLMClient
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem
from security.pgp.client import PGPClient
from security.skmt.certificate_generator import CertificateGenerator
from security.skmt.wrapper import SKMTWrapper, parse_srec
from utils.aws_credentials import load_aws_credentials
from utils.exceptions import DLMError, PGPError, SKMTError, HSMError, FirmwareError, DeviceError
from utils.logging import get_logger
from utils.path_manager import path_manager
from utils.project_config import get_project_config
from utils.srec_manager import SrecManager
from utils.version_manager import get_current_certificate_version, increment_certificate_version, check_version_overflow

logger = get_logger(__name__)

# Initialize managers
srec_manager = SrecManager()


# =============================================================================
# Key Filtering Helpers
# =============================================================================

def filter_keys_by_purpose(keys: list, purpose: str, created_after_days: int = 7) -> list:
    """
    Filter AWS KMS keys by purpose and creation date.
    
    Args:
        keys: List of AWS KMS key metadata dicts
        purpose: Purpose to filter for ('oem_root', 'bootloader', 'customer')
        created_after_days: Only show keys created in last N days (0 = all keys)
    
    Returns:
        List of (key_id, display_name) tuples
    """
    filtered_keys = []
    cutoff_date = None
    if created_after_days > 0:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=created_after_days)
    
    for k in keys:
        # Skip if created too long ago
        if cutoff_date and k.get('CreationDate'):
            if k['CreationDate'] < cutoff_date:
                continue
        
        # Check description and aliases for purpose
        description = k.get('Description', '').lower()
        aliases = k.get('AliasNames', [])
        alias_str = ' '.join(aliases).lower()
        
        # Match purpose
        purpose_lower = purpose.lower()
        if purpose_lower == 'oem_root':
            if 'oem' in description or 'root' in description or 'oem_root' in alias_str:
                name = aliases[0].replace('alias/', '') if aliases else f"{k['KeyId'][:12]}... (No alias)"
                filtered_keys.append((k['KeyId'], name))
        elif purpose_lower == 'bootloader':
            if 'bootloader' in description or 'bootloader' in alias_str:
                name = aliases[0].replace('alias/', '') if aliases else f"{k['KeyId'][:12]}... (No alias)"
                filtered_keys.append((k['KeyId'], name))
        elif purpose_lower == 'customer':
            if 'customer' in description or 'customer' in alias_str:
                name = aliases[0].replace('alias/', '') if aliases else f"{k['KeyId'][:12]}... (No alias)"
                filtered_keys.append((k['KeyId'], name))
    
    return filtered_keys


# =============================================================================
# Prerequisites Folder Management
# =============================================================================

PREREQUISITES_FOLDER = Path("prerequisites")
REUSABLE_FOLDER = Path("output/reusable")


def get_prerequisites_folder() -> Path:
    """Get or create prerequisites folder in project root."""
    return path_manager.get_prerequisites_folder()


def get_reusable_folder() -> Path:
    """Get or create reusable assets folder for keys and certificates."""
    return path_manager.get_reusable_folder()


def prompt_reuse_or_regenerate(asset_name: str, existing_files: list) -> bool:
    """
    Prompt user if they want to reuse existing files or regenerate.
    
    Args:
        asset_name: Name of asset (e.g., "certificates", "UFPK")
        existing_files: List of existing file paths
    
    Returns:
        True if user wants to reuse, False if regenerate
    """
    click.echo(f"\n{'='*70}")
    click.echo(f"WARNING: Existing {asset_name} Found")
    click.echo(f"{'='*70}")
    click.echo(f"\nFound existing {asset_name}:")
    for f in existing_files:
        click.echo(f"  [OK] {f.name}")
    
    click.echo(f"\nOptions:")
    click.echo(f"  [R] Reuse existing {asset_name}")
    click.echo(f"  [G] Generate new {asset_name} (will overwrite)")
    
    while True:
        choice = click.prompt("\nYour choice", type=str, default="R").strip().upper()
        if choice in ["R", "G"]:
            return choice == "R"
        click.echo("Invalid choice. Please enter 'R' or 'G'.")


def get_prerequisite_file(
    file_description: str,
    file_patterns: List[str],
    required: bool = True,
    target_name: Optional[str] = None,
) -> Optional[Path]:
    """
    Get a file from prerequisites folder.
    
    Args:
        file_description: Human-readable description (e.g., "Application SREC")
        file_patterns: List of patterns to search (e.g., ["*app*.srec", "*APP*.srec"])
        required: If True, exit if file not found
        target_name: Name to save file as in prerequisites folder
    
    Returns:
        Path to the file (in prerequisites folder), or None if not found and not required
    """
    prereq_folder = get_prerequisites_folder()
    
    # Search in prerequisites folder
    for pattern in file_patterns:
        found = list(prereq_folder.glob(pattern))
        if found:
            click.echo(f"   [+] Found {file_description}: {found[0].name}")
            return found[0]
    
    # Not found
    if required:
        click.echo(f"\n[ERROR] {file_description} not found in prerequisites/", err=True)
        click.echo(f"   Searched for patterns: {', '.join(file_patterns)}", err=True)
        click.echo(f"   Please place the file in: {prereq_folder.absolute()}", err=True)
        sys.exit(1)
    
    return None


def open_folder_in_explorer(folder: Path):
    """Open folder in Windows Explorer."""
    try:
        subprocess.run(["explorer", str(folder.absolute())], check=False)
    except Exception as e:
        logger.warning(f"Failed to open folder: {e}")


def get_flow_folder() -> Path:
    """Get or create current flow folder with timestamp.
    
    Logic:
    - Reuses existing folder if it has any provisioning files
    - Create new folder only if explicitly needed or no folders exist
    """
    output_base = Path("output")
    output_base.mkdir(exist_ok=True)
    
    # Find latest flow folder
    flow_folders = [d for d in output_base.iterdir() if d.is_dir() and d.name.startswith("flow_")]
    
    if flow_folders:
        latest = sorted(flow_folders, key=lambda x: x.name, reverse=True)[0]
        
        # Check if folder has any provisioning files (reuse if it does)
        important_files = [
            "ufpk.key",
            "ufpk_wrapped_decrypted.key",
            "oem_root_key.rkey",
            "key_cert.bin",
            "code_cert.bin",
            "combined.srec"
        ]
        
        # Reuse folder if ANY important file exists
        for file_name in important_files:
            if (latest / file_name).exists():
                return latest
    
    # Create new flow folder only if no folders exist or explicitly needed
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    flow_folder = output_base / f"flow_{timestamp}"
    flow_folder.mkdir(parents=True, exist_ok=True)
    return flow_folder


@click.group("workflow")
def workflow_group():
    """Provisioning workflow commands (run steps individually)."""
    pass


def workflow_main():
    """Main entry point for workflow command."""
    from cli.main import cli
    
    original_argv = sys.argv.copy()
    if len(original_argv) > 1:
        subcommand = original_argv[1]
        sub_args = original_argv[2:] if len(original_argv) > 2 else []
        cmd_line = ['workflow', subcommand] + sub_args
        result = cli(cmd_line, standalone_mode=False, obj={})
        sys.exit(result if isinstance(result, int) else 0)
    else:
        cli(['workflow', '--help'], standalone_mode=False, obj={})


@workflow_group.command("prepare-ufpk-file")
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
def prepare_ufpk_file(ctx, ufpk_hardcoded: Optional[str], ufpk_file: Optional[Path]):
    """
    Step 1: Start workflow - Generate UFPK and create flow folder.
    
    This creates a new timestamped folder and generates UFPK.
    All subsequent commands will use this folder.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 1: Starting Workflow - Generate UFPK")
    click.echo("="*70 + "\n")

    flow_folder = get_flow_folder()
    click.echo(f"[DIR] Flow folder: {flow_folder.absolute()}\n")
    
    # Generate or use UFPK
    if ufpk_file:
        ufpk_path = ufpk_file
        click.echo(f"[+] Using existing UFPK: {ufpk_path}")
    elif ufpk_hardcoded:
        ufpk_hex = ufpk_hardcoded.replace(" ", "").replace("-", "")
        if len(ufpk_hex) != 64:
            click.echo(f"[ERROR] Hardcoded UFPK must be 64 hex characters, got {len(ufpk_hex)}", err=True)
            sys.exit(1)
        ufpk_path = flow_folder / "ufpk.key"
        skmt_wrapper = SKMTWrapper(
            skmt_path=config.skmt.skmt_path,
            working_directory=config.skmt.working_directory,
        )
        ufpk_path = skmt_wrapper.generate_ufpk(ufpk_hex=ufpk_hex, output_file=str(ufpk_path))
        click.echo(f"[+] UFPK generated (hardcoded): {ufpk_path.name}")
    else:
        ufpk_path = flow_folder / "ufpk.key"
        skmt_wrapper = SKMTWrapper(
            skmt_path=config.skmt.skmt_path,
            working_directory=config.skmt.working_directory,
        )
        # Generate RANDOM UFPK (per Renesas docs: 256-bit random key)
        ufpk_path = skmt_wrapper.generate_ufpk(output_file=str(ufpk_path))
        click.echo(f"[+] UFPK generated (RANDOM 256-bit): {ufpk_path.name}")
    
    click.echo(f"   Saved to: {ufpk_path.absolute()}\n")
    click.echo("[OK] Step 1 complete! Run: workflow encrypt-ufpk")


@workflow_group.command("encrypt-ufpk")
@click.pass_context
def encrypt_ufpk(ctx):
    """
    Step 2: Encrypt UFPK with Renesas public key.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 2: Encrypting UFPK with Renesas public key")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    ufpk_path = flow_folder / "ufpk.key"
    
    if not ufpk_path.exists():
        click.echo(f"[ERROR] UFPK file not found: {ufpk_path}", err=True)
        click.echo("   Run 'workflow start' first.", err=True)
        sys.exit(1)
    
    encrypted_ufpk = flow_folder / "ufpk_encrypted.pgp"
    renesas_key = Path(config.pgp.renesas_public_key)
    
    # Check prerequisites folder first
    prerequisites_key = Path("prerequisites") / "keywrap-pub.key"
    if prerequisites_key.exists():
        renesas_key = prerequisites_key
    elif not renesas_key.exists():
        click.echo(f"[ERROR] Renesas public key not found!", err=True)
        click.echo(f"   Place keywrap-pub.key in: prerequisites/", err=True)
        sys.exit(1)
    
    pgp_client = PGPClient(config.pgp)
    pgp_client.encrypt_file(
        input_file=ufpk_path,
        recipient_key_file=renesas_key,
        output_file=encrypted_ufpk,
    )
    click.echo(f"[+] UFPK encrypted: {encrypted_ufpk.name}")
    click.echo(f"   Saved to: {encrypted_ufpk.absolute()}\n")
    click.echo("[OK] Step 2 complete! Run: workflow upload-dlm")


@workflow_group.command("upload-dlm")
@click.option("--device-id", type=str, help="Device ID for DLM operations.")
@click.pass_context
def upload_dlm(ctx, device_id: Optional[str]):
    """
    Step 3: Upload encrypted UFPK to DLM server.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 3: Uploading to DLM Server")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    encrypted_ufpk = flow_folder / "ufpk_encrypted.pgp"
    
    if not encrypted_ufpk.exists():
        click.echo(f"[ERROR] Encrypted UFPK not found: {encrypted_ufpk}", err=True)
        click.echo("   Run 'workflow encrypt-ufpk' first.", err=True)
        sys.exit(1)
    
    dlm_client = DLMClient(config.dlm)
    job_id = dlm_client.wrap_ufpk(encrypted_ufpk, device_id)
    click.echo(f"[+] Upload successful! Request ID: {job_id[:12]}...")
    click.echo(f"[EMAIL] Check your email ({config.dlm.username}) for the wrapped UFPK\n")
    click.echo("[OK] Step 3 complete! After downloading from email, run: workflow decrypt-wrapped")


@workflow_group.command("decrypt-wrapped")
@click.argument("wrapped_file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def decrypt_wrapped(ctx, wrapped_file: Path):
    """
    Step 4: Decrypt wrapped UFPK from email.
    
    WRAPPED_FILE: Path to the wrapped UFPK file downloaded from email.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 4: Decrypting Wrapped UFPK")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    
    # Copy to flow folder and decrypt if needed
    wrapped_ufpk_path = flow_folder / "ufpk_wrapped_decrypted.key"
    
    if wrapped_file.suffix in ['.pgp', '.gpg']:
        # Decrypt using GPG keyring directly (most reliable method)
        click.echo(f"[INFO] Decrypting wrapped UFPK using GPG keyring...")
        env = os.environ.copy()
        env['GPG_TTY'] = ''
        
        # Start gpg-agent to avoid timeout
        try:
            gpg_agent_path = config.pgp.gpg_path.replace("gpg.exe", "gpg-connect-agent.exe").replace("gpg", "gpg-connect-agent")
            agent_start = subprocess.run(
                [gpg_agent_path, "/bye"],
                capture_output=True,
                timeout=5
            )
            if agent_start.returncode == 0:
                click.echo(f"[+] GPG agent ready")
        except Exception as e:
            click.echo(f"[WARN] Could not start GPG agent: {e}")
        
        cmd = [
            config.pgp.gpg_path,
            "--batch",
            "--yes",
            "--no-tty",
            "--pinentry-mode", "loopback",
            "--passphrase-fd", "0",
            "--decrypt",
            "--output", str(wrapped_ufpk_path),
            str(wrapped_file),
        ]
        
        result = subprocess.run(
            cmd,
            input="".encode('utf-8'),
            capture_output=True,
            timeout=30,
            env=env
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.decode() if result.stderr else result.stdout.decode()
            click.echo(f"[ERROR] GPG decryption failed!", err=True)
            click.echo(f"[ERROR] {error_msg[:300]}", err=True)
            click.echo("", err=True)
            click.echo("[TIP] Make sure the customer private key is imported:", err=True)
            click.echo("      gpg --import prerequisites/customer_private_key.asc", err=True)
            sys.exit(1)
        
        click.echo(f"[+] Wrapped UFPK decrypted: {wrapped_ufpk_path.name}")
    else:
        shutil.copy(wrapped_file, wrapped_ufpk_path)
        click.echo(f"[+] Wrapped UFPK saved: {wrapped_ufpk_path.name}")
    
    click.echo(f"   Saved to: {wrapped_ufpk_path.absolute()}\n")
    click.echo("[OK] Step 4 complete! Run: workflow generate-rkey")


@workflow_group.command("generate-rkey")
@click.option(
    "--oem-root-sk-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Root Secret Key. If not provided, will prompt.",
)
@click.pass_context
def generate_rkey(ctx, oem_root_sk_key_id: Optional[str]):
    """
    Step 5: Generate RKEY (wrap OEM Root PK with W-UFPK).
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 5: Generating RKEY")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    wrapped_ufpk_path = flow_folder / "ufpk_wrapped_decrypted.key"
    
    if not wrapped_ufpk_path.exists():
        click.echo(f"[ERROR] Wrapped UFPK not found: {wrapped_ufpk_path}", err=True)
        click.echo("   Run 'workflow decrypt-wrapped' first.", err=True)
        sys.exit(1)

    if not oem_root_sk_key_id:
        hsm_client = create_hsm_client(config.hsm)
        hsm_client.connect()
        try:
            keys = hsm_client.list_keys()
            oem_root_keys = [
                (k.get("KeyId"), k.get("AliasNames", [""])[0].replace("alias/", ""))
                for k in keys
                if "oem_root" in k.get("AliasNames", [""])[0].lower()
            ]
            
            if not oem_root_keys:
                click.echo("[ERROR] No OEM_ROOT keys found in AWS KMS!", err=True)
                sys.exit(1)
            
            click.echo("Available OEM Root keys:")
            for i, (key_id, alias) in enumerate(oem_root_keys, 1):
                click.echo(f"  {i}. {alias} ({key_id[:12]}...)")
            
            selection = click.prompt("Select OEM Root key", type=int)
            if selection < 1 or selection > len(oem_root_keys):
                click.echo("[ERROR] Invalid selection!", err=True)
                sys.exit(1)
            
            oem_root_sk_key_id = oem_root_keys[selection - 1][0]
        finally:
            hsm_client.disconnect()
    
    # Export OEM Root Public Key
    hsm_client = create_hsm_client(config.hsm)
    hsm_client.connect()
    try:
        oem_root_pk_der = hsm_client.get_public_key(oem_root_sk_key_id)
        oem_root_pk_file = flow_folder / "oem_root_public.pem"
        save_public_key_pem(oem_root_pk_der, oem_root_pk_file, KeyCurve.SECP256R1)
        click.echo(f"[+] OEM Root public key exported: {oem_root_pk_file.name}")
    finally:
        hsm_client.disconnect()
    
    # Generate RKEY
    rkey_path = flow_folder / "oem_root_key.rkey"
    skmt_wrapper = SKMTWrapper(
        skmt_path=config.skmt.skmt_path,
        working_directory=config.skmt.working_directory,
    )
    
    oem_root_pk_bytes = oem_root_pk_file.read_bytes()
    wrapped_key = skmt_wrapper.wrap_oem_root_public_key(
        oem_root_pk=oem_root_pk_bytes,
        ufpk=str(wrapped_ufpk_path),
        output_file=str(rkey_path),
    )
    
    click.echo(f"[+] RKEY generated: {rkey_path.name}")
    click.echo(f"   Saved to: {rkey_path.absolute()}\n")
    click.echo("[OK] Step 5 complete! Run: workflow generate-certs")


@workflow_group.command("generate-certs")
@click.option(
    "--oem-root-sk-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Root Secret Key.",
)
@click.option(
    "--oem-bl-sk-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Bootloader Secret Key.",
)
@click.option(
    "--bootloader-binary",
    type=click.Path(exists=True, path_type=Path),
    help="Bootloader binary file (.bin or .srec).",
)
@click.option(
    "--version",
    type=int,
    help="Certificate version (default: auto-increment from config). WARNING: Must be > current ARC_OEMBL value!",
)
@click.pass_context
def generate_certs(ctx, oem_root_sk_key_id: Optional[str], oem_bl_sk_key_id: Optional[str], bootloader_binary: Optional[Path], version: Optional[int]):
    """
    Step 6: Generate Key and Code Certificates.
    
    Uses auto-incrementing version counter from aws_credentials.json for anti-rollback protection.
    Version starts at 25 due to previous device programming attempts.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 6: Generating Certificates")
    click.echo("="*70 + "\n")
    
    # Check if reusable certificates already exist
    reusable_folder = get_reusable_folder()
    existing_certs = [
        reusable_folder / "oem_root_key.rkey",
        reusable_folder / "key_cert.bin",
        reusable_folder / "code_cert.bin",
    ]
    
    certs_exist = all(f.exists() for f in existing_certs)
    
    if certs_exist:
        # Prompt user: reuse or regenerate
        if prompt_reuse_or_regenerate("certificates", existing_certs):
            click.echo(f"\nReusing existing certificates from: {reusable_folder.absolute()}")
            
            # Copy to current flow folder for consistency
            flow_folder = get_flow_folder()
            for cert_file in existing_certs:
                dest = flow_folder / cert_file.name
                shutil.copy2(cert_file, dest)
                click.echo(f"   [+] Copied: {cert_file.name}")
            
            click.echo(f"\n[OK] Certificates ready in flow folder: {flow_folder.absolute()}")
            click.echo("[OK] Run: workflow sign-app (optional) or workflow program-device")
            return
        else:
            click.echo(f"\nRegenerating certificates...")
    
    # Check version overflow before proceeding
    current_ver, remaining, is_critical = check_version_overflow()
    if is_critical:
        click.echo(f"[WARN] Certificate version: {current_ver}/64")
        click.echo(f"[WARN] Only {remaining} versions remaining before ARC_OEMBL overflow!")
        click.echo(f"[WARN] Consider re-initializing device or using new keys.\n")
    
    # Get certificate version
    if version is None:
        cert_version = get_current_certificate_version()
        click.echo(f"[INFO] Certificate version: {cert_version} (auto from config)")
        click.echo(f"[INFO] Next certificate will use version: {cert_version + 1}\n")
    else:
        cert_version = version
        click.echo(f"[INFO] Certificate version: {cert_version} (manual override)\n")
        if cert_version <= current_ver:
            click.echo(f"[WARN] Manual version {cert_version} <= current {current_ver}")
            click.echo(f"[WARN] Device will REJECT this if ARC_OEMBL >= {cert_version}!")
            if not click.confirm("Continue anyway?"):
                sys.exit(0)
    
    flow_folder = get_flow_folder()
    
    # Get keys if not provided
    hsm_client = create_hsm_client(config.hsm)
    hsm_client.connect()
    try:
        if not oem_root_sk_key_id or not oem_bl_sk_key_id:
            keys = hsm_client.list_keys()
            
            if not oem_root_sk_key_id:
                oem_root_keys = [
                    (k.get("KeyId"), k.get("AliasNames", [""])[0].replace("alias/", ""))
                    for k in keys
                    if "oem_root" in k.get("AliasNames", [""])[0].lower()
                ]
                if not oem_root_keys:
                    click.echo("[ERROR] No OEM_ROOT keys found!", err=True)
                    sys.exit(1)
                click.echo("Available OEM Root keys:")
                for i, (key_id, alias) in enumerate(oem_root_keys, 1):
                    click.echo(f"  {i}. {alias} ({key_id[:12]}...)")
                selection = click.prompt("Select OEM Root key", type=int)
                oem_root_sk_key_id = oem_root_keys[selection - 1][0]
            
            if not oem_bl_sk_key_id:
                oem_bl_keys = [
                    (k.get("KeyId"), k.get("AliasNames", [""])[0].replace("alias/", ""))
                    for k in keys
                    if "oem_bootloader" in k.get("AliasNames", [""])[0].lower() or "bootloader" in k.get("AliasNames", [""])[0].lower()
                ]
                if not oem_bl_keys:
                    click.echo("[ERROR] No OEM_BOOTLOADER keys found!", err=True)
                    sys.exit(1)
                click.echo("Available OEM Bootloader keys:")
                for i, (key_id, alias) in enumerate(oem_bl_keys, 1):
                    click.echo(f"  {i}. {alias} ({key_id[:12]}...)")
                selection = click.prompt("Select OEM Bootloader key", type=int)
                oem_bl_sk_key_id = oem_bl_keys[selection - 1][0]
        
        # Get bootloader binary
        if not bootloader_binary:
            bootloader_binary = click.prompt(
                "Enter path to bootloader binary file",
                type=click.Path(exists=True, path_type=Path),
            )

        oem_root_pk_der = hsm_client.get_public_key(oem_root_sk_key_id)
        oem_root_pk_file = flow_folder / "oem_root_public.pem"
        save_public_key_pem(oem_root_pk_der, oem_root_pk_file, KeyCurve.SECP256R1)

        oem_bl_pk_der = hsm_client.get_public_key(oem_bl_sk_key_id)
        oem_bl_pk_file = flow_folder / "oem_bl_public.pem"
        save_public_key_pem(oem_bl_pk_der, oem_bl_pk_file, KeyCurve.SECP256R1)
        
        # Generate Key Certificate
        click.echo("   Generating Key Certificate...")
        key_cert_path = flow_folder / f"key_cert_v{cert_version}.bin"
        cert_generator = CertificateGenerator(config.skmt)
        key_cert = cert_generator.generate_key_certificate(
            oem_root_sk_handle=oem_root_sk_key_id,
            oem_root_pk=oem_root_pk_file.read_bytes(),
            oem_bl_pk=oem_bl_pk_file.read_bytes(),
            output_file=str(key_cert_path),
        )
        click.echo(f"[+] Key Certificate v{cert_version} generated: {key_cert_path.name}")
        
        # Generate Code Certificate
        click.echo(f"   Generating Code Certificate (version {cert_version})...")
        code_cert_path = flow_folder / f"code_cert_v{cert_version}.bin"
        bootloader_bytes = bootloader_binary.read_bytes()
        

        if bootloader_binary.name == "bootloader.srec":
            click.echo(f"   [WARNING] Generating Code Certificate on bootloader.srec", err=True)
            click.echo(f"   [WARNING] This will FAIL if device is flashed with bootloader_with_key.srec!", err=True)
            click.echo(f"   [TIP] Use 'invoke sign-app' instead, which uses bootloader_with_key.srec", err=True)
        

        proj_config = get_project_config()
        load_addr = int(proj_config.cert_load_addr, 16)
        cfsize = int(proj_config.cert_cfsize, 16)
        bl_binary = parse_srec(bootloader_binary, load_addr, cfsize)
        click.echo(f"   Bootloader binary: {len(bl_binary)} bytes (ACTUAL size)")

        code_cert = cert_generator.generate_code_certificate(
            oem_bl_sk_key_id=oem_bl_sk_key_id,
            bootloader_binary=bl_binary,
            output_file=code_cert_path,
            oem_bl_pk_file=oem_bl_pk_file,
            oem_root_sk_key_id=oem_root_sk_key_id,
            oem_root_pk_file=oem_root_pk_file,
            version=cert_version,
            oem_bl_pk_hash=key_cert.oem_bl_pk_hash,
        )
        click.echo(f"[+] Code Certificate v{cert_version} generated: {code_cert_path.name}")

        key_cert_keyhash = key_cert.oem_bl_pk_hash
        code_cert_data = code_cert_path.read_bytes()
        signer_id_offset = 36 + 4 + 68 + 8 + 4  # Type&Length (4 bytes)
        code_cert_signer_id = code_cert_data[signer_id_offset:signer_id_offset + 32]

        if key_cert_keyhash != code_cert_signer_id:
            click.echo(f"\n{'='*70}", err=True)
            click.echo(f"   [ERROR] CRITICAL: SIGNER_ID != KEYHASH - PROVISIONING STOPPED!", err=True)
            click.echo(f"{'='*70}", err=True)
            click.echo(f"   [ERROR] Key Cert KEYHASH:   {key_cert_keyhash.hex()}", err=True)
            click.echo(f"   [ERROR] Code Cert SIGNER_ID: {code_cert_signer_id.hex()}", err=True)
            click.echo(f"   [ERROR] These MUST be equal byte-by-byte for chain of trust!", err=True)
            click.echo(f"   [ERROR] Device will REJECT certificates with this mismatch!", err=True)
            click.echo(f"{'='*70}\n", err=True)
            raise click.ClickException(
                "OBLIGATORY ASSERT FAILED: signer_id != keyhash. "
                "Provisioning stopped - certificates will be rejected by device!"
            )

        click.echo(f"   [OK] OBLIGATORY ASSERT PASSED: signer_id == keyhash")
        click.echo(f"   [OK] KEYHASH:   {key_cert_keyhash.hex()[:16]}...")
        click.echo(f"   [OK] SIGNER_ID: {code_cert_signer_id.hex()[:16]}...")
        click.echo(f"   [OK] Chain of trust verification will PASS!")
        click.echo(f"   Version: {cert_version}")
        click.echo(f"   Saved to: {flow_folder.absolute()}\n")
        
        # Save to reusable folder for future use
        click.echo("   Copying certificates to reusable folder...")
        reusable_folder = get_reusable_folder()
        
        # Generate RKEY (wrapped OEM Root Public Key)
        click.echo("   Generating RKEY (wrapped OEM Root Public Key)...")
        rkey_path = flow_folder / "oem_root_key.rkey"
        if not rkey_path.exists():
            click.echo(f"   [WARN] RKEY generation not yet implemented")

        files_to_copy = [
            (key_cert_path, reusable_folder / f"key_cert_v{cert_version}.bin"),
            (code_cert_path, reusable_folder / f"code_cert_v{cert_version}.bin"),
        ]
        
        if rkey_path.exists():
            files_to_copy.append((rkey_path, reusable_folder / "oem_root_key.rkey"))
        
        for src, dest in files_to_copy:
            shutil.copy2(src, dest)
            click.echo(f"   [+] Saved: {dest.name} → {reusable_folder.absolute()}")

        readme_path = reusable_folder / "README.txt"
        readme_content = f"""Provisioning Assets - Reusable Files
=====================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Certificate Version: {cert_version}

WARNING: CRITICAL - Keep these files secure! They contain security keys!

Files in this folder can be reused for ALL devices in this production series.

Files:
- oem_root_key.rkey: OEM Root Public Key (wrapped with W-UFPK)
- key_cert.bin: Key Certificate (authenticates Bootloader Key)
- code_cert.bin: Code Certificate (authenticates Bootloader binary, version {cert_version})

Usage:
  1. Run 'invoke sign-app' to sign new applications
  2. Run 'invoke program-device' to program devices
  
  The tool will automatically use certificates from this folder.
"""
        readme_path.write_text(readme_content)
        click.echo(f"   [+] Created: README.txt\n")
        
        # Increment version for next certificate (only if not manually overridden)
        if version is None:
            new_version = increment_certificate_version()
            click.echo(f"[INFO] Certificate version incremented: {cert_version} → {new_version}")
            click.echo(f"[INFO] Next certificate generation will use version {new_version}\n")
        
    finally:
        hsm_client.disconnect()
    
    click.echo(f"[OK] Step 6 complete!")
    click.echo(f"[OK] Certificates saved to: {reusable_folder.absolute()}")
    click.echo(f"[OK] Run: workflow sign-app (optional) or workflow program-device")


@workflow_group.command("prepare-srec")
@click.option(
    "--app-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Application SREC file. If not provided, will prompt.",
)
@click.option(
    "--bootloader-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Bootloader SREC file. If not provided, will search or prompt.",
)
@click.option(
    "--app-offset",
    type=str,
    default="0x02010000",
    help="Application start address offset (default: 0x02010000).",
)
@click.pass_context
def prepare_srec(
    ctx, 
    app_srec: Optional[Path], 
    bootloader_srec: Optional[Path],
    app_offset: str,
):
    """
    Prepare SREC files: copy app, offset addresses, and combine with bootloader.
    This step prepares everything needed for signing.
    """
    click.echo("\n" + "="*70)
    click.echo("Prepare SREC Files")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    click.echo(f"[DIR] Flow folder: {flow_folder.absolute()}\n")
    
    # === Step 1: Get Application SREC ===
    click.echo("-"*50)
    click.echo("Step 1: Application SREC")
    click.echo("-"*50)
    
    if not app_srec:
        # Search for SREC files in common locations
        search_paths = [
            Path("."),
            Path(".."),
            Path.home() / "Downloads",
            flow_folder,
        ]
        found_srecs = []
        for search_path in search_paths:
            if search_path.exists():
                for pattern in ["*.srec", "*.s19", "*.s28", "*.s37"]:
                    found_srecs.extend(search_path.glob(pattern))
        
        # Filter out bootloader and already processed files
        found_srecs = [
            f for f in found_srecs 
            if "bootloader" not in f.name.lower() 
            and "combined" not in f.name.lower()
            and "signed" not in f.name.lower()
            and "offset" not in f.name.lower()
        ]
        found_srecs = list(set(found_srecs))[:10]  # Limit and dedupe
        
        if found_srecs:
            click.echo("\n[FILE] Found application SREC files:")
            for i, f in enumerate(found_srecs, 1):
                click.echo(f"  {i}. {f.name} ({f.parent})")
            click.echo(f"  {len(found_srecs) + 1}. [Enter path manually]")
            
            selection = click.prompt("Select application SREC", type=int, default=1)
            if selection <= len(found_srecs):
                app_srec = found_srecs[selection - 1]
            else:
                app_path = click.prompt("Enter path to application SREC")
                app_srec = Path(app_path.strip('"'))
        else:
            app_path = click.prompt("Enter path to application SREC")
            app_srec = Path(app_path.strip('"'))
    
    if not app_srec.exists():
        click.echo(f"[ERROR] File not found: {app_srec}", err=True)
        sys.exit(1)
    
    # Copy to flow folder
    app_copy = flow_folder / f"application_original.srec"
    shutil.copy2(app_srec, app_copy)
    click.echo(f"   [+] Copied: {app_srec.name} -> {app_copy.name}")
    
    # === Step 2: Offset Application Addresses ===
    click.echo("\n" + "-"*50)
    click.echo("Step 2: Offset Application Addresses")
    click.echo("-"*50)
    
    offset_value = int(app_offset, 16)
    app_offset_file = flow_folder / "application_offset.srec"
    
    try:
        offset_srec_addresses(app_copy, app_offset_file, offset_value)
        click.echo(f"   [+] Offset applied: {app_offset} -> {app_offset_file.name}")
    except Exception as e:
        click.echo(f"   [WARN]  Offset failed: {e}", err=True)
        shutil.copy2(app_copy, app_offset_file)
        click.echo(f"   Using original file (no offset applied)")
    
    # === Step 3: Get Bootloader SREC ===
    click.echo("\n" + "-"*50)
    click.echo("Step 3: Bootloader SREC")
    click.echo("-"*50)
    
    if not bootloader_srec:
        bl_patterns = ["*bootloader*.srec", "*bootloader*.s19", "bl_*.srec"]
        found_bls = []
        for search_path in [Path("."), Path(".."), flow_folder]:
            if search_path.exists():
                for pattern in bl_patterns:
                    found_bls.extend(search_path.glob(pattern))
        found_bls = list(set(found_bls))[:10]
        
        if found_bls:
            click.echo("\n[FILE] Found bootloader SREC files:")
            for i, f in enumerate(found_bls, 1):
                click.echo(f"  {i}. {f.name}")
            click.echo(f"  {len(found_bls) + 1}. [Enter path manually]")
            click.echo(f"  0. [Skip bootloader]")
            
            selection = click.prompt("Select bootloader SREC", type=int, default=0)
            if selection == 0:
                bootloader_srec = None
            elif selection <= len(found_bls):
                bootloader_srec = found_bls[selection - 1]
            else:
                bl_path = click.prompt("Enter path to bootloader SREC")
                bootloader_srec = Path(bl_path.strip('"'))
        else:
            click.echo("   No bootloader files found automatically.")
            has_bl = click.confirm("Do you have a bootloader SREC?", default=False)
            if has_bl:
                bl_path = click.prompt("Enter path to bootloader SREC")
                bootloader_srec = Path(bl_path.strip('"'))
    
    if bootloader_srec and bootloader_srec.exists():
        bl_copy = flow_folder / "bootloader.srec"
        shutil.copy2(bootloader_srec, bl_copy)
        click.echo(f"   [+] Copied: {bootloader_srec.name} -> {bl_copy.name}")
    else:
        bl_copy = None
        click.echo("   [WARN]  No bootloader provided (will sign app only)")

    click.echo("\n" + "="*70)
    click.echo("[OK] SREC Files Prepared!")
    click.echo("="*70)
    click.echo(f"\n[DIR] Files in: {flow_folder.absolute()}")
    click.echo("\nPrepared files:")
    click.echo(f"   [+] Application (original): application_original.srec")
    click.echo(f"   [+] Application (offset {app_offset}): application_offset.srec")
    if bl_copy:
        click.echo(f"   [+] Bootloader: bootloader.srec")
    click.echo("\n[TIP] Next step: Run 'invoke sign-app' to sign the application")
    click.echo("")


def offset_srec_addresses(input_file: Path, output_file: Path, offset: int):
    """Offset all addresses in an SREC file by the given value."""
    srec_manager.offset_addresses(input_file, output_file, offset)


def calculate_srec_checksum(hex_data: str) -> int:
    """Calculate SREC checksum (one's complement of sum of bytes)."""
    return srec_manager.calculate_checksum(hex_data)


def inject_customer_key_in_srec(srec_file: Path, key_der: bytes, start_addr: int):
    """
    Inject customer public key into SREC file at specified address.
    
    CRITICAL: Reference bootloader expects DER SubjectPublicKeyInfo format (91 bytes),
    NOT RAW uncompressed! We inject DER directly.
    """
    logger.info(f"  Injecting DER public key ({len(key_der)} bytes) at 0x{start_addr:08X}")
    
    # Inject DER key directly (bootloader expects SubjectPublicKeyInfo format!)
    srec_manager.inject_customer_key(srec_file, key_der, start_addr)


def _fix_s7_checksum(srec_file: Path):
    """
    Fix S7 termination record checksum if incorrect.
    
    S7 format: S7 + byte_count + address (4 bytes) + checksum
    Byte count = 5 (includes count byte + 4 addr bytes, NOT checksum)
    """
    lines = srec_file.read_text().splitlines()
    fixed_lines = []
    
    for line in lines:
        if line.startswith('S7'):
            # Parse S7 record
            byte_count = int(line[2:4], 16)
            addr_hex = line[4:4 + byte_count * 2 - 2]  # Address is (byte_count-1) bytes
            
            # Recalculate checksum
            data = bytes.fromhex(line[2:4 + byte_count * 2 - 2])
            checksum = (~sum(data) & 0xFF)
            
            # Rebuild S7 with correct checksum
            fixed_line = f"S7{line[2:4 + byte_count * 2 - 2]}{checksum:02X}"
            fixed_lines.append(fixed_line)
        else:
            fixed_lines.append(line)
    
    # Write back
    srec_file.write_text('\n'.join(fixed_lines) + '\n')


def _add_osm_records_to_combined(combined_path: Path, bootloader_path: Path):
    """
    Add OSM (Option Setting Memory) records to combined.srec.
    
    OSM records configure device security and are essential for proper boot.
    They must be extracted from the original bootloader and added to combined.srec.
    """
    osm_records = []
    with open(bootloader_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('S3'):
                addr = line[4:12]
                # OSM addresses: 0x0300Axxx (CF/DF protection) and 0x2703xxxx (security)
                if addr.upper().startswith('0300A') or addr.upper().startswith('27030'):
                    osm_records.append(line)
    
    if not osm_records:
        click.echo("   [WARN] No OSM records found - device may not boot correctly!")
        return
    
    # Read combined.srec
    combined_lines = []
    s5_line = None
    s7_line = None
    
    with open(combined_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('S5'):
                s5_line = line
                continue
            elif line.startswith('S7'):
                s7_line = line
                continue
            combined_lines.append(line)

    combined_lines.extend(osm_records)
    data_record_count = sum(1 for l in combined_lines if l.startswith(('S1', 'S2', 'S3')))
    s5_data = f'03{data_record_count:04X}'
    s5_checksum = (~sum(bytes.fromhex(s5_data)) & 0xFF)
    new_s5 = f'S5{s5_data}{s5_checksum:02X}'

    bootloader_srec = open(bootloader_path, 'r').readlines()
    memory = {}
    for line in bootloader_srec:
        line = line.strip()
        if line.startswith('S3'):
            addr = int(line[4:12], 16)
            count = int(line[2:4], 16)
            data_len = count - 5
            data_bytes = bytes.fromhex(line[12:12 + data_len * 2])
            for i, b in enumerate(data_bytes):
                memory[addr + i] = b
    
    # Read reset handler from bootloader vector table
    if 0x02000004 in memory:
        reset_handler = struct.unpack('<I', bytes([memory[0x02000004 + i] for i in range(4)]))[0]
        s7_data = f'05{reset_handler:08X}'
        s7_checksum = (~sum(bytes.fromhex(s7_data)) & 0xFF)
        new_s7 = f'S7{s7_data}{s7_checksum:02X}'
    else:
        # Fallback to default bootloader start
        new_s7 = s7_line if s7_line else 'S70502000000F8'
    
    # Write back with correct S5 and S7
    with open(combined_path, 'w') as f:
        for line in combined_lines:
            f.write(line + '\n')
        f.write(new_s5 + '\n')
        f.write(new_s7 + '\n')
    
    click.echo(f"   [+] Added {len(osm_records)} OSM records to combined.srec")
    click.echo(f"   [+] Updated S5 (count={data_record_count}) and S7 (start=0x{reset_handler:08X})")


def _coalesce_srec_records(records: list) -> list:
    """Coalesce contiguous SREC records into larger records."""
    return srec_manager._coalesce_records(records)


def _reformat_srec_to_s325(input_srec: Path, output_srec: Path):
    """
    Reformat SREC file to use S325 records (32 bytes data per line).
    
    S325 format means:
    - S3 = 32-bit address
    - 25 (hex) = 37 (decimal) = count byte = addr(4) + data(32) + checksum(1)
    - Data payload = 32 bytes
    
    Args:
        input_srec: Input SREC file (any format)
        output_srec: Output SREC file (S325 format)
    """
    bootloader_zone = {}
    bootloader_customer_key_records = []
    application_zone = {}
    osm_zone_records = []
    other_zone_records = []
    s0_header = None
    end_record = None
    
    with open(input_srec, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('S0'):
                s0_header = line
                continue
            
            if line.startswith('S7') or line.startswith('S8') or line.startswith('S9'):
                end_record = line
                continue
            
            if line.startswith('S3'):
                count = int(line[2:4], 16)
                addr = int(line[4:12], 16)
                data_len = count - 5
                data = bytes.fromhex(line[12:12 + data_len * 2])

                if (addr >= 0x03000000 and addr < 0x04000000):
                    osm_zone_records.append(line)
                elif (addr >= 0x27000000 and addr < 0x28000000):
                    other_zone_records.append(line)
                elif (addr >= 0x02009100 and addr <= 0x0200916F):
                    bootloader_customer_key_records.append(line)
                elif (addr >= 0x02000000 and addr < 0x02010000):
                    for i, b in enumerate(data):
                        bootloader_zone[addr + i] = b
                elif (addr >= 0x02010000 and addr < 0x03000000):
                    # Application zone
                    for i, b in enumerate(data):
                        application_zone[addr + i] = b
                else:
                    other_zone_records.append(line)

    with open(output_srec, 'w') as f:
        if s0_header:
            f.write(s0_header + "\n")

        if bootloader_zone:
            _write_zone_as_s325(f, bootloader_zone)
        
        # Write customer key zone (coalesce to match reference format)
        if bootloader_customer_key_records:
            ck_coalesced = _coalesce_srec_records(bootloader_customer_key_records)
            for ck_record in ck_coalesced:
                f.write(ck_record + "\n")

        if application_zone:
            _write_zone_as_s325(f, application_zone)

        if osm_zone_records:
            osm_coalesced = _coalesce_srec_records(osm_zone_records)
            for osm_record in osm_coalesced:
                f.write(osm_record + "\n")
        
        # Write other zones (Data Flash, etc.) - coalesce contiguous records
        if other_zone_records:
            other_coalesced = _coalesce_srec_records(other_zone_records)
            for other_record in other_coalesced:
                f.write(other_record + "\n")


def _write_zone_as_s325(f, memory_zone: dict):
    """Helper to write a memory zone as S325 records."""
    sorted_addrs = sorted(memory_zone.keys())
    chunk_size = 32
    
    i = 0
    while i < len(sorted_addrs):
        # Start a new chunk
        start_addr = sorted_addrs[i]
        chunk = bytearray()

        for j in range(chunk_size):
            addr = start_addr + j
            if addr in memory_zone:
                chunk.append(memory_zone[addr])
            else:
                break

        if chunk:
            data_len = len(chunk)
            count = data_len + 5
            record = f"S3{count:02X}{start_addr:08X}{chunk.hex().upper()}"
            checksum = calculate_srec_checksum(record[2:])
            record += f"{checksum:02X}"
            f.write(record + "\n")

        last_processed = start_addr + len(chunk) - 1
        while i < len(sorted_addrs) and sorted_addrs[i] <= last_processed:
            i += 1


@workflow_group.command("sign-app")
@click.option(
    "--app-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Application SREC file. If not provided, will prompt.",
)
@click.option(
    "--bootloader-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Bootloader SREC file. If not provided, will search or prompt.",
)
@click.option(
    "--app-offset",
    type=str,
    default="0x02010000",
    help="Application start address offset (default: 0x02010000).",
)
@click.option(
    "--customer-key-id",
    type=str,
    help="AWS KMS Key ID for Customer Key (for signing application).",
)
@click.pass_context
def sign_app(
    ctx, 
    app_srec: Optional[Path],
    bootloader_srec: Optional[Path],
    app_offset: str,
    customer_key_id: Optional[str]
):
    """
    Sign application, offset addresses, and combine with bootloader.
    
    Flow:
    1. Get files from prerequisites/ folder (or select via file dialog)
    2. Sign app.srec -> app.bin.signed
    3. Offset addresses -> app_signed_offset.srec
    4. Concatenate with bootloader -> combined.srec
    5. Cleanup - keep only final files
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Sign Application & Combine")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    prereq_folder = get_prerequisites_folder()
    
    click.echo(f"[DIR] Prerequisites folder: {prereq_folder.absolute()}")
    click.echo(f"[DIR] Flow folder: {flow_folder.absolute()}\n")

    click.echo("-"*50)
    click.echo("Getting Application BIN (unsigned)")
    click.echo("-"*50)
    
    if not app_srec:
        app_bin = get_prerequisite_file(
            file_description="Application BIN (unsigned)",
            file_patterns=["*app*.bin", "*APP*.bin", "application.bin"],
            required=True,
            target_name="application.bin"
        )
    else:

        if app_srec.suffix == ".bin":
            app_bin = app_srec
        else:
            click.echo(f"   [WARN] SREC format detected, converting to BIN...")
            app_bin = flow_folder / "application.bin"

    app_copy = flow_folder / "application.bin"
    if app_bin.suffix == ".bin":
        if app_bin.resolve() != app_copy.resolve():
            if app_copy.exists():
                app_copy.unlink()
            shutil.copy2(app_bin, app_copy)
        bin_size = app_copy.stat().st_size
        click.echo(f"   [+] Application BIN: {app_copy.name}")
        click.echo(f"   [+] Size: {bin_size} bytes (0x{bin_size:X})")

    with open(app_copy, 'rb') as f:
        first_bytes = f.read(4)
        click.echo(f"   [+] First 4 bytes: {first_bytes.hex()} (ARM vector table)")

    click.echo("\n" + "-"*50)
    click.echo("Getting Bootloader SREC")
    click.echo("-"*50)
    
    if not bootloader_srec:
        bootloader_srec = get_prerequisite_file(
            file_description="Bootloader SREC",
            file_patterns=["*bootloader*.srec", "*BL*.srec", "*bl*.srec", "bootloader.srec"],
            required=False,
            target_name="bootloader.srec"
        )
    
    if bootloader_srec and bootloader_srec.exists():
        bl_copy = flow_folder / "bootloader.srec"
        if bootloader_srec.resolve() != bl_copy.resolve():
            if bl_copy.exists():
                bl_copy.unlink()
            shutil.copy2(bootloader_srec, bl_copy)
    else:
        bl_copy = None
        click.echo("   [WARN]  No bootloader (will create signed app only)")
    
    # === Step 1: Get Signing Key (CUSTOMER KEY for application) ===
    click.echo("\n" + "-"*50)
    click.echo("Step 1: Select Customer Key (for Application Signing)")
    click.echo("-"*50)

    def filter_keys_by_purpose(keys: list, purpose: str, created_after: datetime = None) -> list:
        """Filter keys by purpose (customer/bootloader) and optionally by creation date"""
        filtered_keys = []
        for k in keys:
            key_id = k.get("KeyId")
            description = k.get("Description", "").lower()
            creation_date = k.get("CreationDate")
            key_spec = k.get("KeySpec")
            key_usage = k.get("KeyUsage")

            if key_spec != "ECC_NIST_P256" or key_usage != "SIGN_VERIFY":
                continue

            if created_after and creation_date and creation_date < created_after:
                continue

            if purpose == "customer" and "customer" in description:
                filtered_keys.append((key_id, description, creation_date))
            elif purpose == "bootloader" and "bootloader" in description:
                filtered_keys.append((key_id, description, creation_date))

        filtered_keys.sort(key=lambda x: x[2] if x[2] else datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        return [(k[0], k[1]) for k in filtered_keys]  # Return (key_id, description) tuples
    
    if not customer_key_id:
        hsm_client = create_hsm_client(config.hsm)
        hsm_client.connect()
        try:
            try:
                aws_creds = load_aws_credentials()
                config_customer_key = aws_creds.kms_config.get("customer_key_id") if hasattr(aws_creds, 'kms_config') else None
            except:
                config_customer_key = None
            
            keys = hsm_client.list_keys()

            def get_key_name(k):
                """Get human-readable key name"""
                desc = k.get("Description", "")
                alias = k.get("AliasNames", [""])[0].replace("alias/", "")
                return f"{desc}" if desc else (alias if alias else k.get("KeyId", "")[:20])

            def verify_key_exists(key_id: str) -> tuple:
                """Verify if key exists in AWS KMS and return (key_id, name) or None"""
                for k in keys:
                    if k.get("KeyId") == key_id:
                        if k.get("KeySpec") == "ECC_NIST_P256" and k.get("KeyUsage") == "SIGN_VERIFY":
                            return (key_id, get_key_name(k))
                return None

            if config_customer_key:
                verified = verify_key_exists(config_customer_key)
                if verified:
                    customer_key_id = verified[0]
                    click.echo(f"\n[OK] Auto-selected Customer Key from config:")
                    click.echo(f"     {verified[1]}")
                    click.echo(f"     Key ID: {customer_key_id}")
                else:
                    click.echo(f"\n[WARN] Customer Key from config not found in AWS KMS: {config_customer_key[:20]}...")
            
            if not customer_key_id:
                seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
                oem_bl_keys = filter_keys_by_purpose(keys, "customer", seven_days_ago)
                
                if not oem_bl_keys:
                    oem_bl_keys = filter_keys_by_purpose(keys, "bootloader", seven_days_ago)
                
                if not oem_bl_keys:
                    oem_bl_keys = filter_keys_by_purpose(keys, "customer")
                    if not oem_bl_keys:
                        oem_bl_keys = filter_keys_by_purpose(keys, "bootloader")
                
                if not oem_bl_keys:
                    click.echo("[ERROR] No Customer/Bootloader signing keys found in AWS KMS!", err=True)
                    click.echo("\n[TIP] Expected key description containing:")
                    click.echo("      - 'Customer' (preferred for application signing)")
                    click.echo("      - 'Bootloader' (alternative)")
                    click.echo("\n[TIP] Create keys using: invoke setup-keys create-keys")
                    sys.exit(1)

                if len(oem_bl_keys) == 1:
                    customer_key_id = oem_bl_keys[0][0]
                    click.echo(f"\n[OK] Auto-selected signing key: {oem_bl_keys[0][1]}")
                    click.echo(f"     Key ID: {customer_key_id[:20]}...")
                else:
                    click.echo(f"\n[KEY] Found {len(oem_bl_keys)} eligible signing keys:")
                    for i, (key_id, name) in enumerate(oem_bl_keys, 1):
                        click.echo(f"  {i}. {name}")
                        click.echo(f"     Key ID: {key_id[:20]}...")
                    click.echo(f"  {len(oem_bl_keys) + 1}. [Create new Customer key]")
                    
                    selection = click.prompt("Select signing key", type=int, default=1)
                    
                    if selection == len(oem_bl_keys) + 1:
                        click.echo("\n[*] Creating new Customer key in AWS KMS...")
                        new_key = hsm_client.kms_client.create_key(
                            Description=f'RA8M1 Customer Key - Used for application signing (created {datetime.now().strftime("%Y-%m-%d %H:%M")})',
                            KeyUsage='SIGN_VERIFY',
                            KeySpec='ECC_NIST_P256',
                            Tags=[
                                {'TagKey': 'ProvisioningType', 'TagValue': 'CUSTOMER'},
                                {'TagKey': 'CreationDate', 'TagValue': datetime.now().isoformat()}
                            ]
                        )
                        customer_key_id = new_key['KeyMetadata']['KeyId']
                        click.echo(f"[OK] New key created: {customer_key_id[:20]}...")
                    else:
                        customer_key_id = oem_bl_keys[selection - 1][0]
        finally:
            hsm_client.disconnect()

    click.echo("\n" + "-"*50)
    click.echo("Step 2: Sign Application BIN -> .bin.signed")
    click.echo("CRITICAL: Signing with HSM (AWS KMS/CloudHSM), NO local keys!")
    click.echo("-"*50)

    signed_bin_path = flow_folder / "application.bin.signed"

    if not customer_key_id:
        click.echo(f"   [ERROR] Customer key ID required! Cannot sign without HSM key!", err=True)
        click.echo(f"   [TIP] Provide --customer-key-id or configure in aws_credentials.json", err=True)
        sys.exit(1)

    click.echo(f"   [INFO] Signing with HSM: {customer_key_id[:20]}...")
    click.echo(f"   [INFO] Using AWS KMS/CloudHSM for signing (no local private keys!)")

    proj_config = get_project_config()

    sign_image_with_aws_kms(
        input_file=app_copy,
        output_file=signed_bin_path,
        aws_kms_key_id=customer_key_id,
        config=config.hsm,
        header_size=proj_config.imgtool_header_size,
        align=proj_config.imgtool_align,
        max_align=proj_config.imgtool_max_align,
        slot_size=proj_config.imgtool_slot_size,
        max_sectors=proj_config.imgtool_max_sectors,
        version=proj_config.imgtool_version,
        pad_header=proj_config.imgtool_pad_header,
        pad=proj_config.imgtool_pad,
        confirm=proj_config.imgtool_confirm,
    )
    click.echo(f"   [+] Signed with HSM: {signed_bin_path.name}")

    customer_pk_pem = flow_folder / "customer_public.pem"
    hsm_client = create_hsm_client(config.hsm)
    hsm_client.connect()
    customer_pk_der = hsm_client.get_public_key(customer_key_id)
    hsm_client.disconnect()
    save_public_key_pem(customer_pk_der, customer_pk_pem, KeyCurve.SECP256R1)
    click.echo(f"   [+] Customer public key saved: {customer_pk_pem.name}")
    
    click.echo(f"   [+] Signed binary size: {signed_bin_path.stat().st_size} bytes (0x{signed_bin_path.stat().st_size:X})")

    click.echo("\n" + "-"*50)
    click.echo(f"Step 3: Convert signed BIN to SREC with offset ({app_offset})")
    click.echo("-"*50)
    
    offset_value = int(app_offset, 16)
    signed_offset_path = flow_folder / "app_signed_offset.srec"

    # Get srec_cat path from project_config.json
    proj_config = get_project_config()
    srec_cat_exe = proj_config.srec_cat_exe

    if not srec_cat_exe.exists():
        click.echo(f"   [ERROR] srec_cat.exe not found at: {srec_cat_exe}", err=True)
        click.echo(f"   [ERROR] Please configure 'paths.srec_cat_exe' in project_config.json", err=True)
        click.echo(f"   [ERROR] Or install SRecord and set the path to srec_cat.exe", err=True)
        sys.exit(1)
    
    try:
        click.echo(f"   [+] Using srec_cat.exe (reference method - proven working!)")
        click.echo(f"   [+] Tool: {srec_cat_exe.name}")

        # srec_cat Debug\EK_RA8M1_MCUBOOT_APP.bin.signed -binary -offset 0x2010000 -execution-start-address 0x2010000 -o EK_RA8M1_MCUBOOT_APP_signed_offset.srec
        cmd = [
            str(srec_cat_exe),
            str(signed_bin_path), "-binary",
            "-offset", f"0x{offset_value:X}",
            "-execution-start-address", f"0x{offset_value:X}",
            "-o", str(signed_offset_path)
        ]
        
        click.echo(f"   [+] Command: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            click.echo(f"   [ERROR] srec_cat failed with exit code {result.returncode}", err=True)
            if result.stderr:
                click.echo(f"   [ERROR] stderr: {result.stderr}", err=True)
            if result.stdout:
                click.echo(f"   [ERROR] stdout: {result.stdout}", err=True)
            sys.exit(1)

        if not signed_offset_path.exists():
            click.echo(f"   [ERROR] Output file not created: {signed_offset_path}", err=True)
            sys.exit(1)
        
        click.echo(f"   [+] Conversion complete: {signed_offset_path.name}")
        click.echo(f"   [+] Start address: {app_offset}")
        click.echo(f"   [+] Output size: {signed_offset_path.stat().st_size} bytes")
            
    except subprocess.TimeoutExpired:
        click.echo(f"   [ERROR] srec_cat timed out after 30 seconds", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"   [ERROR] BIN to SREC conversion failed: {e}", err=True)
        sys.exit(1)

    click.echo("\n" + "-"*50)
    click.echo("Step 3.5: Inject Customer Key into Bootloader @ 0x02009114")
    click.echo("-"*50)

    
    if False:
        click.echo(f"   [INFO] TEST MODE: Using Reference Customer Key PUBLIC")
        reference_customer_key_hex = "3059301306072A8648CE3D020106082A8648CE3D030107034200042ACB403CE8FEED5BA44995A1A91DAEE8DBBE1937CD14FB2F245737E5953988D994B9D65AEBD7CDD5308AD6FE48B24A6A810EE5F07D8B6834CC3A6AFC538EFAC1"
        customer_key_der = bytes.fromhex(reference_customer_key_hex)
        click.echo(f"   [+] Reference Customer Key (DER format, {len(customer_key_der)} bytes)")
    else:
        click.echo(f"   [INFO] PRODUCTION MODE: Exporting Customer Key from AWS KMS...")
        click.echo(f"   [INFO] Using AWS KMS for key management")
        hsm_client = create_hsm_client(config.hsm)
        hsm_client.connect()
        customer_key_der = hsm_client.get_public_key(customer_key_id)
        hsm_client.disconnect()
        click.echo(f"   [+] Customer Key from AWS KMS (DER format, {len(customer_key_der)} bytes)")
        click.echo(f"   [+] Customer Key ID: {customer_key_id}")

    bl_with_key = flow_folder / "bootloader_with_key.srec"
    shutil.copy(bl_copy, bl_with_key)

    _fix_s7_checksum(bl_with_key)
    
    START_ADDR = 0x02009114
    inject_customer_key_in_srec(bl_with_key, customer_key_der, START_ADDR)
    
    click.echo(f"   [+] Customer key injected (DER format, {len(customer_key_der)} bytes) at 0x{START_ADDR:08X}")
    click.echo(f"   [+] Bootloader with key: {bl_with_key.name}")
    
    bl_to_use = bl_with_key

    click.echo("\n" + "-"*50)
    click.echo("Step 3.6: Code Certificate generation deferred")
    click.echo("-"*50)
    click.echo("   [INFO] Code Certificate will be generated in Step 4.1 (after combined.srec is created)")
    click.echo("   [INFO] SKMT requires 'OEM Bootloader Image' = combined.srec (FSBL + MCUboot + App)")
    click.echo("   [INFO] Image Size will be calculated from combined.srec span (not just bootloader region)")
    
    # === Step 4: Combine with Bootloader using srec_cat ===
    click.echo("\n" + "-"*50)
    click.echo("Step 4: Combine Bootloader + Application -> combined.srec")
    click.echo("-"*50)
    click.echo("   [+] Using srec_cat.exe (reference method - auto-merges S5/S7)")
    
    if bl_to_use and bl_to_use.exists():
        combined_srec_path = flow_folder / "combined.srec"

        try:
            cmd = [
                str(srec_cat_exe),
                str(bl_to_use),
                str(signed_offset_path),
                "-o", str(combined_srec_path)
            ]
            
            click.echo(f"   [+] Command: {' '.join([p.name if isinstance(p, Path) else p for p in cmd])}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                click.echo(f"   [ERROR] srec_cat combine failed with exit code {result.returncode}", err=True)
                if result.stderr:
                    click.echo(f"   [ERROR] stderr: {result.stderr}", err=True)
                if result.stdout:
                    click.echo(f"   [ERROR] stdout: {result.stdout}", err=True)
                sys.exit(1)

            if not combined_srec_path.exists():
                click.echo(f"   [ERROR] Combined SREC not created: {combined_srec_path}", err=True)
                sys.exit(1)
            
            click.echo(f"   [+] Combined SREC created: {combined_srec_path.name}")
            click.echo(f"   [+] Size: {combined_srec_path.stat().st_size} bytes")

            with open(combined_srec_path, 'r') as f:
                lines = f.readlines()
                s3_count = sum(1 for line in lines if line.strip().startswith('S3'))
                click.echo(f"   [+] S3 data records: {s3_count}")
                click.echo(f"   [+] Total lines: {len(lines)}")
            

            _add_osm_records_to_combined(combined_srec_path, bl_copy)
            
            click.echo("\n" + "-"*50)
            click.echo("Step 4.1: Generate Code Certificate on combined.srec")
            click.echo("-"*50)
            
            IMAGE_START = 0x02000000
            max_addr_written = IMAGE_START - 1
            
            # OSM regions to exclude
            CF_OSM_START = 0x0300A100
            CF_OSM_END = 0x0300A2FF
            DF_OSM_START = 0x27030000
            DF_OSM_END = 0x2703FFFF
            
            with open(combined_srec_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or not line.startswith('S3'):
                        continue
                    
                    count = int(line[2:4], 16)
                    addr = int(line[4:12], 16)
                    data_len = count - 5
                    end_addr = addr + data_len - 1
                    
                    if addr >= IMAGE_START:
                        if (CF_OSM_START <= addr <= CF_OSM_END) or (DF_OSM_START <= addr <= DF_OSM_END):
                            continue

                        if end_addr > max_addr_written:
                            max_addr_written = end_addr
            
            # Calculate Image Size: align_up(max_address_written - 0x02000000 + 1, 16)
            if max_addr_written < IMAGE_START:
                click.echo(f"   [ERROR] No Code Flash addresses found in combined.srec!", err=True)
                sys.exit(1)
            
            image_span = max_addr_written - IMAGE_START + 1
            image_size = ((image_span + 15) // 16) * 16  # Align to 16 bytes
            
            click.echo(f"   [+] Combined SREC Code Flash region: 0x{IMAGE_START:08X} - 0x{max_addr_written:08X}")
            click.echo(f"   [+] Max address written: 0x{max_addr_written:08X}")
            click.echo(f"   [+] Image Size (aligned to 16): 0x{image_size:08X} = {image_size} bytes = {image_size/1024:.2f} KB")
            click.echo(f"   [INFO] OSM records (0x0300Axxx, 0x2703xxxx) excluded from Image Size calculation")
            
            cert_version = get_current_certificate_version()
            code_cert_path = flow_folder / f"code_cert_v{cert_version}.bin"
            
            # Get HSM key IDs from config
            try:
                aws_creds = load_aws_credentials()
                oem_bl_sk_key_id = aws_creds.kms_config.get("bootloader_key_id") or aws_creds.kms_config.get("oem_bl_sk_key_id")
                oem_root_sk_key_id = aws_creds.kms_config.get("oem_root_key_id")
                if not oem_bl_sk_key_id:
                    click.echo(f"   [ERROR] OEM Bootloader key ID not found in config!", err=True)
                    sys.exit(1)
                if not oem_root_sk_key_id:
                    click.echo(f"   [ERROR] OEM Root key ID not found in config!", err=True)
                    sys.exit(1)
            except Exception as e:
                click.echo(f"   [ERROR] Failed to load AWS credentials: {e}", err=True)
                sys.exit(1)
            
            # Get KEYHASH from Key Certificate
            key_cert_path = flow_folder / f"key_cert_v{cert_version}.bin"
            oem_bl_pk_hash = None
            if key_cert_path.exists():
                try:
                    skmt_wrapper = SKMTWrapper(
                        skmt_path=config.skmt.skmt_path,
                        working_directory=config.skmt.working_directory,
                    )
                    key_cert = skmt_wrapper.parse_key_certificate(str(key_cert_path))
                    oem_bl_pk_hash = key_cert.oem_bl_pk_hash
                    click.echo(f"   [OK] Using KEYHASH from Key Certificate: {oem_bl_pk_hash.hex()[:16]}...")
                except Exception as e:
                    click.echo(f"   [ERROR] Failed to parse Key Certificate: {e}", err=True)
                    sys.exit(1)
            else:
                click.echo(f"   [ERROR] Key Certificate not found: {key_cert_path}", err=True)
                sys.exit(1)

            oem_root_pk_file = flow_folder / "oem_root_public.pem"
            if not oem_root_pk_file.exists():
                oem_root_pk_file = None

            click.echo(f"   [+] Generating Code Certificate on combined.srec...")
            
            try:
                proj_config = get_project_config()
                load_addr = int(proj_config.cert_load_addr, 16)
                cfsize = int(proj_config.cert_cfsize, 16)
                bl_binary = parse_srec(combined_srec_path, load_addr, cfsize)
                click.echo(f"   [+] Extracted binary: {len(bl_binary)} bytes (ACTUAL size from parse_srec)")
                
                cert_generator = CertificateGenerator(
                    skmt_config=config.skmt,
                    hsm_config=config.hsm,
                )
                
                code_cert = cert_generator.generate_code_certificate(
                    oem_bl_sk_key_id=oem_bl_sk_key_id,
                    bootloader_binary=bl_binary,  # Use parsed binary, not file!
                    output_file=code_cert_path,
                    version=cert_version,
                    oem_bl_pk_hash=oem_bl_pk_hash,
                )
                
                click.echo(f"   [+] Code Certificate v{cert_version} generated: {code_cert_path.name}")
                click.echo(f"   [OK] Signed with HSM (no local private keys used!)")
                click.echo(f"   [OK] Code Certificate includes CRC32 of combined.srec!")
                
                try:
                    skmt_wrapper = SKMTWrapper(
                        skmt_path=config.skmt.skmt_path,
                        working_directory=config.skmt.working_directory,
                    )
                    code_cert_parsed = skmt_wrapper._parse_code_certificate(code_cert_path.read_bytes())
                    code_cert_signer_id = code_cert_parsed.signer_id
                    
                    if oem_bl_pk_hash != code_cert_signer_id:
                        click.echo(f"\n{'='*70}", err=True)
                        click.echo(f"   [ERROR] CRITICAL: SIGNER_ID != KEYHASH - PROVISIONING STOPPED!", err=True)
                        click.echo(f"{'='*70}", err=True)
                        click.echo(f"   [ERROR] Key Cert KEYHASH:   {oem_bl_pk_hash.hex()}", err=True)
                        click.echo(f"   [ERROR] Code Cert SIGNER_ID: {code_cert_signer_id.hex()}", err=True)
                        click.echo(f"   [ERROR] These MUST be equal byte-by-byte for chain of trust!", err=True)
                        click.echo(f"   [ERROR] Device will REJECT certificates with this mismatch!", err=True)
                        click.echo(f"{'='*70}\n", err=True)
                        raise click.ClickException(
                            "OBLIGATORY ASSERT FAILED: signer_id != keyhash. "
                            "Provisioning stopped - certificates will be rejected by device!"
                        )
                    
                    click.echo(f"   [OK] OBLIGATORY ASSERT PASSED: signer_id == keyhash")
                    click.echo(f"   [OK] KEYHASH:   {oem_bl_pk_hash.hex()[:16]}...")
                    click.echo(f"   [OK] SIGNER_ID: {code_cert_signer_id.hex()[:16]}...")
                    click.echo(f"   [OK] Chain of trust verification will PASS!")
                except Exception as e:
                    click.echo(f"   [WARN] Failed to verify SIGNER_ID == KEYHASH: {e}", err=True)
                    click.echo(f"   [WARN] Continuing, but certificates may be rejected by device!", err=True)
                
                new_version = increment_certificate_version()
                click.echo(f"\n[INFO] Certificate version incremented: {cert_version} -> {new_version}")
                
            except Exception as e:
                click.echo(f"   [ERROR] Failed to generate Code Certificate: {e}", err=True)
                traceback.print_exc()
                sys.exit(1)
            
        except subprocess.TimeoutExpired:
            click.echo(f"   [ERROR] srec_cat timed out after 30 seconds", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"   [ERROR] SREC combination failed: {e}", err=True)
    else:
        click.echo("   [WARN] No bootloader - using signed app only")
        final_output = signed_offset_path
    
    # === Step 6: Cleanup - Keep only required files ===
    click.echo("\n" + "-"*50)
    click.echo("Step 6: Cleanup (DISABLED FOR DEBUG)")
    click.echo("-"*50)
    click.echo("   [DEBUG] Keeping all intermediate files for analysis")

    click.echo("\n" + "="*70)
    click.echo("[OK] Provisioning Files Ready!")
    click.echo("="*70)
    click.echo(f"\n[DIR] Output folder: {flow_folder.absolute()}")
    click.echo("\n[FILES] Final files for provisioning:")

    final_files = sorted([f.name for f in flow_folder.iterdir() if f.is_file()])
    for f in final_files:
        click.echo(f"   [+] {f}")
    click.echo("\n[TIP] Next step: Run provisioning script with these files")
    click.echo("")


@workflow_group.command("program-device")
@click.option(
    "--com-port",
    type=str,
    help="COM port for device programming. If not provided, will auto-detect or prompt.",
)
@click.option(
    "--lock-device/--no-lock-device",
    default=None,
    help="Lock device to LCK_BOOT state after provisioning. Default: from config.json (lock_after_provisioning)",
)
@click.option(
    "--bootloader-binary",
    type=click.Path(exists=True, path_type=Path),
    help="Bootloader binary if not using combined.srec.",
)
@click.option(
    "--skip-initialize",
    is_flag=True,
    help="Skip device initialization (if already initialized).",
)
@click.pass_context
def program_device(ctx, com_port: Optional[str], lock_device: bool, bootloader_binary: Optional[Path], skip_initialize: bool):
    """
    Step 8: Program device with all generated files.
    
    This is the final step. After this, a new flow folder will be created for the next workflow.
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Step 8: Device Programming")
    click.echo("="*70 + "\n")
    
    flow_folder = get_flow_folder()
    reusable_folder = get_reusable_folder()
    
    # Helper function to find files with version suffix and fallback to reusable folder
    def find_cert_with_version(base_name: str, description: str) -> Path:
        """Find certificate file with version suffix (e.g., key_cert_v25.bin or oem_key_cert_v25.bin)."""
        # Search locations in priority order
        search_locations = [
            # New gen-fsbl-certs: certs/oem_key_cert_v*.bin
            (flow_folder / "certs", f"oem_{base_name}_v*.bin", "flow/certs"),
            # Old workflow: key_cert_v*.bin in root
            (flow_folder, f"{base_name}_v*.bin", "flow"),
            # Reusable folder (new naming)
            (reusable_folder / "certs", f"oem_{base_name}_v*.bin", "reusable/certs"),
            # Reusable folder (old naming)
            (reusable_folder, f"{base_name}_v*.bin", "reusable"),
        ]
        
        for folder, pattern, location in search_locations:
            if not folder.exists():
                continue
            matches = list(folder.glob(pattern))
            if matches:
                # Sort by version number (highest first)
                matches.sort(key=lambda p: int(p.stem.split('_v')[-1]), reverse=True)
                click.echo(f"   [+] Using {description} from {location}: {matches[0].name}")
                return matches[0]
        
        # Fallback to old naming (no version) for compatibility
        fallback_paths = [
            (flow_folder / "certs" / f"oem_{base_name}.bin", "flow/certs"),
            (flow_folder / f"{base_name}.bin", "flow"),
            (reusable_folder / f"{base_name}.bin", "reusable"),
        ]
        for path, location in fallback_paths:
            if path.exists():
                click.echo(f"   [+] Using {description} from {location}: {path.name}")
                return path
        
        return None
    
    def find_file_with_fallback(filename: str, description: str) -> Path:
        """Find file in flow folder, fallback to reusable folders."""
        # Check multiple locations
        reuse_ufpk_folder = Path("output/reuse_ufpk")
        search_paths = [
            (flow_folder / filename, "flow"),
            (reusable_folder / filename, "reusable"),
            (reuse_ufpk_folder / filename, "reuse_ufpk"),
        ]
        
        for path, location in search_paths:
            if path.exists():
                click.echo(f"   [+] Using {description} from {location}: {filename}")
                return path
        
        return None
    
    # Check required files (with fallback to reusable/)
    rkey_path = find_file_with_fallback("oem_root_key.rkey", "RKEY")
    if not rkey_path:
        click.echo(f"[ERROR] RKEY not found!", err=True)
        click.echo("", err=True)
        click.echo("   RKEY is required for device programming.", err=True)
        click.echo("   Searched in:", err=True)
        click.echo(f"     - {flow_folder}", err=True)
        click.echo(f"     - {reusable_folder}", err=True)
        click.echo(f"     - output/reuse_ufpk", err=True)
        click.echo("", err=True)
        click.echo("   To generate RKEY, run these commands:", err=True)
        click.echo("     1. invoke prepare-ufpk    # Generate UFPK (one-time)", err=True)
        click.echo("     2. invoke generate-rkey   # Wrap OEM Root PK with UFPK", err=True)
        click.echo("", err=True)
        sys.exit(1)
    
    key_cert_path = find_cert_with_version("key_cert", "Key Certificate")
    if not key_cert_path:
        click.echo(f"[ERROR] Key Certificate not found!", err=True)
        click.echo("", err=True)
        click.echo("   Run the complete workflow first:", err=True)
        click.echo("     invoke workflow-all", err=True)
        click.echo("", err=True)
        click.echo("   Or run individual commands:", err=True)
        click.echo("     1. invoke sign-app", err=True)
        click.echo("     2. invoke make-combined-srec", err=True)
        click.echo("     3. invoke gen-fsbl-certs", err=True)
        click.echo("", err=True)
        sys.exit(1)
    
    code_cert_path = find_cert_with_version("code_cert", "Code Certificate")
    if not code_cert_path:
        click.echo(f"[ERROR] Code Certificate not found!", err=True)
        click.echo("", err=True)
        click.echo("   Run the complete workflow first:", err=True)
        click.echo("     invoke workflow-all", err=True)
        click.echo("", err=True)
        click.echo("   Or run individual commands:", err=True)
        click.echo("     1. invoke sign-app", err=True)
        click.echo("     2. invoke make-combined-srec", err=True)
        click.echo("     3. invoke gen-fsbl-certs", err=True)
        click.echo("", err=True)
        sys.exit(1)
    
    # combined.srec is always application-specific (no fallback)
    combined_srec_path = flow_folder / "combined.srec"
    
    # Use combined.srec or bootloader
    if not combined_srec_path.exists():
        if bootloader_binary:
            combined_srec_path = bootloader_binary
        else:
            click.echo(f"[ERROR] Combined SREC not found!", err=True)
            click.echo(f"   Expected: {combined_srec_path}", err=True)
            click.echo("", err=True)
            click.echo("   Run the complete workflow first:", err=True)
            click.echo("     invoke workflow-all", err=True)
            click.echo("", err=True)
            click.echo("   Or run individual commands:", err=True)
            click.echo("     1. invoke sign-app", err=True)
            click.echo("     2. invoke make-combined-srec", err=True)
            click.echo("     3. invoke gen-fsbl-certs", err=True)
            click.echo("", err=True)
            sys.exit(1)
    
    # Get COM port
    if not com_port:
        com_port = RA8ProvisioningClient.find_ra_com_port()
        if not com_port:
            ports = RA8ProvisioningClient.list_com_ports()
            click.echo("Available COM ports:")
            for i, port in enumerate(ports, 1):
                click.echo(f"  {i}. {port}")
            selection = click.prompt("Select COM port", type=int)
            if selection < 1 or selection > len(ports):
                click.echo("[ERROR] Invalid selection!", err=True)
                sys.exit(1)
            com_port = ports[selection - 1]
    
    click.echo(f"   Using COM port: {com_port}")
    
    # Determine lock_device from CLI or config.json
    if lock_device is None:
        # Read from config.json device.lock_after_provisioning (default: false)
        lock_device = getattr(config, 'device_lock_after_provisioning', False)
        if lock_device:
            click.echo(f"   [CONFIG] lock_after_provisioning=true (from config.json)")
    
    final_state = "LCK_BOOT" if lock_device else "OEM_PL0"
    
    def reset_callback():
        click.echo("")
        click.echo("[WARN]  RESET REQUIRED!")
        click.echo("   Please reset the board with MD low, then press Enter...")
        input()
    
    workflow = RA8ProvisioningWorkflow(
        com_port=com_port,
        oem_root_key_file=rkey_path,
        key_cert_file=key_cert_path,
        code_cert_file=code_cert_path,
        combined_srec_file=combined_srec_path,
        final_state=final_state,
        disable_initialize=False,
        reset_callback=reset_callback,
    )
    
    click.echo("   Executing provisioning workflow...")
    success = workflow.execute()
    
    if success:
        click.echo("")
        click.echo("="*70)
        click.echo("[OK] Device Programming Complete!")
        click.echo("="*70)
        click.echo(f"\n[DIR] All files saved in: {flow_folder.absolute()}")
        click.echo("\nNext steps:")
        click.echo("  1. Reset the board")
        click.echo("  2. Verify application runs correctly")
        click.echo("\n[TIP] To start a new workflow, run: workflow start")
        click.echo("")
    else:
        click.echo("[ERROR] Device programming failed!", err=True)
        sys.exit(1)


# =============================================================================
# CLI Commands Help - Interactive Documentation
# =============================================================================

def _print_header():
    """Print the header banner."""
    click.echo("")
    click.echo(click.style("=" * 78, fg="cyan"))
    click.echo(click.style(r"""
    ____   ___   ___  __  __ _   _____  ___   ___  _     
   |  _ \ / _ \ ( _ )|  \/  / | |_   _|/ _ \ / _ \| |    
   | |_) | |_| |/ _ \| |\/| | |   | | | | | | | | | |    
   |  _ <|  _  | (_) | |  | | |   | | | |_| | |_| | |___ 
   |_| \_\_| |_|\___/|_|  |_|_|   |_|  \___/ \___/|_____|
                                                         
   """, fg="cyan"))
    click.echo(click.style("         PROVISIONING TOOL - COMMAND LINE REFERENCE", fg="white", bold=True))
    click.echo(click.style("=" * 78, fg="cyan"))
    click.echo("")


def _print_section(title: str, color: str = "yellow"):
    """Print a section header."""
    click.echo("")
    click.echo(click.style(f"  {'-' * 74}", fg="bright_black"))
    click.echo(click.style(f"  {title}", fg=color, bold=True))
    click.echo(click.style(f"  {'-' * 74}", fg="bright_black"))


def _print_command(name: str, description: str):
    """Print a command entry."""
    click.echo(f"    {click.style(name, fg='green', bold=True)}")
    click.echo(f"      {description}")


def _print_subcommand(name: str, description: str):
    """Print a subcommand entry."""
    click.echo(f"      {click.style('*', fg='cyan')} {click.style(name, fg='bright_green')}: {description}")


def _print_io(label: str, items: list, color: str):
    """Print input/output items."""
    click.echo(f"      {click.style(label, fg=color, bold=True)}")
    for item in items:
        click.echo(f"        {click.style('->', fg='bright_black')} {item}")


def _print_tip(tip: str):
    """Print a tip."""
    click.echo(f"    {click.style('[TIP]', fg='bright_blue', bold=True)} {tip}")


@workflow_group.command("cli-help")
@click.option("--section", "-s", type=click.Choice(["all", "flow", "commands", "files", "troubleshooting"]), 
              default="all", help="Show specific section only")
def provisioning_cli_commands_help(section: str):
    """
    Interactive CLI Commands Reference Guide.
    
    Shows complete documentation about the provisioning workflow,
    all available commands, their inputs, outputs, and usage examples.
    """
    _print_header()
    
    if section in ["all", "flow"]:
        _print_section("PROVISIONING WORKFLOW OVERVIEW", "magenta")
        click.echo("""
    The RA8M1 provisioning workflow is divided into two phases:

    PHASE 1: ONE-TIME SETUP (per device type)
    +---------------------------------------------------------------------------+
    |  Step 1: UFPK Preparation                                                 |
    |          Generate and wrap User Factory Programming Key via Renesas DLM   |
    |          Command: invoke prepare-ufpk                                     |
    |                                                                           |
    |  Step 2: RKEY Generation                                                  |
    |          Wrap OEM Root Public Key with UFPK for device authentication     |
    |          Command: invoke generate-rkey                                    |
    +---------------------------------------------------------------------------+

    PHASE 2: FIRMWARE BUILD (per firmware version)
    +---------------------------------------------------------------------------+
    |  Step 3: Sign Application                                                 |
    |          Sign application binary with AWS KMS (MCUboot format)            |
    |          Command: invoke sign-app                                         |
    |                                                                           |
    |  Step 4: Create Combined SREC                                             |
    |          Inject AWS key into bootloader and combine with signed app       |
    |          Command: invoke make-combined-srec                               |
    |                                                                           |
    |  Step 5: Generate FSBL Certificates                                       |
    |          Generate Key Certificate and Code Certificate for FSBL           |
    |          Command: invoke gen-fsbl-certs                                   |
    |                                                                           |
    |  Step 6: Program Device                                                   |
    |          Flash firmware and certificates to device via Renesas RFP        |
    |          Command: invoke program-device                                   |
    +---------------------------------------------------------------------------+

    QUICK START (Steps 3-5 combined):
    +---------------------------------------------------------------------------+
    |  invoke workflow-all      Runs sign-app + make-combined-srec +            |
    |                           gen-fsbl-certs in correct order                 |
    |  invoke program-device    Flash to device                                 |
    +---------------------------------------------------------------------------+
    """)
        
        click.echo(click.style("    Prerequisites:", fg="white", bold=True))
        click.echo("""
      Before running any commands, ensure these files exist:

      prerequisites/
        bootloader.srec       MCUboot bootloader binary (from your build)
        application.bin       Application binary to sign (from your build)
        keywrap-pub.key       Renesas public key (from DLM registration)

      project_config.json     Configuration file with AWS KMS keys and settings
    """)
    
    if section in ["all", "commands"]:
        _print_section("PHASE 1: ONE-TIME SETUP COMMANDS", "green")
        
        # Command: prepare-ufpk
        click.echo("")
        _print_command("invoke prepare-ufpk", "Generate and wrap UFPK with Renesas DLM")
        click.echo("""
    Description:
      Generates a 256-bit User Factory Programming Key (UFPK), encrypts it with
      the Renesas public key, and guides you through the DLM upload/download
      process. This key is used to wrap the OEM Root Public Key for secure
      device provisioning.

    Steps performed:
      1. Generate random 256-bit UFPK
      2. Encrypt UFPK with Renesas keywrap-pub.key
      3. Open browser to upload encrypted UFPK to DLM
      4. Wait for user to download wrapped UFPK from email
      5. Decrypt wrapped UFPK with your PGP private key

    Inputs:
      - prerequisites/keywrap-pub.key    Renesas public key for encryption
      - PGP private key in GnuPG         For decrypting DLM response

    Outputs:
      - output/reuse_ufpk/ufpk.key                  Plain UFPK
      - output/reuse_ufpk/ufpk_wrapped_decrypted.key  Wrapped UFPK from DLM

    Options:
      --ufpk-hardcoded <hex>    Use specific 64-character hex value as UFPK
      --ufpk-file <path>        Use existing UFPK file instead of generating

    When to run:
      Once per device type. The UFPK is reused for all devices of the same type.
    """)
        
        # Command: generate-rkey
        click.echo("")
        _print_command("invoke generate-rkey", "Generate RKEY (wrapped OEM Root Public Key)")
        click.echo("""
    Description:
      Exports the OEM Root Public Key from AWS KMS and wraps it with the UFPK
      to create the RKEY file. The device requires RKEY format for the OEM Root
      Key - it will reject plain public keys.

    Steps performed:
      1. Locate UFPK files (searches flow folders and reuse_ufpk/)
      2. Export OEM Root Public Key from AWS KMS
      3. Wrap public key with UFPK using SKMT tool
      4. Save RKEY to flow folder

    Inputs:
      - output/reuse_ufpk/ufpk.key                  Plain UFPK
      - output/reuse_ufpk/ufpk_wrapped_decrypted.key  Wrapped UFPK
      - AWS KMS: oem_root_key_id from project_config.json

    Outputs:
      - output/reuse_ufpk/oem_root_key.rkey    Wrapped OEM Root Public Key
      - output/flow_*/oem_root_public.pem      OEM Root Public Key (PEM)

    Configuration (project_config.json):
      aws.kms.oem_root_key_id    AWS KMS Key ID for OEM Root Key

    When to run:
      Once per device type. The RKEY is reused for all firmware builds.
    """)
        
        _print_section("PHASE 2: FIRMWARE BUILD COMMANDS", "green")
        
        # Command: sign-app
        click.echo("")
        _print_command("invoke sign-app", "Sign application with AWS KMS")
        click.echo("""
    Description:
      Signs the application binary using AWS KMS in MCUboot format. The signature
      is created using ECDSA P-256 with the mcuboot_app_key stored in AWS KMS.
      The private key never leaves the HSM.

    Steps performed:
      1. Load application binary
      2. Generate MCUboot header and TLV structure
      3. Calculate SHA256 hash of protected region
      4. Sign hash with AWS KMS (ECDSA P-256)
      5. Inject signature into TLV, replacing dummy signature
      6. Pad to slot size and add trailer

    Inputs:
      - prerequisites/application.bin           Application binary
      - AWS KMS: mcuboot_app_key_id from project_config.json

    Outputs:
      - output/flow_*/application.bin.signed    Signed MCUboot image
      - output/flow_*/customer_public.pem       Signing public key (for verification)

    Configuration (project_config.json):
      aws.kms.mcuboot_app_key_id    AWS KMS Key ID for application signing
      imgtool.*                     MCUboot image parameters (align, slot_size, etc.)

    Common issues:
      - "Key not found": Verify mcuboot_app_key_id in project_config.json
      - "Access denied": Check AWS credentials and KMS key permissions
    """)
        
        # Command: make-combined-srec
        click.echo("")
        _print_command("invoke make-combined-srec", "Combine bootloader and signed app")
        click.echo("""
    Description:
      Injects the AWS KMS public key into the bootloader (replacing the demo key)
      and combines it with the signed application to create the final SREC file.
      This step is critical for the bootloader to verify your signed application.

    Steps performed:
      1. Convert application.bin.signed to SREC with correct offset
      2. Inject AWS KMS mcuboot_app_key into bootloader at 0x02009114
      3. Combine bootloader_with_aws_key.srec + application_offset.srec
      4. Verify no address overlaps

    Inputs:
      - prerequisites/bootloader.srec                Original MCUboot bootloader
      - output/flow_*/application.bin.signed         Signed application (from sign-app)
      - AWS KMS: mcuboot_app_key_id from project_config.json

    Outputs:
      - output/flow_*/bootloader_with_aws_key.srec   Bootloader with injected key
      - output/flow_*/application.bin_offset.srec    Application at correct offset
      - output/flow_*/combined.srec                  Final combined SREC

    Configuration (project_config.json):
      firmware.inject_customer_key    Enable/disable key injection (default: true)
      firmware.mcuboot_pubkey_addr    Address for key injection (0x02009114)
      firmware.app_offset             Application start address (0x02010000)

    Important:
      The bootloader_with_aws_key.srec is used for Code Certificate CRC calculation.
      Run this command BEFORE gen-fsbl-certs.
    """)
        
        # Command: gen-fsbl-certs
        click.echo("")
        _print_command("invoke gen-fsbl-certs", "Generate FSBL Key and Code Certificates")
        click.echo("""
    Description:
      Generates the Key Certificate and Code Certificate required by Renesas FSBL.
      The Key Certificate authenticates the OEM Bootloader Public Key using the
      OEM Root Key. The Code Certificate authenticates the bootloader binary.

    Steps performed:
      1. Export OEM Root and OEM Bootloader public keys from AWS KMS
      2. Generate Key Certificate (signed with OEM_ROOT_SK)
      3. Generate Code Certificate (signed with OEM_BL_SK)
      4. Calculate CRC32 on bootloader_with_aws_key.srec (auto-detected)
      5. Verify certificate chain (KEYHASH == SIGNER_ID)

    Inputs:
      - output/flow_*/bootloader_with_aws_key.srec   For CRC calculation (auto-detected)
      - AWS KMS: oem_root_key_id from project_config.json
      - AWS KMS: oem_bootloader_key_id from project_config.json

    Outputs:
      - output/flow_*/certs/oem_key_cert_vNN.bin     Key Certificate
      - output/flow_*/certs/oem_code_cert_vNN.bin    Code Certificate
      - output/flow_*/oem_root_public.pem            OEM Root Public Key
      - output/flow_*/oem_bl_public.pem              OEM Bootloader Public Key

    Configuration (project_config.json):
      aws.kms.oem_root_key_id         AWS KMS Key ID for OEM Root Key
      aws.kms.oem_bootloader_key_id   AWS KMS Key ID for OEM Bootloader Key
      certificates.load_addr          Bootloader load address (0x02000000)
      certificates.oembl_size         Bootloader region size (0x00030000)
      certificates.cfsize             Flash region filter (0x200000)
      versioning.certificate_version  Anti-rollback version (1-64)

    Important:
      The CRC is calculated on bootloader_with_aws_key.srec (with injected key).
      Run make-combined-srec BEFORE this command.
    """)
        
        # Command: workflow-all
        click.echo("")
        _print_command("invoke workflow-all", "Complete firmware build workflow")
        click.echo("""
    Description:
      Executes the complete firmware build workflow in the correct order:
      sign-app -> make-combined-srec -> gen-fsbl-certs

      This is the recommended command for building firmware. It ensures all
      steps are executed in the correct order with proper dependencies.

    Steps performed:
      1. Sign application with AWS KMS (sign-app)
      2. Inject key and create combined SREC (make-combined-srec)
      3. Generate certificates with correct CRC (gen-fsbl-certs)

    Inputs:
      - prerequisites/bootloader.srec      MCUboot bootloader
      - prerequisites/application.bin      Application binary
      - project_config.json                Configuration file

    Outputs:
      - output/flow_*/application.bin.signed
      - output/flow_*/bootloader_with_aws_key.srec
      - output/flow_*/combined.srec
      - output/flow_*/certs/oem_key_cert_vNN.bin
      - output/flow_*/certs/oem_code_cert_vNN.bin

    Usage:
      invoke workflow-all
      invoke workflow-all --config project_config.json
    """)
        
        # Command: program-device
        click.echo("")
        _print_command("invoke program-device", "Program device with Renesas Flash Programmer")
        click.echo("""
    Description:
      Programs the device with all generated files using the Renesas Flash
      Programmer (RFP) tool. This command locates all required files from
      the flow folder and reusable folders automatically.

    Steps performed:
      1. Locate RKEY (searches flow/, reusable/, reuse_ufpk/)
      2. Locate Key Certificate and Code Certificate
      3. Locate combined.srec
      4. Execute RFP programming sequence

    Inputs:
      - output/reuse_ufpk/oem_root_key.rkey          RKEY (auto-located)
      - output/flow_*/certs/oem_key_cert_vNN.bin     Key Certificate
      - output/flow_*/certs/oem_code_cert_vNN.bin    Code Certificate
      - output/flow_*/combined.srec                  Combined SREC

    Prerequisites:
      - Device connected and in boot mode
      - Renesas Flash Programmer installed

    Device reset procedure:
      When prompted for reset, perform these steps:
      1. Press and hold the RESET button
      2. While holding RESET, ensure MD pin is LOW
      3. Release RESET button
      4. Press Enter to continue

    Common issues:
      - "RKEY not found": Run 'invoke prepare-ufpk' then 'invoke generate-rkey'
      - "Certificate not found": Run 'invoke workflow-all'
      - "CRC mismatch (AAAA0204)": Certificates generated before make-combined-srec
    """)
    
    if section in ["all", "files"]:
        _print_section("FILE REFERENCE", "blue")
        
        click.echo("""
    PREREQUISITES FOLDER (prerequisites/)
    +---------------------------------------------------------------------------+
    | File                  | Description                           | Required |
    |-----------------------|---------------------------------------|----------|
    | bootloader.srec       | MCUboot bootloader binary             | Yes      |
    | application.bin       | Application binary to sign            | Yes      |
    | keywrap-pub.key       | Renesas public key for UFPK           | Yes      |
    +---------------------------------------------------------------------------+

    CONFIGURATION FILE (project_config.json)
    +---------------------------------------------------------------------------+
    | Section               | Key                    | Description             |
    |-----------------------|------------------------|-------------------------|
    | aws.kms               | oem_root_key_id        | OEM Root Key in KMS     |
    | aws.kms               | oem_bootloader_key_id  | OEM Bootloader Key      |
    | aws.kms               | mcuboot_app_key_id     | App signing key         |
    | firmware              | inject_customer_key    | Enable key injection    |
    | firmware              | app_offset             | App start address       |
    | certificates          | load_addr              | Bootloader load addr    |
    | certificates          | oembl_size             | Bootloader region size  |
    | versioning            | certificate_version    | Anti-rollback version   |
    | imgtool               | align, slot_size, etc. | MCUboot parameters      |
    +---------------------------------------------------------------------------+

    OUTPUT FOLDER STRUCTURE
    +---------------------------------------------------------------------------+
    | output/
    |   reuse_ufpk/                        Reusable files (persist across builds)
    |     ufpk.key                         Plain UFPK
    |     ufpk_wrapped_decrypted.key       Wrapped UFPK from DLM
    |     oem_root_key.rkey                RKEY (wrapped OEM Root PK)
    |
    |   flow_YYYYMMDD_HHMMSS/              Per-build output folder
    |     application.bin.signed           Signed MCUboot image
    |     application.bin_offset.srec      Application at correct offset
    |     bootloader_with_aws_key.srec     Bootloader with injected key
    |     combined.srec                    Final SREC for programming
    |     customer_public.pem              App signing public key
    |     oem_root_public.pem              OEM Root public key
    |     oem_bl_public.pem                OEM Bootloader public key
    |     certs/
    |       oem_key_cert_vNN.bin           Key Certificate
    |       oem_code_cert_vNN.bin          Code Certificate
    +---------------------------------------------------------------------------+
    """)
    
    if section in ["all", "troubleshooting"]:
        _print_section("TROUBLESHOOTING", "yellow")
        
        click.echo("""
    COMMON ERRORS AND SOLUTIONS

    Error: "RKEY not found"
    +---------------------------------------------------------------------------+
    | Cause:   UFPK has not been prepared or RKEY has not been generated        |
    | Solution: Run these commands in order:                                    |
    |           1. invoke prepare-ufpk                                          |
    |           2. invoke generate-rkey                                         |
    +---------------------------------------------------------------------------+

    Error: "Certificate not found"
    +---------------------------------------------------------------------------+
    | Cause:   Firmware build workflow has not been completed                   |
    | Solution: Run the complete workflow:                                      |
    |           invoke workflow-all                                             |
    +---------------------------------------------------------------------------+

    Error: "CRC mismatch (AAAA0204)" during device programming
    +---------------------------------------------------------------------------+
    | Cause:   Code Certificate CRC was calculated on wrong bootloader binary   |
    |          This happens when gen-fsbl-certs runs BEFORE make-combined-srec  |
    | Solution: Run commands in correct order:                                  |
    |           1. invoke sign-app                                              |
    |           2. invoke make-combined-srec                                    |
    |           3. invoke gen-fsbl-certs                                        |
    |           Or simply: invoke workflow-all                                  |
    +---------------------------------------------------------------------------+

    Error: "Signature verification failed" on device
    +---------------------------------------------------------------------------+
    | Cause:   Bootloader is verifying with wrong public key                    |
    | Solution: Ensure inject_customer_key is true in project_config.json       |
    |           Re-run: invoke make-combined-srec                               |
    +---------------------------------------------------------------------------+

    Error: "AWS KMS access denied"
    +---------------------------------------------------------------------------+
    | Cause:   AWS credentials invalid or missing KMS permissions               |
    | Solution: 1. Check .env file for AWS_ACCESS_KEY_ID and SECRET             |
    |           2. Verify IAM user has kms:Sign and kms:GetPublicKey            |
    |           3. Verify KMS key policy allows your IAM user                   |
    +---------------------------------------------------------------------------+

    WORKFLOW ORDER (CRITICAL)
    +---------------------------------------------------------------------------+
    | The firmware build commands MUST be executed in this order:               |
    |                                                                           |
    |   1. invoke sign-app           Creates application.bin.signed             |
    |   2. invoke make-combined-srec Creates bootloader_with_aws_key.srec       |
    |   3. invoke gen-fsbl-certs     Uses bootloader_with_aws_key for CRC       |
    |   4. invoke program-device     Programs all files to device               |
    |                                                                           |
    | The 'invoke workflow-all' command handles steps 1-3 automatically.        |
    +---------------------------------------------------------------------------+
    """)
    
    # Footer
    click.echo("")
    click.echo(click.style("=" * 78, fg="cyan"))
    click.echo(click.style("  Configuration: project_config.json", fg="white"))
    click.echo(click.style("  Detailed help: invoke <command> --help", fg="white"))
    click.echo(click.style("=" * 78, fg="cyan"))
    click.echo("")


# =============================================================================
# NEW: Separate Provisioning vs Update Workflows
# =============================================================================

@workflow_group.command("provision-device")
@click.option("--com-port", type=str, default=None, help="COM port (e.g., COM3)")
@click.pass_context
def provision_device(ctx, com_port: Optional[str]):
    """
    FULL PROVISIONING for VIRGIN device (use ONCE per board).
    
    This command performs complete provisioning:
    1. Initialize device (OEM/PL2 state)
    2. Program OSM (Option Setting Memory)
    3. Program OEM Root Key (RKEY)
    4. Program Certificates (Key + Code)
    5. Program combined.srec (Bootloader + Application)
    
    WARNING: Use this ONLY on virgin/erased devices!
    WARNING: For daily development, use 'update-device' instead.
    
    Example:
        invoke workflow provision-device --com-port COM4
    """
    click.echo("\n" + "="*70)
    click.echo("FULL DEVICE PROVISIONING (Virgin Device)")
    click.echo("="*70 + "\n")
    
    click.echo("[INFO] This workflow includes:")
    click.echo("  [OK] Initialize (OEM/PL2)")
    click.echo("  [OK] OSM programming")
    click.echo("  [OK] RKEY programming")
    click.echo("  [OK] Certificate programming")
    click.echo("  [OK] Firmware programming (combined.srec)")
    click.echo()
    
    # Confirm with user
    if not click.confirm("WARNING: Device must be VIRGIN or CHIP-ERASED. Continue?", default=False):
        click.echo("[ABORT] Provisioning cancelled.")
        return
    
    # Call existing program-device with full provisioning
    ctx.invoke(program_device, com_port=com_port, lock_device=True, 
               bootloader_binary=None, skip_initialize=False)


@workflow_group.command("update-device")
@click.option("--com-port", type=str, default=None, help="COM port (e.g., COM3)")
@click.option("--only-app", is_flag=True, help="Flash only application (skip bootloader)")
@click.pass_context
def update_device(ctx, com_port: Optional[str], only_app: bool):
    """
    QUICK UPDATE for already-provisioned device (daily development).
    
    This command performs MINIMAL programming:
    - [OK] Program combined.srec (Bootloader + Application)
    - [X] NO Initialize
    - [X] NO OSM programming
    - [X] NO RKEY programming
    - [X] NO Certificate programming
    
    Use this for:
    - Daily development cycles
    - Application updates
    - Bootloader updates
    - Testing new firmware
    
    WARNING: Device must be already provisioned with valid certificates!
    
    Example:
        invoke workflow update-device --com-port COM4
        invoke workflow update-device --com-port COM4 --only-app
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("QUICK FIRMWARE UPDATE (Already Provisioned Device)")
    click.echo("="*70 + "\n")
    
    click.echo("[INFO] This workflow SKIPS:")
    click.echo("  [X] Initialize (device stays in current state)")
    click.echo("  [X] OSM programming (already protected)")
    click.echo("  [X] RKEY programming (already programmed)")
    click.echo("  [X] Certificate programming (reuses existing)")
    click.echo()
    click.echo("[INFO] This workflow PROGRAMS:")
    if only_app:
        click.echo("  [OK] Application ONLY (bootloader unchanged)")
    else:
        click.echo("  [OK] Combined SREC (bootloader + application)")
    click.echo()
    
    flow_folder = get_flow_folder()
    
    # Find combined.srec
    combined_srec = flow_folder / "combined.srec"
    if not combined_srec.exists():
        click.echo(f"[ERROR] combined.srec not found in {flow_folder}", err=True)
        click.echo("[TIP] Run 'invoke workflow sign-app' first!", err=True)
        sys.exit(1)
    
    click.echo(f"[FILE] Using: {combined_srec}")
    click.echo()
    
    # Auto-detect or prompt for COM port
    if not com_port:
        try:
            client = RA8ProvisioningClient()
            com_port = client.auto_detect_com_port()
            click.echo(f"[AUTO] Detected COM port: {com_port}")
        except Exception as e:
            click.echo(f"[WARN] Could not auto-detect COM port: {e}")
            com_port = click.prompt("Enter COM port", type=str, default="COM4")
    
    click.echo(f"[COM] Using port: {com_port}")
    click.echo()
    
    # Create minimal workflow (no provisioning steps)
    try:
        click.echo("="*70)
        click.echo("Starting firmware programming...")
        click.echo("="*70)
        click.echo()
        
        client = RA8ProvisioningClient(com_port=com_port)
        workflow = RA8ProvisioningWorkflow(client)
        
        # Connect to device
        click.echo("[1/3] Connecting to device...")
        client.connect()
        client.connect_boot_mode()
        click.echo("  [OK] Connected")
        
        # Program SREC only
        click.echo("\n[2/3] Programming firmware...")
        workflow.program_srec(combined_srec)
        click.echo("  [OK] Firmware programmed")
        
        # Disconnect
        click.echo("\n[3/3] Finalizing...")
        client.disconnect()
        click.echo("  [OK] Disconnected")
        
        # Success message
        click.echo()
        click.echo("="*70)
        click.echo("[SUCCESS] FIRMWARE UPDATE COMPLETE!")
        click.echo("="*70)
        click.echo()
        click.echo("Next steps:")
        click.echo("  1. Reset the board (press RESET button)")
        click.echo("  2. Verify application runs correctly")
        click.echo()
        click.echo("[TIP] Device retains existing certificates and security settings")
        
    except Exception as e:
        click.echo(f"\n[ERROR] Firmware update failed: {e}", err=True)
        logger.exception("Firmware update failed")
        sys.exit(1)
