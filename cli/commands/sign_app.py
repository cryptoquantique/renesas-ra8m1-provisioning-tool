"""
CLI Command: sign-app

MCUboot application signing using AWS KMS.
Firmware signing only - does NOT generate FSBL certificates.

This module provides functionality to:
    - Sign application binary with MCUboot header and TLV structure
    - Use AWS KMS ECDSA P-256 key for cryptographic signing
    - Generate offset SREC for combining with bootloader

Inputs:
    - application.bin: Raw application binary from prerequisites/
    - AWS KMS Key ID: Customer signing key in AWS KMS
    - version: Application version string (e.g., '1.0.0')

Outputs:
    - application.bin.signed: Signed binary with MCUboot header
    - application_offset.srec: Offset SREC at IMAGE_START address
    - customer_public.pem: Customer public key for verification
"""

import sys
import traceback
from pathlib import Path
from typing import Optional

import click

from config.settings import HSMConfig
from firmware.aws_kms_signer_v3 import sign_image_with_aws_kms
from models.keys import KeyCurve
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem
from utils.exceptions import FirmwareError, ConfigError
from utils.logging import get_logger
from utils.project_config import get_project_config

logger = get_logger(__name__)


@click.command("sign-app")
@click.option(
    "--app-bin",
    type=click.Path(exists=True, path_type=Path),
    help="Application binary file. If not provided, uses path from project_config.json"
)
@click.option(
    "--kms-key-id",
    type=str,
    help="AWS KMS Key ID for MCUboot APP signing. If not provided, uses project_config.json"
)
@click.option(
    "--version",
    type=str,
    help="Application version (e.g., '1.0.0'). If not provided, uses project_config.json"
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    help="Output signed binary file. Default: <app>.bin.signed in output folder"
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to project_config.json (optional, auto-detected)"
)
@click.option(
    "--production",
    is_flag=True,
    default=False,
    help="Production mode: blocks temporary local key generation (requires alternative MCUboot builder)"
)
def sign_app_command(
    app_bin: Optional[Path],
    kms_key_id: Optional[str],
    version: Optional[str],
    out: Optional[Path],
    config: Optional[Path],
    production: bool
):
    """
    Sign APPLICATION firmware with AWS KMS (MCUboot format).
    
    \b
    This command:
    1. Takes application binary (app.bin)
    2. Signs it with AWS KMS using MCUboot format
    3. Produces signed binary (app.bin.signed)
    
    \b
    All parameters can be read from project_config.json:
    - app_bin: paths.application_bin
    - kms_key_id: aws.kms.mcuboot_app_key_id
    - version: versioning.application_version
    
    \b
    Example:
        $ tool sign-app
        $ tool sign-app --app-bin app.bin --kms-key-id <KEY_ID> --version 1.0.0
    
    \b
    Output:
        output/flow_YYYYMMDD_HHMMSS/app.bin.signed
    
    \b
    Verification:
        [OK] MCUboot header valid
        [OK] TLV signature valid
        [OK] KEYHASH correct
    """
    click.echo("="*70)
    click.echo("SIGN-APP: MCUboot Application Signing")
    click.echo("="*70)
    
    try:
        # Load project config
        proj_config = get_project_config(config)
        click.echo(f"[OK] Loaded config: {proj_config.project_name} v{proj_config.project_version}\n")
        
        # Get parameters (CLI overrides config)
        app_bin = app_bin or proj_config.application_bin
        kms_key_id = kms_key_id or proj_config.mcuboot_app_key_id
        version = version or proj_config.application_version
        
        # Validate
        if not app_bin.exists():
            click.echo(f"[ERROR] Application binary not found: {app_bin}", err=True)
            sys.exit(1)
        
        if not kms_key_id or kms_key_id.startswith('xxxx'):
            click.echo("[ERROR] mcuboot_app_key_id not configured in project_config.json!", err=True)
            sys.exit(1)
        
        # Create output folder using flow manager
        from utils.flow_manager import get_current_flow
        output_dir = get_current_flow(
            output_dir=proj_config.output_dir,
            certificate_version=proj_config.certificate_version,
            force_new=False  # Reuse existing flow if incomplete
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine output file
        if not out:
            out = output_dir / f"{app_bin.stem}.bin.signed"
        
        click.echo(f"Input binary:  {app_bin}")
        click.echo(f"KMS Key ID:    {kms_key_id}")
        click.echo(f"Version:       {version}")
        click.echo(f"Output:        {out}")
        click.echo(f"Output folder: {output_dir}")
        if production:
            click.echo(f"Mode:          PRODUCTION (local keys BLOCKED)")
        else:
            click.echo(f"Mode:          DEVELOPMENT (local keys allowed for imgtool)")
        click.echo("")
        
        # Sign with AWS KMS
        click.echo("-"*70)
        click.echo("Signing with AWS KMS...")
        click.echo("-"*70)
        
        hsm_config = HSMConfig(
            hsm_type="aws_kms",
            aws_region=proj_config.aws_region,
            aws_access_key_id=proj_config.aws_access_key_id,
            aws_secret_access_key=proj_config.aws_secret_access_key
        )
        
        # All imgtool parameters from project_config.json (SINGLE SOURCE OF TRUTH)
        sign_image_with_aws_kms(
            input_file=app_bin,
            output_file=out,
            aws_kms_key_id=kms_key_id,
            config=hsm_config,
            header_size=proj_config.imgtool_header_size,
            align=proj_config.imgtool_align,
            max_align=proj_config.imgtool_max_align,
            slot_size=proj_config.imgtool_slot_size,
            max_sectors=proj_config.imgtool_max_sectors,
            version=version or proj_config.imgtool_version,
            pad_header=proj_config.imgtool_pad_header,
            pad=proj_config.imgtool_pad,
            confirm=proj_config.imgtool_confirm,
            allow_local_temp_keys=not production,
        )

        customer_pk_pem = output_dir / "customer_public.pem"
        hsm_client = create_hsm_client(hsm_config)
        hsm_client.connect()
        customer_pk_der = hsm_client.get_public_key(kms_key_id)
        hsm_client.disconnect()
        save_public_key_pem(customer_pk_der, customer_pk_pem, KeyCurve.SECP256R1)
        click.echo(f"\n[OK] Customer public key saved: {customer_pk_pem}")
        
        click.echo(f"\n{'='*70}")
        click.echo(f"[OK] APPLICATION SIGNED SUCCESSFULLY")
        click.echo(f"{'='*70}")
        click.echo(f"\nOutput: {out}")
        click.echo(f"Size:   {out.stat().st_size} bytes")
        click.echo(f"\nNext step: Run 'gen-fsbl-certs' to generate certificates")
        
    except ConfigError as e:
        click.echo(f"\n[ERROR] Configuration error: {e}", err=True)
        sys.exit(1)
    except FirmwareError as e:
        click.echo(f"\n[ERROR] Firmware signing failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[ERROR] Unexpected error: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    sign_app_command()
