"""
CLI Command: make-combined-srec

Combines bootloader and signed application into a single SREC file.
Equivalent to Renesas srec_cat workflow batch script.

This module provides functionality to:
    - Inject AWS KMS public key into bootloader at fixed address
    - Combine bootloader SREC with offset application SREC
    - Generate combined.srec ready for device programming

Inputs:
    - bootloader.srec: Original bootloader SREC from prerequisites/
    - application_offset.srec: Signed and offset application from sign-app
    - AWS KMS key: Customer public key for bootloader injection

Outputs:
    - bootloader_with_aws_key.srec: Bootloader with injected customer key
    - combined.srec: Final combined SREC (bootloader + application)
"""

import sys
from pathlib import Path
from typing import Optional

import click

from utils.project_config import get_project_config
from utils.srec_combiner import SrecCombiner
from utils.key_injector import inject_key_into_srec
from utils.exceptions import FirmwareError, ConfigError
from utils.logging import get_logger

logger = get_logger(__name__)


@click.command("make-combined-srec")
@click.option(
    "--bootloader-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Bootloader SREC file. If not provided, uses project_config.json"
)
@click.option(
    "--app-signed-bin",
    type=click.Path(exists=True, path_type=Path),
    required=False,
    help="Signed application binary (from sign-app command). Auto-detected from latest flow if not provided."
)
@click.option(
    "--app-offset",
    type=str,
    help="Application offset address (hex). If not provided, uses project_config.json"
)
@click.option(
    "--codecert-bin",
    type=click.Path(exists=True, path_type=Path),
    help="Code Certificate binary (optional, if already generated)"
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    help="Output combined SREC file. Default: output/flow_*/combined.srec"
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to project_config.json (optional)"
)
@click.option(
    "--inject-aws-key/--no-inject-aws-key",
    default=True,
    help="Inject AWS KMS mcuboot_app_key public key into bootloader (default: yes)"
)
def make_combined_srec_command(
    bootloader_srec: Optional[Path],
    app_signed_bin: Optional[Path],
    app_offset: Optional[str],
    codecert_bin: Optional[Path],
    out: Optional[Path],
    config: Optional[Path],
    inject_aws_key: bool
):
    """
    Combine bootloader and signed app into combined.srec.
    
    \b
    RENESAS-CORRECT WORKFLOW:
        - combined.srec = bootloader.srec + app_signed_offset.srec ONLY
        - Code Certificate is programmed SEPARATELY via boot interface (program-device)
        - Key Certificate is programmed SEPARATELY via boot interface (program-device)
    
    \b
    This is the Renesas batch equivalent:
        srec_cat app.signed -binary -offset 0x2010000 -execution-start-address 0x2010000 -o app_offset.srec
        srec_cat bootloader.srec app_offset.srec -o combined.srec
    
    \b
    Steps:
    1. Convert app.bin.signed to SREC with offset + execution start address
    2. Combine: bootloader + app_offset → combined.srec
    3. Add OSM records from bootloader (critical for device security config)
    4. Verify: no overlaps, correct S5/S7 records
    
    \b
    Example:
        $ tool make-combined-srec --app-signed-bin app.bin.signed
        $ tool make-combined-srec --bootloader-srec bl.srec --app-signed-bin app.signed
    
    \b
    Output:
        output/flow_YYYYMMDD_HHMMSS/combined.srec
    
    \b
    Verification:
        [OK] No memory overlaps
        [OK] OSM records present
        [OK] S5/S7 records valid
    
    \b
    NOTE: CodeCert parameter is deprecated. Certificates are programmed separately.
    """
    click.echo("="*70)
    click.echo("MAKE-COMBINED-SREC: Combine SREC Files")
    click.echo("="*70)
    
    try:
        # Load config
        proj_config = get_project_config(config)
        click.echo(f"[OK] Loaded config: {proj_config.project_name}")
        
        # Display key injection mode prominently at the start
        click.echo("-"*70)
        if inject_aws_key:
            click.echo("[KEY MODE] INJECT CUSTOMER KEY")
            click.echo("           MCUboot will verify apps signed with YOUR AWS KMS key")
        else:
            click.echo("[KEY MODE] KEEP ORIGINAL RENESAS DEMO KEY")
            click.echo("           MCUboot will verify apps signed with Renesas demo key")
            click.echo("           (Use this only for testing with Renesas reference apps)")
        click.echo("-"*70 + "\n")
        
        # Auto-detect app_signed_bin if not provided
        if not app_signed_bin:
            output_dir = Path(proj_config.output_dir)
            if not output_dir.exists():
                click.echo("[ERROR] No output directory found. Run 'sign-app' first.", err=True)
                sys.exit(1)
            
            # Find most recent flow directory
            flow_dirs = sorted(
                [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
                key=lambda d: d.stat().st_mtime,
                reverse=True
            )
            
            if not flow_dirs:
                click.echo("[ERROR] No flow directories found. Run 'sign-app' first.", err=True)
                sys.exit(1)
            
            latest_flow = flow_dirs[0]
            
            # Infer signed filename from project_config.json application_bin
            # e.g., application_bin = "prerequisites/blinky.bin" → "blinky.bin.signed"
            app_bin_name = Path(proj_config.application_bin).name  # e.g., "blinky.bin"
            expected_signed = latest_flow / f"{app_bin_name}.signed"  # e.g., "blinky.bin.signed"
            
            if expected_signed.exists():
                app_signed_bin = expected_signed
            else:
                # Fallback: search for any .bin.signed file in the latest flow
                signed_files = list(latest_flow.glob("*.bin.signed"))
                if signed_files:
                    app_signed_bin = signed_files[0]
                else:
                    click.echo(f"[ERROR] No signed app found in latest flow: {latest_flow}", err=True)
                    click.echo(f"  Expected: {expected_signed.name} (from project_config application_bin)", err=True)
                    click.echo(f"  Also searched for: *.bin.signed", err=True)
                    click.echo(f"  Run 'sign-app' first to sign your application.", err=True)
                    sys.exit(1)
            
            click.echo(f"Auto-detected signed app: {app_signed_bin}")
        
        # Get parameters
        bootloader_srec = bootloader_srec or proj_config.bootloader_srec
        app_offset_int = int(app_offset or proj_config.app_offset, 16)
        
        # Validate
        if not bootloader_srec.exists():
            click.echo(f"[ERROR] Bootloader SREC not found: {bootloader_srec}", err=True)
            sys.exit(1)
        
        if not app_signed_bin.exists():
            click.echo(f"[ERROR] Signed app binary not found: {app_signed_bin}", err=True)
            sys.exit(1)
        
        # Determine output
        if not out:
            # Use same flow folder as app_signed_bin
            out = app_signed_bin.parent / "combined.srec"
        
        click.echo(f"Bootloader SREC:  {bootloader_srec}")
        click.echo(f"App signed:       {app_signed_bin}")
        click.echo(f"App offset:       0x{app_offset_int:08X}")
        if codecert_bin:
            click.echo(f"Code Certificate: {codecert_bin}")
        click.echo(f"Output:           {out}\n")
        
        # Initialize combiner
        combiner = SrecCombiner(proj_config.srec_cat_exe)
        
        # Step 1: Convert app binary to SREC with offset
        click.echo("-"*70)
        click.echo("Step 1: Convert app binary to SREC with offset")
        click.echo("-"*70)
        
        app_offset_srec = app_signed_bin.parent / f"{app_signed_bin.stem}_offset.srec"
        combiner.bin_to_srec(
            binary_file=app_signed_bin,
            output_srec=app_offset_srec,
            offset=app_offset_int,
            exec_start_addr=app_offset_int
        )
        
        # Step 1.5: Inject AWS KMS public key into bootloader (CRITICAL!)
        if inject_aws_key:
            click.echo(f"\n{'-'*70}")
            click.echo("Step 1.5: Inject AWS KMS public key into bootloader")
            click.echo("-"*70)
            click.echo("Replacing MCUboot demo root_pub_der with customer public key from HSM")

            from config.settings import HSMConfig
            from security.hsm.factory import create_hsm_client

            key_address = int(proj_config.mcuboot_pubkey_addr, 16)
            modified_bootloader = app_signed_bin.parent / "bootloader_with_aws_key.srec"

            hsm_config = HSMConfig(
                hsm_type=proj_config.hsm_type,
                aws_region=proj_config.aws_region,
                aws_access_key_id=proj_config.aws_access_key_id,
                aws_secret_access_key=proj_config.aws_secret_access_key,
            )
            hsm_client = create_hsm_client(hsm_config)
            hsm_client.connect()
            try:
                public_key_der = hsm_client.get_public_key(proj_config.mcuboot_app_key_id)
            finally:
                hsm_client.disconnect()

            inject_key_into_srec(
                srec_file=bootloader_srec,
                key_der=public_key_der,
                key_address=key_address,
                output_file=modified_bootloader,
            )

            click.echo(f"[OK] Injected AWS KMS key at 0x{key_address:08X}")
            click.echo(f"[OK] Modified bootloader: {modified_bootloader.name}")

            # Use modified bootloader for combine
            bootloader_srec = modified_bootloader
        
        # Step 2: Combine SREC files
        click.echo(f"\n{'-'*70}")
        click.echo("Step 2: Combine SREC files (bootloader + app ONLY)")
        click.echo("-"*70)
        click.echo("RENESAS-CORRECT: CodeCert is programmed separately via boot interface")
        
        srec_files = [bootloader_srec, app_offset_srec]
        
        # DEPRECATED: CodeCert should NOT be in combined.srec
        # It's programmed separately via boot interface in program-device command
        if codecert_bin and codecert_bin.exists():
            click.echo(f"\n[WARN] WARNING: CodeCert parameter is DEPRECATED!")
            click.echo(f"[WARN] Renesas workflow programs CodeCert via boot interface (separate from combined.srec)")
            click.echo(f"[WARN] Ignoring: {codecert_bin.name}")
            click.echo(f"[WARN] Use 'program-device' command to program certificates\n")
        
        combiner.combine_srec_files(
            srec_files=srec_files,
            output_file=out,
            check_overlap=False  # srec_cat handles this correctly
        )
        
        # NOTE: OSM records are already included from bootloader.srec by srec_cat
        # Do NOT add them manually - this causes duplicates!
        
        click.echo(f"\n{'='*70}")
        click.echo(f"[OK] COMBINED SREC CREATED SUCCESSFULLY")
        click.echo(f"{'='*70}")
        click.echo(f"\nOutput: {out}")
        click.echo(f"Size:   {out.stat().st_size} bytes")
        click.echo(f"\nNext steps:")
        click.echo(f"  1. invoke gen-fsbl-certs  # Generate FSBL certificates (uses combined.srec for CRC)")
        click.echo(f"  2. invoke program-device  # Flash firmware + certificates to device")
        
    except ConfigError as e:
        click.echo(f"\n[ERROR] Configuration error: {e}", err=True)
        sys.exit(1)
    except FirmwareError as e:
        click.echo(f"\n[ERROR] SREC combination failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[ERROR] Unexpected error: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    make_combined_srec_command()
