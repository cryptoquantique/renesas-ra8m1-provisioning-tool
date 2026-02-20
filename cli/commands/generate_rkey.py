"""
CLI Command: generate-rkey

Generates RKEY (wrapped OEM Root Public Key) for device programming.
RKEY = OEM Root PK encrypted with UFPK (User Factory Programming Key).

This is required by Renesas FSBL - the device will NOT accept plain public keys.
"""

import sys
from pathlib import Path
from typing import Optional

import click

from utils.project_config import get_project_config
from utils.flow_manager import get_current_flow
from utils.exceptions import ConfigError, DeviceError
from utils.logging import get_logger
from config.settings import HSMConfig
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem, KeyCurve

logger = get_logger(__name__)


@click.command("generate-rkey")
@click.option(
    "--oem-root-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Root key. If not provided, uses project_config.json"
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to project_config.json (optional)"
)
def generate_rkey_command(
    oem_root_key_id: Optional[str],
    config: Optional[Path]
):
    """
    Generate RKEY (wrapped OEM Root Public Key) for device programming.
    
    \b
    What is RKEY?
        RKEY = OEM Root Public Key encrypted/wrapped with UFPK
        UFPK = User Factory Programming Key (device-specific)
    
    \b
    Why do we need RKEY?
        Renesas FSBL requires OEM Root PK to be wrapped with UFPK for security.
        The device will REJECT plain public keys!
    
    \b
    Prerequisites:
        1. Run 'invoke prepare-ufpk' first to get UFPK
        2. Have OEM Root Key in AWS KMS
    
    \b
    Steps:
        1. Check UFPK exists (wrapped + plain)
        2. Export OEM Root PK from AWS KMS
        3. Wrap OEM Root PK with UFPK → RKEY
        4. Save RKEY to flow folder
    
    \b
    Output:
        output/flow_YYYYMMDD_HHMMSS/oem_root_key.rkey
    
    \b
    Example:
        $ invoke generate-rkey
        $ invoke generate-rkey --oem-root-key-id 3ce24d75-caec-4ba9-b10a-38f7c3ff6dc0
    
    \b
    Next Steps:
        After RKEY generation:
        1. invoke sign-app            # Sign application with AWS KMS
        2. invoke make-combined-srec  # Combine bootloader + signed app
        3. invoke gen-fsbl-certs      # Generate FSBL certificates
        4. invoke program-device      # Flash to device
    """
    click.echo("="*70)
    click.echo("GENERATE-RKEY: Wrap OEM Root Public Key")
    click.echo("="*70)
    
    try:
        # Load config
        proj_config = get_project_config(config)
        click.echo(f"[OK] Loaded config: {proj_config.project_name}\n")
        
        # Get OEM Root Key ID
        oem_root_key_id = oem_root_key_id or proj_config.oem_root_key_id
        if not oem_root_key_id:
            click.echo("[ERROR] OEM Root Key ID not provided and not in config!", err=True)
            sys.exit(1)
        
        # Get or reuse existing flow folder (smart logic - reuses if has files)
        output_dir = Path(proj_config.output_dir)
        output_dir.mkdir(exist_ok=True)
        
        # Find latest flow folder
        flow_folders = sorted(
            [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        # Reuse latest flow if it has any provisioning files
        flow_folder = None
        if flow_folders:
            latest = flow_folders[0]
            important_files = [
                "ufpk.key",
                "ufpk_wrapped_decrypted.key",
                "oem_root_key.rkey",
                "oem_root_public.pem",
                "oem_bl_public.pem",
                "combined.srec",
                "application.bin.signed"
            ]
            
            # Reuse if ANY file exists
            for file_name in important_files:
                if (latest / file_name).exists():
                    flow_folder = latest
                    click.echo(f"Reusing existing flow: {latest.name}")
                    break
        
        # Create new flow only if no folders exist or all are complete
        if not flow_folder:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            flow_folder = output_dir / f"flow_{timestamp}"
            flow_folder.mkdir(parents=True, exist_ok=True)
            click.echo(f"Created new flow: {flow_folder.name}")
        
        click.echo(f"Flow folder:       {flow_folder}")
        click.echo(f"OEM Root Key ID:   {oem_root_key_id}\n")
        
        # === Step 1: Find UFPK (multiple locations) ===
        click.echo("-"*70)
        click.echo("Step 1: Locate UFPK")
        click.echo("-"*70)
        
        # Search locations (priority order):
        # 1. Flow folder (current flow)
        # 2. Other flow folders (previous flows)
        # 3. Reusable folder (shared between flows)
        # 4. Prerequisites (static/hardcoded)
        
        output_dir = Path(proj_config.output_dir)
        reuse_folder = output_dir / "reuse_ufpk"
        prerequisites_folder = Path("prerequisites")
        
        # Find all flow folders
        flow_folders = sorted(
            [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
            key=lambda d: d.stat().st_mtime,
            reverse=True  # Most recent first
        )
        
        search_locations = [
            (flow_folder, "current flow"),
            *[(f, f"previous flow ({f.name})") for f in flow_folders if f != flow_folder],
            (reuse_folder, "reusable folder"),
            (prerequisites_folder, "prerequisites")
        ]
        
        wrapped_ufpk_path = None
        plain_ufpk_path = None
        source_location = None
        
        for location, location_name in search_locations:
            if not location.exists():
                continue
                
            wrapped_candidate = location / "ufpk_wrapped_decrypted.key"
            plain_candidate = location / "ufpk.key"
            
            if wrapped_candidate.exists() and plain_candidate.exists():
                wrapped_ufpk_path = wrapped_candidate
                plain_ufpk_path = plain_candidate
                source_location = location_name
                break
        
        if not wrapped_ufpk_path or not plain_ufpk_path:
            click.echo("[ERROR] UFPK not found in any location!", err=True)
            click.echo("", err=True)
            click.echo("Searched locations:", err=True)
            for loc, name in search_locations[:5]:  # Show first 5
                click.echo(f"  - {loc} ({name})", err=True)
            click.echo("", err=True)
            click.echo("Run 'invoke prepare-ufpk' first to generate UFPK!", err=True)
            sys.exit(1)
        
        click.echo(f"[OK] Found UFPK in: {source_location}")
        click.echo(f"    Wrapped: {wrapped_ufpk_path}")
        click.echo(f"    Plain:   {plain_ufpk_path}\n")
        
        # === Step 2: Export OEM Root PK from AWS KMS ===
        click.echo("-"*70)
        click.echo("Step 2: Export OEM Root Public Key from AWS KMS")
        click.echo("-"*70)
        
        oem_root_pk_file = flow_folder / "oem_root_public.pem"
        
        if oem_root_pk_file.exists():
            click.echo(f"[OK] OEM Root PK already exists: {oem_root_pk_file.name}")
        else:
            click.echo(f"Exporting from AWS KMS: {oem_root_key_id[:20]}...")
            
            # Create HSM config
            hsm_config = HSMConfig(
                hsm_type=proj_config.hsm_type,  # Use config (broker or aws_kms)
                aws_region=proj_config.aws_region,
                aws_access_key_id=proj_config.aws_access_key_id,
                aws_secret_access_key=proj_config.aws_secret_access_key
            )
            
            hsm_client = create_hsm_client(hsm_config)
            hsm_client.connect()
            
            try:
                oem_root_pk_der = hsm_client.get_public_key(oem_root_key_id)
                save_public_key_pem(oem_root_pk_der, oem_root_pk_file, KeyCurve.SECP256R1)
                click.echo(f"[OK] Exported: {oem_root_pk_file.name}")
            finally:
                hsm_client.disconnect()
        
        click.echo(f"    Size: {oem_root_pk_file.stat().st_size} bytes\n")
        
        # === Step 3: Find or Generate RKEY ===
        click.echo("-"*70)
        click.echo("Step 3: Find or Generate RKEY")
        click.echo("-"*70)
        
        rkey_path = flow_folder / "oem_root_key.rkey"
        
        # Check if RKEY already exists in current flow
        if rkey_path.exists():
            click.echo(f"[OK] RKEY already exists in current flow: {rkey_path.name}")
            click.echo(f"    Size: {rkey_path.stat().st_size} bytes")
        else:
            # Search for RKEY in other flow folders
            rkey_found = None
            for f in flow_folders:
                rkey_candidate = f / "oem_root_key.rkey"
                if rkey_candidate.exists():
                    rkey_found = rkey_candidate
                    click.echo(f"[OK] Found RKEY in: {f.name}")
                    click.echo(f"    Copying to current flow...")
                    import shutil
                    shutil.copy2(rkey_found, rkey_path)
                    click.echo(f"[OK] RKEY copied: {rkey_path.name}")
                    click.echo(f"    Size: {rkey_path.stat().st_size} bytes")
                    break
            
            if not rkey_found:
                # Generate new RKEY using native Python (AES-CBC + CBC-MAC)
                click.echo("No existing RKEY found. Generating new RKEY...")
                click.echo("[INFO] Using native Python RKEY generator (AES-CBC + CBC-MAC)")
                click.echo("")
                
                try:
                    from security.skmt.native_rkey_generator import generate_rkey_from_files
                    # Needs BOTH plain UFPK (32 bytes) and wrapped UFPK (36 bytes)
                    generate_rkey_from_files(
                        oem_root_pk_file=oem_root_pk_file,
                        ufpk_file=plain_ufpk_path,
                        output_file=rkey_path,
                        w_ufpk_file=wrapped_ufpk_path,
                    )
                    click.echo(f"[OK] RKEY generated: {rkey_path.name}")
                    click.echo(f"    Size: {rkey_path.stat().st_size} bytes")
                except Exception as e:
                    click.echo(f"\n[ERROR] RKEY generation failed: {e}", err=True)
                    click.echo("\nPlease check:", err=True)
                    click.echo(f"  - OEM Root PK file: {oem_root_pk_file}", err=True)
                    click.echo(f"  - UFPK file: {wrapped_ufpk_path}", err=True)
                    click.echo("  - Both files must exist and be valid", err=True)
                    click.echo("\nAlternative: Place an existing .rkey file at:", err=True)
                    click.echo(f"  - {rkey_path}", err=True)
                    click.echo("  - output/reuse_ufpk/oem_root_key.rkey", err=True)
                    sys.exit(1)
        
        # === Step 4: Move UFPK to reusable folder (cleanup) ===
        click.echo("\n" + "-"*70)
        click.echo("Step 4: Cleanup - Move UFPK to reusable folder")
        click.echo("-"*70)
        
        reuse_folder.mkdir(parents=True, exist_ok=True)
        
        # Copy UFPK to reusable folder if not already there
        if source_location != "reusable folder":
            reuse_wrapped = reuse_folder / "ufpk_wrapped_decrypted.key"
            reuse_plain = reuse_folder / "ufpk.key"
            
            if not reuse_wrapped.exists():
                import shutil
                shutil.copy2(wrapped_ufpk_path, reuse_wrapped)
                click.echo(f"[OK] Copied wrapped UFPK to: {reuse_folder.name}/")
            
            if not reuse_plain.exists():
                import shutil
                shutil.copy2(plain_ufpk_path, reuse_plain)
                click.echo(f"[OK] Copied plain UFPK to: {reuse_folder.name}/")
        else:
            click.echo("[OK] UFPK already in reusable folder")
        
        # Remove UFPK from flow folder (keep only RKEY)
        flow_wrapped = flow_folder / "ufpk_wrapped_decrypted.key"
        flow_plain = flow_folder / "ufpk.key"
        
        if flow_wrapped.exists():
            flow_wrapped.unlink()
            click.echo(f"[OK] Removed {flow_wrapped.name} from flow (cleanup)")
        
        if flow_plain.exists():
            flow_plain.unlink()
            click.echo(f"[OK] Removed {flow_plain.name} from flow (cleanup)")
        
        click.echo(f"\n[OK] Flow folder now contains ONLY: {rkey_path.name}")
        
        click.echo("\n" + "="*70)
        click.echo("[OK] RKEY GENERATED SUCCESSFULLY")
        click.echo("="*70)
        click.echo(f"\nOutput: {rkey_path}")
        click.echo("\nNext steps:")
        click.echo("  1. invoke sign-app            # Sign application with AWS KMS")
        click.echo("  2. invoke make-combined-srec  # Combine bootloader + signed app")
        click.echo("  3. invoke gen-fsbl-certs      # Generate FSBL certificates")
        click.echo("  4. invoke program-device      # Flash to device")
        click.echo(f"\n  Or run steps 1-3 at once: invoke workflow-all")
        click.echo("")
        
    except ConfigError as e:
        click.echo(f"\n[ERROR] Configuration error: {e}", err=True)
        sys.exit(1)
    except DeviceError as e:
        click.echo(f"\n[ERROR] Device error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[ERROR] Unexpected error: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    generate_rkey_command()
