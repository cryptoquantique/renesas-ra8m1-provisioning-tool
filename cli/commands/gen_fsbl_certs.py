"""
CLI Command: gen-fsbl-certs

Generates Key Certificate and Code Certificate for FSBL (First Stage Boot Loader).
Includes MANDATORY verifications: TLV Length, KEYHASH==SIGNER_ID, CRC with 0xFF fill.

This module provides functionality to:
    - Generate Key Certificate (authenticates OEM Bootloader PK using OEM Root SK)
    - Generate Code Certificate (authenticates bootloader binary using OEM BL SK)
    - Validate certificate chain integrity

Inputs:
    - OEM Root SK: AWS KMS key ID for root secret key
    - OEM Bootloader SK: AWS KMS key ID for bootloader secret key
    - bootloader_with_aws_key.srec: Bootloader with injected customer key (for CRC)

Outputs:
    - key_cert.bin: Key Certificate (256 bytes)
    - code_cert.bin: Code Certificate (256 bytes)
    - oem_root_public.pem: OEM Root public key
    - oem_bl_public.pem: OEM Bootloader public key
"""

import hashlib
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from config.settings import SKMTConfig, HSMConfig
from models.keys import KeyCurve
from security.hsm.factory import create_hsm_client
from security.key_utils import save_public_key_pem
from security.skmt.certificate_generator import CertificateGenerator
from security.skmt.wrapper import extract_raw_public_key_qxqy, parse_srec
from utils.cert_validator import CertificateValidator
from utils.exceptions import SKMTError, ConfigError, HSMError
from utils.logging import get_logger
from utils.project_config import get_project_config

logger = get_logger(__name__)


@click.command("gen-fsbl-certs")
@click.option(
    "--oemroot-kms-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Root SK. If not provided, uses project_config.json"
)
@click.option(
    "--oembl-kms-key-id",
    type=str,
    help="AWS KMS Key ID for OEM Bootloader SK. If not provided, uses project_config.json"
)
@click.option(
    "--oembl-srec",
    type=click.Path(exists=True, path_type=Path),
    help="OEM Bootloader SREC file. If not provided, uses project_config.json"
)
@click.option(
    "--combined-srec",
    type=click.Path(exists=True, path_type=Path),
    help="Combined SREC file (bootloader+app) for CRC calculation. CRITICAL: If provided, CRC is calculated on this file instead of oembl-srec. Required for correct FSBL verification!"
)
@click.option(
    "--loadaddr",
    type=str,
    help="Load address (hex). Default: from project_config.json"
)
@click.option(
    "--oembl-size",
    type=str,
    help="OEM Bootloader size (hex). If not provided, uses project_config.json"
)
@click.option(
    "--ver",
    type=int,
    help="Certificate version (decimal). If not provided, uses project_config.json"
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    help="Output directory for certificates. Default: output/flow_*/certs/"
)
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to project_config.json (optional)"
)
def gen_fsbl_certs_command(
    oemroot_kms_key_id: Optional[str],
    oembl_kms_key_id: Optional[str],
    oembl_srec: Optional[Path],
    combined_srec: Optional[Path],
    loadaddr: Optional[str],
    oembl_size: Optional[str],
    ver: Optional[int],
    out: Optional[Path],
    config: Optional[Path]
):
    """
    Generate FSBL certificates (Key Certificate + Code Certificate).
    
    \b
    This command:
    1. Exports public keys from AWS KMS
    2. Generates Key Certificate (signed with OEM_ROOT_SK)
    3. Generates Code Certificate (signed with OEM_BL_SK)
    4. Verifies KEYHASH == SIGNER_ID
    5. Verifies TLV lengths (Key=0xAC, Code=0xB4)
    
    \b
    Parameters from project_config.json:
    - oemroot_kms_key_id: aws.kms.oem_root_key_id
    - oembl_kms_key_id: aws.kms.oem_bootloader_key_id
    - oembl_srec: paths.bootloader_srec
    - loadaddr: certificates.load_addr
    - oembl_size: certificates.oembl_size
    - ver: versioning.certificate_version
    
    \b
    Example:
        $ tool gen-fsbl-certs
        $ tool gen-fsbl-certs --ver 20
    
    \b
    Output:
        output/flow_YYYYMMDD_HHMMSS/certs/oem_key_cert.bin
        output/flow_YYYYMMDD_HHMMSS/certs/oem_code_cert.bin
    
    \b
    Mandatory Verifications:
        [OK] TLV Length: Key = 0xAC (172 bytes)
        [OK] TLV Length: Code = 0xB4 (180 bytes)
        [OK] KEYHASH == SIGNER_ID
        [OK] CRC calculated with 0xFF fill
        [OK] Signatures valid
    """
    click.echo("="*70)
    click.echo("GEN-FSBL-CERTS: Generate FSBL Certificates")
    click.echo("="*70)
    
    try:
        # Load config
        proj_config = get_project_config(config)
        click.echo(f"[OK] Loaded config: {proj_config.project_name}\n")
        
        # Get parameters
        oemroot_kms_key_id = oemroot_kms_key_id or proj_config.oem_root_key_id
        oembl_kms_key_id = oembl_kms_key_id or proj_config.oem_bootloader_key_id
        oembl_srec = oembl_srec or proj_config.bootloader_srec
        loadaddr = loadaddr or proj_config.cert_load_addr
        oembl_size = oembl_size or proj_config.cert_oembl_size
        ver = ver or proj_config.certificate_version
        
        # Validate
        if not oemroot_kms_key_id or oemroot_kms_key_id.startswith('xxxx'):
            click.echo("[ERROR] oem_root_key_id not configured in project_config.json!", err=True)
            sys.exit(1)
        
        if not oembl_kms_key_id or oembl_kms_key_id.startswith('xxxx'):
            click.echo("[ERROR] oem_bootloader_key_id not configured in project_config.json!", err=True)
            sys.exit(1)
        
        if not oembl_srec.exists():
            click.echo(f"[ERROR] Bootloader SREC not found: {oembl_srec}", err=True)
            sys.exit(1)

        if not out:
            output_dir = Path(proj_config.output_dir)
            output_dir.mkdir(exist_ok=True)
            flow_folders = sorted(
                [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )

            flow_dir = None
            if flow_folders:
                latest = flow_folders[0]
                important_files = [
                    "oem_root_key.rkey",
                    "oem_root_public.pem",
                    "oem_bl_public.pem",
                    "combined.srec",
                    "application.bin.signed"
                ]

                for file_name in important_files:
                    if (latest / file_name).exists():
                        flow_dir = latest
                        break

            if not flow_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                flow_dir = output_dir / f"flow_{timestamp}"
                flow_dir.mkdir(parents=True, exist_ok=True)
            
            out = flow_dir / "certs"
        
        out.mkdir(parents=True, exist_ok=True)

        bootloader_with_key = out.parent / "bootloader_with_aws_key.srec"
        if bootloader_with_key.exists():
            crc_srec_source = bootloader_with_key
            crc_source_desc = "bootloader_with_aws_key.srec (auto-detected, WITH AWS KEY!)"
        elif combined_srec:
            crc_srec_source = combined_srec
            crc_source_desc = f"{combined_srec.name} (bootloader portion, WITH AWS KEY!)"
        else:
            crc_srec_source = oembl_srec
            crc_source_desc = f"{oembl_srec.name} (ORIGINAL - no AWS key!)"
        
        click.echo(f"OEM Root Key:      {oemroot_kms_key_id}")
        click.echo(f"OEM Bootloader Key: {oembl_kms_key_id}")
        click.echo(f"Bootloader SREC:   {oembl_srec}")
        click.echo(f"CRC Source:        {crc_source_desc}")
        if not bootloader_with_key.exists() and not combined_srec:
            click.echo(f"  [WARN] No modified bootloader found! CRC will be wrong if AWS key was injected!")
        click.echo(f"Load Address:      {loadaddr}")
        click.echo(f"Bootloader Size:   {oembl_size}")
        click.echo(f"Certificate Ver:   {ver}")
        click.echo(f"Output directory:  {out}\n")
        
        # Initialize certificate generator
        click.echo("-"*70)
        click.echo("Initializing Certificate Generator...")
        click.echo("-"*70)
        
        skmt_config = SKMTConfig(
            skmt_path=Path("skmt"),  # TODO: Configure proper path
            working_directory=out.parent / "skmt_work"
        )
        
        hsm_config = HSMConfig(
            hsm_type="aws_kms",
            aws_region=proj_config.aws_region,
            aws_access_key_id=proj_config.aws_access_key_id,
            aws_secret_access_key=proj_config.aws_secret_access_key
        )
        
        cert_gen = CertificateGenerator(
            skmt_config=skmt_config,
            hsm_config=hsm_config
        )
        
        # Export public keys from KMS
        click.echo(f"\n{'-'*70}")
        click.echo("Step 1: Export Public Keys from AWS KMS")
        click.echo("-"*70)
        
        hsm_client = create_hsm_client(hsm_config)
        hsm_client.connect()
        
        # Export OEM_ROOT_PK
        click.echo(f"  Exporting OEM Root Public Key from KMS...")
        oem_root_pk_bytes = hsm_client.get_public_key(oemroot_kms_key_id)
        oem_root_pk_pem = out.parent / "oem_root_public.pem"
        save_public_key_pem(oem_root_pk_bytes, oem_root_pk_pem, KeyCurve.SECP256R1)
        click.echo(f"    [OK] Saved: {oem_root_pk_pem.name}")
        
        # Export OEM_BL_PK
        click.echo(f"  Exporting OEM Bootloader Public Key from KMS...")
        oem_bl_pk_bytes = hsm_client.get_public_key(oembl_kms_key_id)
        oem_bl_pk_pem = out.parent / "oem_bl_public.pem"
        save_public_key_pem(oem_bl_pk_bytes, oem_bl_pk_pem, KeyCurve.SECP256R1)
        click.echo(f"    [OK] Saved: {oem_bl_pk_pem.name}")
        
        # Generate Key Certificate
        click.echo(f"\n{'-'*70}")
        click.echo("Step 2: Generate Key Certificate")
        click.echo("-"*70)
        
        key_cert_path = out / f"oem_key_cert_v{ver}.bin"
        
        key_cert = cert_gen.generate_key_certificate(
            oem_root_sk_key_id=oemroot_kms_key_id,
            oem_bl_pk_file=oem_bl_pk_pem,
            output_file=key_cert_path,
            oem_root_pk_file=oem_root_pk_pem
        )
        click.echo(f"  [OK] Generated: {key_cert_path.name}")
        click.echo(f"    Size: {key_cert_path.stat().st_size} bytes")

        click.echo(f"\n  Computing KEYHASH = SHA256(OEM_BL_PK_raw)...")
        oem_bl_pk_raw = extract_raw_public_key_qxqy(oem_bl_pk_pem.read_bytes())
        oem_bl_pk_hash = hashlib.sha256(oem_bl_pk_raw).digest()
        click.echo(f"    OEM_BL_PK_HASH: {oem_bl_pk_hash.hex()[:32]}...")
        click.echo(f"    (This will be SIGNER_ID in Code Certificate)")
        
        # Generate Code Certificate
        click.echo(f"\n{'-'*70}")
        click.echo("Step 3: Generate Code Certificate")
        click.echo("-"*70)
        
        code_cert_path = out / f"oem_code_cert_v{ver}.bin"
        load_addr_int = int(proj_config.cert_load_addr, 16)
        cfsize = int(proj_config.cert_cfsize, 16)
        click.echo(f"  CRC Source: {crc_srec_source.name}")
        click.echo(f"  Load address: 0x{load_addr_int:08X} (from config)")
        click.echo(f"  cfsize filter: 0x{cfsize:X} (from config, range filter)")

        bl_binary = parse_srec(crc_srec_source, load_addr_int, cfsize)
        click.echo(f"  Extracted binary: {len(bl_binary)} bytes (ACTUAL size, as reference)")
        
        code_cert = cert_gen.generate_code_certificate(
            oem_bl_sk_key_id=oembl_kms_key_id,
            oem_bl_pk_file=oem_bl_pk_pem,
            bootloader_binary=bl_binary,
            output_file=code_cert_path,
            version=ver,
            oem_bl_pk_hash=oem_bl_pk_hash
        )
        click.echo(f"  [OK] Generated: {code_cert_path.name}")
        click.echo(f"    Size: {code_cert_path.stat().st_size} bytes")

        click.echo(f"\n{'-'*70}")
        click.echo("Step 4: Verify Certificates (COMPLETE - ALL FSBL CHECKS)")
        click.echo("-"*70)
        click.echo("Performing ALL checks that device FSBL will perform...")
        click.echo("")

        is_valid, validation_msg = CertificateValidator.validate_certificates_complete(
            key_cert_path=key_cert_path,
            code_cert_path=code_cert_path,
            oem_root_pk_pem=oem_root_pk_pem,
            oem_bl_pk_pem=oem_bl_pk_pem,
            bootloader_binary=bl_binary,
            flash_length=len(bl_binary)
        )
        
        if not is_valid:
            click.echo(f"\n[FAIL] CERTIFICATE VALIDATION FAILED!", err=True)
            click.echo(f"{validation_msg}", err=True)
            click.echo(f"\n[WARN] Device will REJECT these certificates!", err=True)
            sys.exit(1)
        
        click.echo(f"\n{validation_msg}")
        
        click.echo(f"\n{'='*70}")
        click.echo(f"[OK] FSBL CERTIFICATES GENERATED SUCCESSFULLY")
        click.echo(f"{'='*70}")
        click.echo(f"\nOutput directory: {out}")
        click.echo(f"  - {key_cert_path.name} ({key_cert_path.stat().st_size} bytes)")
        click.echo(f"  - {code_cert_path.name} ({code_cert_path.stat().st_size} bytes)")
        click.echo(f"\nVerification Summary:")
        click.echo(f"  [OK] Magic bytes valid")
        click.echo(f"  [OK] TLV lengths correct")
        click.echo(f"  [OK] Certificate chain valid (KEYHASH == SIGNER_ID)")
        click.echo(f"\nNext step: Run 'make-combined-srec' with --codecert-bin {code_cert_path}")
        
    except ConfigError as e:
        click.echo(f"\n[ERROR] Configuration error: {e}", err=True)
        sys.exit(1)
    except (SKMTError, HSMError) as e:
        click.echo(f"\n[ERROR] Certificate generation failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[ERROR] Unexpected error: {e}", err=True)
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    gen_fsbl_certs_command()
