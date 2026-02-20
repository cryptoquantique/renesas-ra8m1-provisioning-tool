"""
Invoke tasks for RA8M1 Provisioning Workflow.

UFPK Flow (one-time per device type):
    invoke prepare-ufpk             # Complete UFPK flow (generate, encrypt, upload, decrypt)
    invoke generate-rkey            # Generate RKEY from UFPK

Firmware Build Flow (per firmware version):
    invoke sign-app                 # Step 1: Sign application with MCUboot format
    invoke make-combined-srec       # Step 2: Combine bootloader + signed app
    invoke gen-fsbl-certs --combined-srec <path>  # Step 3: Generate certificates (CRC on combined!)
    invoke program-device           # Step 4: Program device

CRITICAL: Certificate generation MUST use --combined-srec for correct CRC calculation!
         FSBL calculates CRC on the entire 192KB region (bootloader + app).
"""

from invoke import task
from pathlib import Path
import sys
import subprocess


def _run_workflow_command(ctx, cmd_name: str, **kwargs):
    """Helper to run workflow CLI command."""
    import subprocess
    from pathlib import Path

    python_exe = sys.executable

    if cmd_name == 'prepare-ufpk':
        cmd_parts = [python_exe, '-m', 'cli', 'prepare-ufpk']
    elif cmd_name == 'export-pgp-public-key':
        cmd_parts = [python_exe, '-m', 'cli', 'export-pgp-public-key']
    else:
        cmd_parts = [python_exe, '-m', 'cli', 'workflow', cmd_name]

    for key, value in kwargs.items():
        if value is None:
            continue
        if isinstance(value, bool):
            if value:
                cmd_parts.append(f'--{key.replace("_", "-")}')
        elif isinstance(value, (str, Path)):
            cmd_parts.append(f'--{key.replace("_", "-")}')
            cmd_parts.append(str(value))
        elif isinstance(value, (int, float)):
            cmd_parts.append(f'--{key.replace("_", "-")}')
            cmd_parts.append(str(value))

    result = subprocess.run(cmd_parts, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)
    return result


@task
def prepare_ufpk_file(ctx, ufpk_hardcoded=None, ufpk_file=None):
    """
    Step 1 (Individual): Prepare UFPK file - Generate UFPK and create flow directory.
    
    Options:
        --ufpk-hardcoded: Hardcoded UFPK hex (64 chars). If not provided, will generate random.
        --ufpk-file: Use existing UFPK file instead of generating new one.
    """
    _run_workflow_command(ctx, 'prepare-ufpk-file', ufpk_hardcoded=ufpk_hardcoded, ufpk_file=ufpk_file)


@task
def prepare_ufpk(ctx, ufpk_hardcoded=None, ufpk_file=None):
    """
    Complete UFPK preparation (all-in-one): Generate, Encrypt, Upload to DLM, Wait for email, Decrypt.
    
    This combines all UFPK steps into one command with interactive prompts.
    
    Options:
        --ufpk-hardcoded: Hardcoded UFPK hex (64 chars). If not provided, will generate random.
        --ufpk-file: Use existing UFPK file instead of generating new one.
    """
    _run_workflow_command(ctx, 'prepare-ufpk', ufpk_hardcoded=ufpk_hardcoded, ufpk_file=ufpk_file)


@task
def encrypt_ufpk(ctx):
    """
    Step 2: Encrypt UFPK with Renesas public key.
    
    Uses UFPK from current flow directory.
    """
    _run_workflow_command(ctx, 'encrypt-ufpk')


@task
def upload_dlm(ctx):
    """
    Step 3: Upload encrypted UFPK to DLM server.
    
    Uses encrypted UFPK from current flow directory.
    """
    _run_workflow_command(ctx, 'upload-dlm')


@task
def decrypt_wrapped(ctx, wrapped_file=None):
    """
    Step 4: Decrypt wrapped UFPK from email.
    
    Options:
        --wrapped-file: Path to wrapped UFPK file from email. If not provided, will prompt.
    """
    _run_workflow_command(ctx, 'decrypt-wrapped', wrapped_file=wrapped_file)


@task
def generate_rkey(ctx, oem_root_key_id=None):
    """
    Step 5: Generate RKEY from wrapped UFPK and OEM Root Public Key.
    
    Options:
        --oem-root-key-id: AWS KMS Key ID for OEM Root key. If not provided, will prompt.
    """
    _run_workflow_command(ctx, 'generate-rkey', oem_root_key_id=oem_root_key_id)



@task(name="sign-app")
def sign_app(ctx, app_bin=None, kms_key_id=None, version=None, out=None, config=None, production=False):
    """
    Sign MCUboot application with HSM backend (PKCS#11 Broker or AWS KMS direct).
    
    Steps:
    1. Sign application binary via configured HSM backend
    2. Produce MCUboot-format signed binary (app.bin.signed)
    
    Options:
        --app-bin: Application binary file (e.g., app.bin)
        --kms-key-id: AWS KMS Key ID for MCUboot APP signing
        --version: Application version (e.g., '1.0.0')
        --out: Output signed binary file
        --config: Path to project_config.json (recommended)
        --production: Production mode (blocks temporary local keys)
    
    Example:
        invoke sign-app --config project_config.json
        invoke sign-app --app-bin prerequisites/app.bin --version 1.0.0
    """
    # Run new refactored command directly (not through workflow group)
    python_exe = sys.executable
    cmd_parts = [python_exe, '-m', 'cli', 'sign-app']
    
    if app_bin:
        cmd_parts.extend(['--app-bin', str(app_bin)])
    if kms_key_id:
        cmd_parts.extend(['--kms-key-id', str(kms_key_id)])
    if version:
        cmd_parts.extend(['--version', str(version)])
    if out:
        cmd_parts.extend(['--out', str(out)])
    if config:
        cmd_parts.extend(['--config', str(config)])
    if production:
        cmd_parts.append('--production')
    
    result = subprocess.run(cmd_parts, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


@task(name="generate-rkey")
def generate_rkey(ctx, oem_root_key_id=None, config=None):
    """
    [NEW] Generate RKEY (wrapped OEM Root Public Key) for device programming.
    
    RKEY = OEM Root PK encrypted/wrapped with UFPK (User Factory Programming Key).
    Required by Renesas FSBL - device will NOT accept plain public keys!
    
    Prerequisites:
        1. Run 'invoke prepare-ufpk' first to get UFPK
        2. Have OEM Root Key in AWS KMS
    
    Options:
        --oem-root-key-id: AWS KMS Key ID for OEM Root key
        --config: Path to project_config.json
    
    Example:
        invoke generate-rkey
        invoke generate-rkey --oem-root-key-id 3ce24d75-caec-4ba9-b10a-38f7c3ff6dc0
    
    Next Steps:
        After RKEY generation:
        1. invoke sign-app            # Sign application with AWS KMS
        2. invoke make-combined-srec  # Combine bootloader + signed app
        3. invoke gen-fsbl-certs      # Generate FSBL certificates
        4. invoke program-device      # Flash to device
        Or run steps 1-3 at once: invoke workflow-all
    """
    python_exe = sys.executable
    cmd_parts = [python_exe, '-m', 'cli', 'generate-rkey']
    
    if oem_root_key_id:
        cmd_parts.extend(['--oem-root-key-id', str(oem_root_key_id)])
    if config:
        cmd_parts.extend(['--config', str(config)])
    
    result = subprocess.run(cmd_parts, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


@task(name="gen-fsbl-certs")
def gen_fsbl_certs(ctx, oemroot_kms_key_id=None, oembl_kms_key_id=None, oembl_srec=None, 
                   combined_srec=None, loadaddr=None, oembl_size=None, ver=None, out=None, config=None):
    """
    [NEW] Generate FSBL Certificates (Key Certificate + Code Certificate).
    
    This is the NEW refactored command for certificate generation.
    
    IMPORTANT WORKFLOW ORDER:
        1. invoke sign-app           # Sign application first
        2. invoke make-combined-srec # Create combined.srec
        3. invoke gen-fsbl-certs --combined-srec output/flow_*/combined.srec
        4. invoke program-device     # Program device
    
    Steps:
    1. Export public keys from AWS KMS
    2. Generate Key Certificate (signed with OEM_ROOT_SK)
    3. Generate Code Certificate (signed with OEM_BL_SK)
    4. Validate TLV structure, KEYHASH==SIGNER_ID, signatures, CRC32
    
    Options:
        --oemroot-kms-key-id: AWS KMS Key ID for OEM Root Secret Key
        --oembl-kms-key-id: AWS KMS Key ID for OEM Bootloader Secret Key
        --oembl-srec: Path to OEM Bootloader SREC
        --combined-srec: Path to combined SREC (bootloader+app) for CRC calculation!
                        CRITICAL: Use this for correct FSBL CRC verification!
        --loadaddr: Load address (hex, e.g., '0x02000000')
        --oembl-size: OEM_BL size (hex, e.g., '0x00030000' = 192KB)
        --ver: Certificate version for anti-rollback (1-64)
        --out: Output directory for certificates
        --config: Path to project_config.json
    
    Example:
        invoke gen-fsbl-certs --combined-srec output/flow_20260122_211657/combined.srec
    """
    python_exe = sys.executable
    cmd_parts = [python_exe, '-m', 'cli', 'gen-fsbl-certs']
    
    if oemroot_kms_key_id:
        cmd_parts.extend(['--oemroot-kms-key-id', str(oemroot_kms_key_id)])
    if oembl_kms_key_id:
        cmd_parts.extend(['--oembl-kms-key-id', str(oembl_kms_key_id)])
    if oembl_srec:
        cmd_parts.extend(['--oembl-srec', str(oembl_srec)])
    if combined_srec:
        cmd_parts.extend(['--combined-srec', str(combined_srec)])
    if loadaddr:
        cmd_parts.extend(['--loadaddr', str(loadaddr)])
    if oembl_size:
        cmd_parts.extend(['--oembl-size', str(oembl_size)])
    if ver:
        cmd_parts.extend(['--ver', str(ver)])
    if out:
        cmd_parts.extend(['--out', str(out)])
    if config:
        cmd_parts.extend(['--config', str(config)])
    
    result = subprocess.run(cmd_parts, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


@task(name="make-combined-srec")
def make_combined_srec(ctx, bootloader_srec=None, app_signed_bin=None, app_offset=None, 
                       codecert_bin=None, out=None, config=None, inject_aws_key=True):
    """
    [NEW] Combine bootloader and signed app into combined.srec.
    
    RENESAS-CORRECT workflow:
    - combined.srec = bootloader.srec + app_signed_offset.srec ONLY
    - Code Certificate is programmed SEPARATELY via boot interface
    - AWS KMS public key is INJECTED into bootloader (replaces demo key)
    
    Steps:
    1. Convert app.bin.signed to SREC with offset + execution start address
    1.5. INJECT AWS KMS mcuboot_app_key into bootloader (at 0x02009114)
    2. Combine bootloader_with_aws_key.srec + app_offset.srec
    3. Verify: no overlaps, correct S5/S7 records
    
    Options:
        --bootloader-srec: Bootloader SREC file
        --app-signed-bin: Signed application binary (from sign-app-new)
        --app-offset: Application offset address (hex, e.g., '0x2010000')
        --codecert-bin: Code Certificate (DEPRECATED - ignored)
        --out: Output combined SREC file
        --config: Path to project_config.json
        --inject-aws-key: Inject AWS KMS key into bootloader (default: True)
    
    Example:
        invoke make-combined-srec --app-signed-bin output/flow_*/app.bin.signed
    """
    python_exe = sys.executable
    cmd_parts = [python_exe, '-m', 'cli', 'make-combined-srec']
    
    # Always inject AWS key by default
    if inject_aws_key:
        cmd_parts.append('--inject-aws-key')
    else:
        cmd_parts.append('--no-inject-aws-key')
    
    if bootloader_srec:
        cmd_parts.extend(['--bootloader-srec', str(bootloader_srec)])
    if app_signed_bin:
        cmd_parts.extend(['--app-signed-bin', str(app_signed_bin)])
    if app_offset:
        cmd_parts.extend(['--app-offset', str(app_offset)])
    if codecert_bin:
        cmd_parts.extend(['--codecert-bin', str(codecert_bin)])
    if out:
        cmd_parts.extend(['--out', str(out)])
    if config:
        cmd_parts.extend(['--config', str(config)])
    
    result = subprocess.run(cmd_parts, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)


@task(name="workflow-all")
def workflow_all(ctx, config=None):
    """
    Complete workflow: generate-rkey -> sign-app -> make-combined-srec -> gen-fsbl-certs.
    
    Steps:
    0. generate-rkey: Generate RKEY (skipped if already exists)
    1. sign-app: Sign application with AWS KMS (MCUboot format)
    2. make-combined-srec: Combine bootloader + signed app
    3. gen-fsbl-certs: Generate certificates WITH combined.srec for CRC!
    
    Prerequisites:
        - Run 'invoke prepare-ufpk' first (one-time per device type)
        - bootloader.srec and application.bin in prerequisites/
        - AWS KMS keys configured in project_config.json
    
    After this, use 'invoke program-device' to flash to device.
    
    Options:
        --config: Path to project_config.json (recommended)
    
    Example:
        invoke workflow-all
    """
    import json
    from pathlib import Path
    
    # Read inject_customer_key from config
    inject_customer_key = True  # Default
    config_path = Path(config) if config else Path("project_config.json")
    if config_path.exists():
        with open(config_path, 'r') as f:
            cfg = json.load(f)
        inject_customer_key = cfg.get("firmware", {}).get("inject_customer_key", True)
    
    print("\n" + "="*70)
    print("STARTING COMPLETE PROVISIONING WORKFLOW")
    print("="*70)
    print("Order: generate-rkey -> sign-app -> make-combined-srec -> gen-fsbl-certs")
    print("-"*70)
    
    # Display key injection mode prominently
    if inject_customer_key:
        print("[KEY MODE] INJECT CUSTOMER KEY into bootloader")
        print("           MCUboot will verify apps signed with YOUR AWS KMS key")
    else:
        print("[KEY MODE] KEEP ORIGINAL RENESAS DEMO KEY in bootloader")
        print("           Bootloader will verify apps signed with Renesas demo key")
    print("="*70 + "\n")
    
    # Step 0: Generate RKEY (if not already present)
    output_dir = Path(cfg.get("paths", {}).get("output_dir", "output"))
    flow_dirs = sorted(
        [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    
    if not flow_dirs:
        print("[ERROR] No flow directory found! Run 'invoke prepare-ufpk' first.")
        sys.exit(1)
    
    flow_folder = flow_dirs[0]
    rkey_path = flow_folder / "oem_root_key.rkey"
    
    # Also check reusable folder
    reusable_rkey = output_dir / "reusable" / "oem_root_key.rkey"
    
    if rkey_path.exists():
        print(f"Step 0: RKEY already exists: {rkey_path.name} (skipping)")
    elif reusable_rkey.exists():
        import shutil
        shutil.copy2(reusable_rkey, rkey_path)
        print(f"Step 0: RKEY copied from reusable folder: {rkey_path.name}")
    else:
        print("Step 0: Generating RKEY (wrapped OEM Root Public Key)...")
        generate_rkey(ctx, config=config)
    
    # Step 1: Sign app
    print("\nStep 1: Signing application...")
    sign_app(ctx, config=config)
    
    # Step 2: Make combined SREC (BEFORE certificates!)
    print("\nStep 2: Creating combined SREC...")
    make_combined_srec(ctx, config=config, inject_aws_key=inject_customer_key)
    
    # Re-scan flow dirs to find the combined.srec (may be in a new flow folder)
    flow_dirs = sorted(
        [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("flow_")],
        key=lambda d: d.stat().st_mtime,
        reverse=True
    )
    
    if not flow_dirs:
        print("[ERROR] No flow directory found!")
        sys.exit(1)
    
    combined_srec = flow_dirs[0] / "combined.srec"
    if not combined_srec.exists():
        print(f"[ERROR] combined.srec not found: {combined_srec}")
        sys.exit(1)
    
    # Step 3: Generate certificates WITH combined.srec for correct CRC!
    print("\nStep 3: Generating FSBL certificates (using combined.srec for CRC)...")
    gen_fsbl_certs(ctx, combined_srec=str(combined_srec), config=config)
    
    print("\n" + "="*70)
    print("[OK] WORKFLOW COMPLETED!")
    print("="*70)
    print("\nNext step: invoke program-device")
    print("")



@task
def program_device(ctx, com_port=None, lock_device=False, bootloader_binary=None, skip_initialize=False):
    """
    Step 8: Program device with all generated files.
    
    Options:
        --com-port: COM port for device programming. If not provided, will auto-detect or prompt.
        --lock-device: Lock device to LCK_BOOT state after provisioning.
        --bootloader-binary: Bootloader binary if not using combined.srec.
        --skip-initialize: Skip device initialization (if already initialized).
    """
    _run_workflow_command(
        ctx,
        'program-device',
        com_port=com_port,
        lock_device=lock_device,
        bootloader_binary=bootloader_binary,
        skip_initialize=skip_initialize
    )


@task
def export_pgp_public_key(ctx, output=None):
    """
    Export customer PGP public key for Renesas key exchange.
    
    This exports your PGP public key that you need to paste into
    the DLM website's PGP key exchange form.
    
    Options:
        --output: Output file path (default: customer_public_key.asc)
    """
    _run_workflow_command(ctx, 'export-pgp-public-key', output=output)


@task
def help(ctx):
    """Show workflow help."""
    _run_workflow_command(ctx, 'cli-help')


@task(name="cli-help")
def cli_commands_help(ctx, section="all"):
    """
    Interactive CLI Commands Reference Guide.
    
    Shows complete documentation about the provisioning workflow,
    all available commands, their inputs, outputs, and usage examples.
    
    Options:
        --section: Show specific section only (all, flow, commands, files)
    
    Examples:
        invoke cli-help                    # Show all documentation
        invoke cli-help --section=flow     # Show only workflow overview
        invoke cli-help --section=commands # Show only commands reference
        invoke cli-help --section=files    # Show only file reference
    """
    _run_workflow_command(ctx, 'cli-help', section=section)


@task(name="generate-docs")
def generate_docs(ctx, diagrams=False, html=True):
    """
    Generate API documentation and class diagrams.
    
    This command generates:
    - Sphinx HTML documentation from docstrings
    - Class diagrams using pyreverse (optional)
    
    Prerequisites:
        pip install sphinx sphinx-rtd-theme pylint
    
    Options:
        --diagrams: Generate class diagrams with pyreverse
        --no-html: Skip HTML documentation generation
    
    Examples:
        invoke generate-docs                    # Generate HTML docs only
        invoke generate-docs --diagrams         # Generate docs + diagrams
    
    Output:
        docs/_build/html/index.html            # HTML documentation
        docs/diagrams/*.png                    # Class diagrams (if --diagrams)
    """
    import os
    
    print("\n" + "="*70)
    print("GENERATING DOCUMENTATION")
    print("="*70)

    repo_root = Path(__file__).parent.parent
    sphinx_source = repo_root / "doc" / "source"
    sphinx_build = repo_root / "doc" / "_build"
    
    if not sphinx_source.exists():
        print(f"[ERROR] Sphinx source directory not found: {sphinx_source}")
        print(f"  Expected at: {sphinx_source.absolute()}")
        sys.exit(1)
    
    if diagrams:
        print("\n[1/2] Generating class diagrams...")
        diagrams_dir = sphinx_build / "diagrams"
        diagrams_dir.mkdir(parents=True, exist_ok=True)
        
        modules = [
            ("cli/commands", "CLI"),
            ("device", "Device"),
            ("firmware", "Firmware"),
            ("security", "Security"),
            ("utils", "Utils"),
        ]
        
        for module_path, module_name in modules:
            print(f"  - {module_name} module...")
            result = subprocess.run(
                [sys.executable, "-m", "pylint.pyreverse.main", 
                 "-o", "png", "-p", module_name, module_path, 
                 "-d", str(diagrams_dir)],
                capture_output=True, text=True
            )
        
        print(f"  Diagrams saved to: {diagrams_dir}")
    
    if html:
        step = "2/2" if diagrams else "1/1"
        print(f"\n[{step}] Building Sphinx HTML documentation...")
        
        result = subprocess.run(
            [sys.executable, "-m", "sphinx", "-b", "html", 
             str(sphinx_source), str(sphinx_build / "html")],
            capture_output=True, text=True
        )
        
        if result.returncode == 0:
            print(f"  HTML docs saved to: {sphinx_build / 'html'}")
        else:
            print(f"  [WARN] Sphinx build had issues:")
            if result.stderr:
                # Show only first few lines of errors
                errors = result.stderr.split('\n')[:5]
                for err in errors:
                    print(f"    {err}")
    
    print("\n" + "="*70)
    print("[OK] DOCUMENTATION GENERATED")
    print("="*70)
    print(f"\nTo view: start {sphinx_build / 'html' / 'index.html'}")
    print("")
