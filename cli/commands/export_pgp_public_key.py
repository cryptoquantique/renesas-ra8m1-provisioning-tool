"""
Export customer PGP public key for key exchange with Renesas.

This command exports the customer's PGP public key in ASCII format
for the PGP key exchange on DLM website.
"""

import sys
import click
from pathlib import Path

from config.loader import ConfigLoader
from security.pgp.client import PGPClient
from utils.exceptions import PGPError
from utils.logging import get_logger

logger = get_logger(__name__)


@click.command("export-pgp-public-key")
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Output file path (default: customer_public_key.asc in current directory)",
)
@click.pass_context
def export_pgp_public_key(ctx, output: Path):
    """
    Export customer PGP public key for Renesas key exchange.
    
    This exports your PGP public key in ASCII format that you need to
    paste into the DLM website's PGP key exchange form.
    
    After exporting, you will:
    1. Copy the contents of the exported file
    2. Go to DLM website: https://dlm.renesas.com/keywrap/pgp/
    3. Paste the key content into the form
    4. Click "PGP key exchange"
    5. Renesas will send you their public key via email
    """
    config = ctx.obj["config"]
    
    click.echo("\n" + "="*70)
    click.echo("Export Customer PGP Public Key")
    click.echo("="*70 + "\n")
    
    # Check if customer private key exists
    customer_private_key = Path(config.pgp.customer_private_key)
    if not customer_private_key.exists():
        click.echo(f"   [ERROR] Customer private key not found: {customer_private_key}", err=True)
        click.echo("", err=True)
        click.echo("   Please:", err=True)
        click.echo("      1. Generate a PGP key pair first", err=True)
        click.echo("      2. Or configure customer_private_key in settings", err=True)
        click.echo("", err=True)
        click.echo("   [WARN]  IMPORTANT: Renesas DLM requires RSA 2048 or 3072 bits (NOT 4096!)", err=True)
        click.echo("", err=True)
        click.echo("   To generate a PGP key pair with correct length:", err=True)
        click.echo("      Use: tests\\generate_pgp_key.ps1", err=True)
        click.echo("      Or manually: gpg --full-generate-key (select RSA 2048 or 3072)", err=True)
        click.echo("", err=True)
        sys.exit(1)
    
    # Verify key length is correct for Renesas (2048 or 3072, NOT 4096)
    try:
        import subprocess
        result = subprocess.run(
            [config.pgp.gpg_path, "--list-secret-keys", "--with-colons", str(customer_private_key)],
            capture_output=True,
            timeout=10,
            check=False
        )
        
        if result.returncode == 0:
            for line in result.stdout.decode().split("\n"):
                if line.startswith("pub:"):
                    parts = line.split(":")
                    key_type = parts[3]  # 1 = RSA
                    key_length = parts[2]  # Key length in bits
                    
                    if key_type == "1":  # RSA
                        key_length_int = int(key_length)
                        if key_length_int == 4096:
                            click.echo("", err=True)
                            click.echo("   [ERROR] ERROR: Your PGP key is RSA 4096 bits!", err=True)
                            click.echo("", err=True)
                            click.echo("   [WARN]  Renesas DLM does NOT accept RSA 4096 bits!", err=True)
                            click.echo("      Renesas only accepts RSA 2048 or 3072 bits", err=True)
                            click.echo("", err=True)
                            click.echo("   [OK] Solution: Generate a new key with correct length:", err=True)
                            click.echo("      1. Run: .\\tests\\generate_pgp_key.ps1", err=True)
                            click.echo("      2. Or manually generate RSA 2048/3072 key", err=True)
                            click.echo("      3. Then export the public key again", err=True)
                            click.echo("", err=True)
                            sys.exit(1)
                        elif key_length_int not in [2048, 3072]:
                            click.echo(f"   [WARN]  Warning: Key length is {key_length_int} bits", err=True)
                            click.echo("      Renesas recommends RSA 2048 or 3072 bits", err=True)
                            if not click.confirm("      Continue anyway?", default=False):
                                sys.exit(1)
    except Exception as e:
        logger.debug(f"Could not verify key length: {e}")
    
    # Determine output file - save to prerequisites folder
    if output is None:
        prerequisites_dir = Path("prerequisites")
        prerequisites_dir.mkdir(exist_ok=True)
        output = prerequisites_dir / "customer_public_key.asc"
    
    click.echo(f"   [KEY] Customer private key: {customer_private_key.name}")
    click.echo(f"   [FILE] Output file: {output.absolute()}\n")
    
    try:
        pgp_client = PGPClient(config.pgp)
        
        # Export public key from private key
        click.echo("   Exporting public key from private key...")
        pgp_client.export_public_key_from_private(
            private_key_file=customer_private_key,
            output_file=output
        )
        
        click.echo(f"   [+] Public key exported: {output.name}")
        click.echo(f"   [FILE] Saved to: {output.absolute()}\n")
        
        # Read and display key content
        key_content = output.read_text(encoding="utf-8")
        
        click.echo("="*70)
        click.echo("[OK] Public Key Exported Successfully!")
        click.echo("="*70)
        click.echo("\n[INFO] Next steps:")
        click.echo("   1. Open the exported file:")
        click.echo(f"      {output.absolute()}")
        click.echo("")
        click.echo("   2. Copy ALL the content (from -----BEGIN to -----END)")
        click.echo("")
        click.echo("   3. Go to DLM website:")
        click.echo("      https://dlm.renesas.com/keywrap/pgp/")
        click.echo("")
        click.echo("   4. Paste the key content into the form")
        click.echo("")
        click.echo("   5. Click 'PGP key exchange' button")
        click.echo("")
        click.echo("   6. Check your email for Renesas public key")
        click.echo("")
        click.echo("   7. Save Renesas public key and update config.yaml")
        click.echo("")
        
        # Show preview
        click.echo("="*70)
        click.echo("Key Preview (first 3 lines):")
        click.echo("="*70)
        lines = key_content.split("\n")[:3]
        for line in lines:
            click.echo(f"   {line}")
        click.echo("   ...")
        click.echo("")
        
    except PGPError as e:
        click.echo(f"   [ERROR] Export failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"   [ERROR] Unexpected error: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)

