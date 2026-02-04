"""
Device chip erase command using Renesas Flash Programmer CLI.
"""

import click
import subprocess
import sys
from pathlib import Path
from device.ra8_provisioning_client import RA8ProvisioningClient
from utils.logging import get_logger

logger = get_logger(__name__)


@click.command("chip-erase")
@click.option(
    "--com-port",
    type=str,
    help="COM port for device. If not provided, will auto-detect.",
)
@click.option(
    "--rfp-path",
    type=click.Path(exists=True),
    help="Path to rfp-cli.exe (Renesas Flash Programmer CLI)",
)
@click.pass_context
def chip_erase(ctx, com_port: str, rfp_path: str):
    """
    Perform complete chip erase to reset device to CM state.
    
    This will:
    - Erase ALL flash memory
    - Clear OEM Root Key (RKEY)
    - Reset ARC_OEMBL counter to 0
    - Reset DLM state to CM
    - Reset Protection Level to PL0
    
    WARNING: This is IRREVERSIBLE! All data will be lost.
    """
    
    click.echo("\n" + "="*70)
    click.echo("RA8M1 Chip Erase")
    click.echo("="*70 + "\n")
    
    click.echo("[WARN] This will ERASE the ENTIRE device:")
    click.echo("       - All flash memory")
    click.echo("       - OEM Root Key (RKEY)")
    click.echo("       - Certificates")
    click.echo("       - Anti-rollback counter (ARC_OEMBL)")
    click.echo("       - Application firmware")
    click.echo("")
    
    if not click.confirm("Are you ABSOLUTELY SURE you want to proceed?"):
        click.echo("Aborted.")
        sys.exit(0)
    
    # Get COM port
    if not com_port:
        com_port = RA8ProvisioningClient.find_ra_com_port()
        if not com_port:
            ports = RA8ProvisioningClient.list_com_ports()
            if not ports:
                click.echo("[ERROR] No COM ports found!", err=True)
                sys.exit(1)
            click.echo("Available COM ports:")
            for i, port in enumerate(ports, 1):
                click.echo(f"  {i}. {port}")
            selection = click.prompt("Select COM port", type=int)
            if selection < 1 or selection > len(ports):
                click.echo("[ERROR] Invalid selection!", err=True)
                sys.exit(1)
            com_port = ports[selection - 1]
    
    click.echo(f"\n[COM] Using COM port: {com_port}")
    
    # Find RFP CLI
    if not rfp_path:
        click.echo("\n[INFO] Searching for Renesas Flash Programmer CLI...")
        
        # Common installation paths
        search_paths = [
            r"C:\Renesas\RA\e2studio_2024-10\Internal\RFP\rfp-cli.exe",
            r"C:\Renesas\RA\e2studio_2024-07\Internal\RFP\rfp-cli.exe",
            r"C:\Renesas\RA\e2studio_2024-04\Internal\RFP\rfp-cli.exe",
            r"C:\Renesas\RA\e2studio_2023-10\Internal\RFP\rfp-cli.exe",
            r"C:\Renesas\e2_studio\Internal\RFP\rfp-cli.exe",
            r"C:\Program Files\Renesas\RFP\rfp-cli.exe",
        ]
        
        rfp_path = None
        for path_str in search_paths:
            path = Path(path_str)
            if path.exists():
                rfp_path = str(path)
                click.echo(f"[+] Found RFP CLI: {path}")
                break
        
        if not rfp_path:
            click.echo("[ERROR] Renesas Flash Programmer CLI not found!", err=True)
            click.echo("", err=True)
            click.echo("Please install FSP (Flexible Software Package) which includes RFP:", err=True)
            click.echo("  https://www.renesas.com/software-tool/flexible-software-package-fsp", err=True)
            click.echo("", err=True)
            click.echo("Or provide path manually:", err=True)
            click.echo("  python -m cli device chip-erase --rfp-path 'C:\\path\\to\\rfp-cli.exe'", err=True)
            sys.exit(1)
    
    # Execute chip erase
    click.echo("\n" + "-"*70)
    click.echo("Executing Chip Erase...")
    click.echo("-"*70 + "\n")
    
    cmd = [
        rfp_path,
        "-device", "R7FA8M1AH",
        "-port", com_port,
        "-erase", "all",
        "-auto",  # Auto mode (no prompts)
    ]
    
    click.echo(f"[CMD] {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Show output
        if result.stdout:
            click.echo(result.stdout)
        
        if result.returncode == 0:
            click.echo("\n" + "="*70)
            click.echo("[OK] Chip Erase Complete!")
            click.echo("="*70 + "\n")
            
            click.echo("[INFO] Device state after erase:")
            click.echo("       - DLM: CM (Chip Manufacturer)")
            click.echo("       - Protection Level: PL0")
            click.echo("       - Authentication Level: AL0")
            click.echo("       - ARC_OEMBL: 0 (counter reset)")
            click.echo("")
            
            click.echo("[NEXT] You can now run the provisioning workflow:")
            click.echo("       python -m cli workflow program-device")
            click.echo("")
            click.echo("[TIP] If using certificates, update version to 1:")
            click.echo("      python -m cli version set 1")
            click.echo("")
        else:
            click.echo("\n[ERROR] Chip erase failed!", err=True)
            if result.stderr:
                click.echo(result.stderr, err=True)
            sys.exit(1)
    
    except subprocess.TimeoutExpired:
        click.echo("\n[ERROR] Chip erase timed out!", err=True)
        click.echo("[TIP] Try manual erase using Renesas Flash Programmer GUI", err=True)
        sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n[ERROR] Chip erase failed: {e}", err=True)
        sys.exit(1)
