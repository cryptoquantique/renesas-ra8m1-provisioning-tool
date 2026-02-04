"""
Certificate version management CLI commands.
"""

import click
from utils.version_manager import (
    get_current_certificate_version,
    increment_certificate_version,
    set_certificate_version,
    check_version_overflow,
)
from utils.logging import get_logger

logger = get_logger(__name__)


@click.group("version")
def version_group():
    """Manage certificate version for anti-rollback protection."""
    pass


@version_group.command("show")
def show_version():
    """Show current certificate version."""
    current, remaining, is_critical = check_version_overflow()
    
    click.echo("\n" + "="*70)
    click.echo("Certificate Version Status")
    click.echo("="*70 + "\n")
    
    click.echo(f"Current version: {current}")
    click.echo(f"Next version:    {current + 1}")
    click.echo(f"Versions used:   {current}/64")
    click.echo(f"Remaining:       {remaining}/64")
    
    if is_critical:
        click.echo("\n[WARN] Critical: Only {} versions remaining!".format(remaining))
        click.echo("[WARN] Consider re-initializing device or using new keys.")
    elif remaining <= 15:
        click.echo("\n[INFO] Warning: Only {} versions remaining.".format(remaining))
    else:
        click.echo("\n[OK] Sufficient versions remaining.")
    
    click.echo("\n" + "="*70)
    click.echo("Anti-Rollback Protection Info")
    click.echo("="*70 + "\n")
    click.echo("The RA8M1 Anti-Rollback Counter (ARC_OEMBL) prevents downgrade attacks.")
    click.echo("Each certificate generation increments the version counter.")
    click.echo("Maximum 64 versions supported (64-bit counter).")
    click.echo("")


@version_group.command("set")
@click.argument("version", type=int)
def set_version_cmd(version: int):
    """
    Set certificate version to a specific value.
    
    WARNING: Only use this if you know the current ARC_OEMBL value on your device!
    Setting a version lower than the device's ARC_OEMBL will cause programming to fail.
    """
    if not (1 <= version <= 64):
        click.echo(f"[ERROR] Version must be between 1 and 64, got: {version}", err=True)
        return
    
    current = get_current_certificate_version()
    
    click.echo(f"\nCurrent version: {current}")
    click.echo(f"New version:     {version}")
    
    if version < current:
        click.echo("\n[WARN] You are setting a LOWER version than current!")
        click.echo("[WARN] This will fail if device ARC_OEMBL >= {}.".format(version))
        click.echo("[WARN] Only do this if you know the device counter is lower.")
        if not click.confirm("Are you sure?"):
            click.echo("Aborted.")
            return
    
    try:
        set_certificate_version(version)
        click.echo(f"\n[OK] Certificate version set to {version}")
        click.echo(f"[OK] Next certificate will use version {version}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to set version: {e}", err=True)


@version_group.command("increment")
def increment_version_cmd():
    """Manually increment certificate version."""
    current = get_current_certificate_version()
    
    click.echo(f"\nCurrent version: {current}")
    click.echo(f"Next version:    {current + 1}")
    
    if not click.confirm("Increment version?"):
        click.echo("Aborted.")
        return
    
    try:
        new_version = increment_certificate_version()
        click.echo(f"\n[OK] Version incremented: {current} → {new_version}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to increment version: {e}", err=True)


@version_group.command("reset")
@click.option("--start-version", type=int, default=25, help="Starting version (default: 25)")
def reset_version(start_version: int):
    """
    Reset certificate version to starting value.
    
    Use this when starting with a fresh device or after chip erase.
    Default starting version is 25 (accounting for previous attempts).
    """
    current = get_current_certificate_version()
    
    click.echo(f"\nCurrent version:  {current}")
    click.echo(f"Reset to version: {start_version}")
    
    click.echo("\n[WARN] Only reset if you have:")
    click.echo("[WARN]   1. Erased the device completely (chip erase)")
    click.echo("[WARN]   2. Know the device ARC_OEMBL counter value")
    click.echo("")
    
    if not click.confirm("Reset version?"):
        click.echo("Aborted.")
        return
    
    try:
        set_certificate_version(start_version)
        click.echo(f"\n[OK] Version reset to {start_version}")
    except Exception as e:
        click.echo(f"[ERROR] Failed to reset version: {e}", err=True)
