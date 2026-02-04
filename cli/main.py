"""
Main CLI entry point.

This module provides the main CLI interface using Click.
"""

import sys
import os
from pathlib import Path

# Auto-reload modules in development mode (avoid having to restart terminal)
# MUST happen BEFORE any cli.commands imports!
if os.getenv("PROVISIONING_DEV_MODE", "1") == "1":
    # Clear module cache for cli.commands to force reload
    modules_to_reload = [key for key in list(sys.modules.keys()) if key.startswith('cli.commands')]
    for module_name in modules_to_reload:
        try:
            del sys.modules[module_name]
        except KeyError:
            pass

import click

from config.loader import ConfigLoader
from utils.logging import setup_logging

# Active commands:
from cli.commands.workflow import workflow_group
from cli.commands.workflow_ufpk_prepare import prepare_ufpk
from cli.commands.export_pgp_public_key import export_pgp_public_key
from cli.commands.setup_keys import setup_keys_group
from cli.commands.version import version_group
from cli.commands.chip_erase import chip_erase

# New refactored commands (4-step workflow)
from cli.commands.sign_app import sign_app_command
from cli.commands.gen_fsbl_certs import gen_fsbl_certs_command
from cli.commands.make_combined_srec import make_combined_srec_command
from cli.commands.generate_rkey import generate_rkey_command


@click.group()
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to configuration file (YAML)",
)
@click.option(
    "--verbose", "-v", is_flag=True, help="Enable verbose logging"
)
@click.pass_context
def cli(ctx, config, verbose):
    """
    RA8M1 Provisioning Tool - Command Line Interface.

    Provides all provisioning operations via command line.
    """
    ctx.ensure_object(dict)

    try:
        config_loader = ConfigLoader(config)
        config_obj = config_loader.load()
    except Exception as e:
        if verbose:
            click.echo(f"Warning: Could not load configuration: {e}", err=True)
        from config.settings import ProvisioningToolConfig
        config_obj = ProvisioningToolConfig()

    if verbose:
        config_obj.logging.level = "DEBUG"

    setup_logging(
        log_level=config_obj.logging.level,
        log_file=config_obj.logging.file_path,
        enable_console=config_obj.logging.enable_console,
    )

    ctx.obj["config"] = config_obj


# Active commands:
cli.add_command(workflow_group)
cli.add_command(setup_keys_group)
cli.add_command(prepare_ufpk)
cli.add_command(export_pgp_public_key)
cli.add_command(version_group)
cli.add_command(chip_erase)

# New refactored commands (4-step workflow)
cli.add_command(sign_app_command)
cli.add_command(gen_fsbl_certs_command)
cli.add_command(make_combined_srec_command)
cli.add_command(generate_rkey_command)


def main():
    """Main entry point for CLI."""
    import sys
    
    # If called as 'workflow' entry point, adjust argv
    # sys.argv[0] will be 'workflow' or 'workflow.exe'
    # We need to change it to 'cli' so Click recognizes it
    if len(sys.argv) > 0 and ('workflow' in sys.argv[0] or sys.argv[0].endswith('workflow.exe')):
        # Reconstruct: ['workflow', 'start'] -> ['cli', 'workflow', 'start']
        sys.argv = ['cli'] + sys.argv[1:]
    
    cli(obj={})


if __name__ == "__main__":
    main()
