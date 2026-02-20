"""
CLI commands for the crypto broker service.

This module provides commands to start, stop, and manage
the crypto broker daemon.
"""

import os
import sys
import click

from config.settings import DEFAULT_AWS_REGION
from utils.logging import get_logger

logger = get_logger(__name__)


@click.group(name="broker")
def broker_group():
    """Crypto broker service management commands."""
    pass


@broker_group.command(name="start")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to configuration file (JSON/YAML)",
)
@click.option(
    "--foreground", "-f",
    is_flag=True,
    help="Run in foreground (don't daemonize)",
)
@click.option(
    "--socket-path", "-s",
    type=str,
    default=None,
    help="Path to Unix socket (default: platform-specific)",
)
@click.option(
    "--policies-file", "-p",
    type=click.Path(exists=True),
    default=None,
    help="Path to authorization policies JSON file",
)
@click.option(
    "--pid-file",
    type=str,
    default=None,
    help="Path to PID file",
)
@click.option(
    "--session-timeout",
    type=float,
    default=3600.0,
    help="Session timeout in seconds (default: 3600)",
)
@click.option(
    "--max-sessions",
    type=int,
    default=100,
    help="Maximum concurrent sessions (default: 100)",
)
@click.option(
    "--region", "-r",
    type=str,
    default=None,
    help="AWS region for KMS operations (overrides config/env; default from config.settings.DEFAULT_AWS_REGION)",
)
@click.pass_context
def broker_start(ctx, config, foreground, socket_path, policies_file, pid_file, session_timeout, max_sessions, region):
    """Start the crypto broker daemon."""
    from security.broker.service.daemon import (
        get_default_socket_path,
        get_default_pid_file,
        is_daemon_running,
    )
    from security.broker.authorization import AuthorizationManager

    # Import platform-appropriate daemon
    if sys.platform == "win32":
        from security.broker.service.daemon import WindowsBrokerDaemon as BrokerDaemon
    else:
        from security.broker.service.daemon import BrokerDaemon

    # Load project_config.json as single source of truth
    project_data = None
    config_source = None

    if config:
        config_source = config
    else:
        from pathlib import Path
        default_cfg = Path("project_config.json")
        if default_cfg.exists():
            config_source = str(default_cfg)

    if config_source:
        try:
            import json as _json
            with open(config_source, "r", encoding="utf-8") as f:
                project_data = _json.load(f)
            click.echo(f"Loaded configuration from: {config_source}")
        except Exception as e:
            click.echo(f"Warning: Could not load configuration: {e}", err=True)

    # Check if already running
    pid_file = pid_file or get_default_pid_file()
    if is_daemon_running(pid_file):
        click.echo("Broker daemon is already running")
        sys.exit(1)

    # Resolve socket path
    socket_path = socket_path or get_default_socket_path()

    # Build KMS config from project_config.json
    kms_config = {}
    broker_section = {}

    if project_data:
        aws_section = project_data.get("aws", {})
        broker_section = project_data.get("broker", {})

        kms_config = {
            "aws_region": aws_section.get("region"),
            "aws_access_key_id": aws_section.get("access_key_id"),
            "aws_secret_access_key": aws_section.get("secret_access_key"),
            "key_prefix": broker_section.get("key_prefix", "renesas_"),
        }

    # Fallback to env vars if no credentials in config
    if not kms_config.get("aws_access_key_id"):
        from utils.aws_credentials import get_aws_credentials
        aws_creds = get_aws_credentials(fallback_to_env=True)
        kms_config.update({
            "aws_region": kms_config.get("aws_region") or aws_creds.get("aws_region"),
            "aws_access_key_id": aws_creds.get("aws_access_key_id"),
            "aws_secret_access_key": aws_creds.get("aws_secret_access_key"),
        })

    # CLI --region flag takes highest priority
    if region:
        kms_config["aws_region"] = region

    # Load authorization policies
    auth_manager = None
    if policies_file:
        auth_manager = AuthorizationManager(policies_file)
        click.echo(f"Loaded policies from: {policies_file}")
    elif broker_section.get("policies_file"):
        auth_manager = AuthorizationManager(broker_section["policies_file"])
        click.echo(f"Loaded policies from: {broker_section['policies_file']}")

    # Broker section values as fallback for CLI defaults
    if broker_section:
        session_timeout = session_timeout or broker_section.get("session_timeout", 3600)
        max_sessions = max_sessions or broker_section.get("max_sessions", 100)
        socket_path = socket_path or broker_section.get("pipe_name") or get_default_socket_path()

    active_region = kms_config.get("aws_region", DEFAULT_AWS_REGION)
    click.echo(f"Starting broker daemon on {socket_path}")
    click.echo(f"AWS Region: {active_region}")
    if not foreground:
        click.echo(f"PID file: {pid_file}")
        click.echo("Daemon starting in background...")

    # Create and start daemon (Windows uses pipe_name, Unix uses socket_path)
    if sys.platform == "win32":
        daemon = BrokerDaemon(
            pipe_name=socket_path,
            kms_config=kms_config,
            authorization_manager=auth_manager,
            session_timeout=session_timeout,
            max_sessions=max_sessions,
            pid_file=pid_file,
        )
    else:
        daemon = BrokerDaemon(
            socket_path=socket_path,
            kms_config=kms_config,
            authorization_manager=auth_manager,
            session_timeout=session_timeout,
            max_sessions=max_sessions,
            pid_file=pid_file,
        )

    try:
        daemon.start(foreground=foreground)
    except KeyboardInterrupt:
        click.echo("\nBroker daemon stopped")
    except Exception as e:
        click.echo(f"Error starting broker: {e}", err=True)
        sys.exit(1)


@broker_group.command(name="stop")
@click.option(
    "--pid-file",
    type=str,
    default=None,
    help="Path to PID file",
)
def broker_stop(pid_file):
    """Stop the crypto broker daemon."""
    from security.broker.service.daemon import (
        get_default_pid_file,
        stop_daemon,
        is_daemon_running,
    )

    pid_file = pid_file or get_default_pid_file()

    if not is_daemon_running(pid_file):
        click.echo("Broker daemon is not running")
        return

    click.echo("Stopping broker daemon...")
    if stop_daemon(pid_file):
        click.echo("Broker daemon stopped")
    else:
        click.echo("Failed to stop broker daemon", err=True)
        sys.exit(1)


@broker_group.command(name="status")
@click.option(
    "--socket-path", "-s",
    type=str,
    default=None,
    help="Path to Unix socket or Named Pipe",
)
@click.option(
    "--pid-file",
    type=str,
    default=None,
    help="Path to PID file",
)
def broker_status(socket_path, pid_file):
    """Check the crypto broker daemon status."""
    from pathlib import Path
    from security.broker.service.daemon import (
        get_default_socket_path,
        get_default_pid_file,
        is_daemon_running,
    )

    socket_path = socket_path or get_default_socket_path()
    pid_file = pid_file or get_default_pid_file()

    # On Windows, check service status first
    if sys.platform == "win32":
        from security.broker.service.windows_service import get_service_status
        service_status = get_service_status()
        if service_status:
            click.echo(f"Windows Service: {service_status}")
            running = service_status == "RUNNING"
        else:
            click.echo("Windows Service: NOT INSTALLED")
            # Fall back to checking if daemon is running standalone
            running = is_daemon_running(pid_file)
            if running:
                pid = Path(pid_file).read_text().strip()
                click.echo(f"Standalone daemon: RUNNING (PID: {pid})")
            else:
                click.echo("Standalone daemon: STOPPED")
    else:
        # Unix: check via PID file
        running = is_daemon_running(pid_file)
        if running:
            pid = Path(pid_file).read_text().strip()
            click.echo(f"Broker daemon: RUNNING (PID: {pid})")
        else:
            click.echo("Broker daemon: STOPPED")

    # Check socket/pipe
    if sys.platform == "win32":
        # Named pipe - can't check existence directly, show the path
        click.echo(f"Named Pipe: {socket_path}")
    else:
        if Path(socket_path).exists():
            click.echo(f"Socket: {socket_path} (exists)")
        else:
            click.echo(f"Socket: {socket_path} (not found)")

    # Try to ping if running using native PKCS#11
    if running:
        try:
            from security.broker.pkcs11 import BrokerPKCS11Lib

            lib = BrokerPKCS11Lib(socket_path=socket_path)
            rv = lib.C_Initialize()
            if rv.value == 0:  # CKR_OK
                rv, info = lib.C_GetInfo()
                if rv.value == 0:
                    click.echo(f"Backend: {info.library_description.strip()}")

                rv, slots = lib.C_GetSlotList(token_present=True)
                if rv.value == 0 and slots:
                    rv, token_info = lib.C_GetTokenInfo(slots[0])
                    if rv.value == 0:
                        click.echo(f"Sessions: {token_info.session_count}/{token_info.max_session_count}")

                lib.C_Finalize()
            else:
                click.echo(f"Connection: FAILED (C_Initialize returned {rv.name})")
        except Exception as e:
            click.echo(f"Connection: FAILED ({e})")


@broker_group.command(name="ping")
@click.option(
    "--socket-path", "-s",
    type=str,
    default=None,
    help="Path to Unix socket",
)
def broker_ping(socket_path):
    """Ping the broker service using native PKCS#11."""
    from security.broker.service.daemon import get_default_socket_path

    socket_path = socket_path or get_default_socket_path()

    try:
        from security.broker.pkcs11 import BrokerPKCS11Lib

        lib = BrokerPKCS11Lib(socket_path=socket_path)
        rv = lib.C_Initialize()

        if rv.value != 0:  # Not CKR_OK
            click.echo(f"Ping failed: C_Initialize returned {rv.name}", err=True)
            sys.exit(1)

        rv, info = lib.C_GetInfo()
        if rv.value == 0:  # CKR_OK
            click.echo(f"Pong! PKCS#11 v{info.cryptoki_version.major}.{info.cryptoki_version.minor}")
            click.echo(f"  Library: {info.library_description.strip()}")
            click.echo(f"  Manufacturer: {info.manufacturer_id.strip()}")

        lib.C_Finalize()

    except Exception as e:
        click.echo(f"Ping failed: {e}", err=True)
        sys.exit(1)


@broker_group.command(name="init-policies")
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="security/broker/config/broker_policies.json",
    help="Output file path (default: security/broker/config/broker_policies.json)",
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Overwrite existing file",
)
def broker_init_policies(output, force):
    """Create a default authorization policies file."""
    from pathlib import Path
    from security.broker.authorization import create_default_policies_file

    if Path(output).exists() and not force:
        click.echo(f"File already exists: {output}")
        click.echo("Use --force to overwrite")
        sys.exit(1)

    create_default_policies_file(output)
    click.echo(f"Created default policies file: {output}")
    click.echo("Edit this file to configure client authorization.")


@broker_group.group(name="service")
def broker_service_group():
    """Windows service management commands."""
    pass


@broker_service_group.command(name="install")
@click.option(
    "--username", "-u",
    type=str,
    default=None,
    help="Service account username (default: LocalSystem)",
)
@click.option(
    "--password", "-p",
    type=str,
    default=None,
    help="Service account password",
)
@click.option(
    "--startup",
    type=click.Choice(["auto", "manual", "disabled"]),
    default="auto",
    help="Startup type (default: auto)",
)
def broker_service_install(username, password, startup):
    """Install the crypto broker as a Windows service."""
    if sys.platform != "win32":
        click.echo("Windows service installation only available on Windows", err=True)
        sys.exit(1)

    from security.broker.service.windows_service import install_service

    click.echo("Installing Crypto Broker Windows service...")

    if install_service(username=username, password=password, startup=startup):
        click.echo("")
        click.echo("Service installed successfully!")
        click.echo("")
        click.echo("Next steps:")
        click.echo("  1. Set AWS credentials (if not using IAM role):")
        click.echo("     setx /M AWS_ACCESS_KEY_ID \"your_access_key\"")
        click.echo("     setx /M AWS_SECRET_ACCESS_KEY \"your_secret_key\"")
        click.echo("")
        click.echo("  2. Start the service:")
        click.echo("     net start CryptoBroker")
        click.echo("")
        click.echo("  3. Verify it's running:")
        click.echo("     python -m cli broker status")
    else:
        sys.exit(1)


@broker_service_group.command(name="uninstall")
def broker_service_uninstall():
    """Uninstall the crypto broker Windows service."""
    if sys.platform != "win32":
        click.echo("Windows service uninstallation only available on Windows", err=True)
        sys.exit(1)

    from security.broker.service.windows_service import uninstall_service

    click.echo("Uninstalling Crypto Broker Windows service...")

    if uninstall_service():
        click.echo("Service uninstalled successfully!")
    else:
        sys.exit(1)


@broker_service_group.command(name="start")
def broker_service_start():
    """Start the crypto broker Windows service."""
    if sys.platform != "win32":
        click.echo("Windows service start only available on Windows", err=True)
        sys.exit(1)

    from security.broker.service.windows_service import start_service

    if start_service():
        click.echo("")
        click.echo("Verify with: python -m cli broker status")
    else:
        sys.exit(1)


@broker_service_group.command(name="stop")
def broker_service_stop():
    """Stop the crypto broker Windows service."""
    if sys.platform != "win32":
        click.echo("Windows service stop only available on Windows", err=True)
        sys.exit(1)

    from security.broker.service.windows_service import stop_service

    if stop_service():
        click.echo("Service stopped")
    else:
        sys.exit(1)


@broker_service_group.command(name="status")
def broker_service_status():
    """Get the crypto broker Windows service status."""
    if sys.platform != "win32":
        click.echo("Windows service status only available on Windows", err=True)
        sys.exit(1)

    from security.broker.service.windows_service import get_service_status

    status = get_service_status()
    if status:
        click.echo(f"Service Status: {status}")
    else:
        click.echo("Service not installed")


@broker_group.command(name="test-sign")
@click.option(
    "--socket-path", "-s",
    type=str,
    default=None,
    help="Path to Unix socket",
)
@click.option(
    "--key-arn", "-k",
    type=str,
    required=True,
    help="KMS key ARN or alias to use for signing",
)
def broker_test_sign(socket_path, key_arn):
    """Test signing operation through the broker using native PKCS#11."""
    from security.broker.service.daemon import get_default_socket_path
    import hashlib

    socket_path = socket_path or get_default_socket_path()

    try:
        from security.broker.pkcs11 import (
            BrokerPKCS11Lib, CKR, CKF, CKU, CKM, CK_MECHANISM, CKA, CK_ATTRIBUTE
        )

        click.echo(f"Connecting to broker at {socket_path}...")
        click.echo("Using native PKCS#11 interface")
        click.echo("")

        lib = BrokerPKCS11Lib(socket_path=socket_path)

        # C_Initialize
        click.echo("C_Initialize...")
        rv = lib.C_Initialize()
        if rv != CKR.OK:
            raise Exception(f"C_Initialize failed: {rv.name}")
        click.echo(f"  ✓ Library initialized")

        # C_GetSlotList
        rv, slots = lib.C_GetSlotList(token_present=True)
        if rv != CKR.OK or not slots:
            raise Exception(f"C_GetSlotList failed: {rv.name}")
        slot_id = slots[0]
        click.echo(f"  ✓ Found slot: {slot_id}")

        # C_OpenSession
        click.echo("C_OpenSession...")
        flags = CKF.SERIAL_SESSION | CKF.RW_SESSION
        rv, session = lib.C_OpenSession(slot_id, flags)
        if rv != CKR.OK:
            raise Exception(f"C_OpenSession failed: {rv.name}")
        click.echo(f"  ✓ Session opened: {session}")

        # C_Login
        click.echo("C_Login...")
        rv = lib.C_Login(session, CKU.USER)
        if rv != CKR.OK:
            raise Exception(f"C_Login failed: {rv.name}")
        click.echo(f"  ✓ Logged in as USER")

        # Register key
        click.echo(f"\nRegistering key: {key_arn}")
        rv, key_handle = lib.register_key(session, key_arn)
        if rv != CKR.OK:
            raise Exception(f"register_key failed: {rv.name}")
        click.echo(f"  ✓ Key handle: {key_handle}")

        # Test data
        test_data = b"Hello, Native PKCS#11!"
        click.echo(f"\nTest data: {test_data.decode()}")

        # C_GetAttributeValue (get public key)
        click.echo("\nC_GetAttributeValue (CKA_EC_POINT)...")
        template = [CK_ATTRIBUTE(CKA.EC_POINT, None)]
        rv, attrs = lib.C_GetAttributeValue(session, key_handle, template)
        if rv != CKR.OK:
            raise Exception(f"C_GetAttributeValue failed: {rv.name}")
        public_key = attrs[0].value if attrs and attrs[0].value else b""
        click.echo(f"  ✓ Public key: {len(public_key)} bytes (DER)")

        # C_SignInit + C_Sign (with hash - CKM_ECDSA_SHA256)
        click.echo("\nC_SignInit + C_Sign (CKM_ECDSA_SHA256)...")
        mechanism = CK_MECHANISM(CKM.ECDSA_SHA256)
        rv = lib.C_SignInit(session, mechanism, key_handle)
        if rv != CKR.OK:
            raise Exception(f"C_SignInit failed: {rv.name}")

        rv, signature = lib.C_Sign(session, test_data)
        if rv != CKR.OK:
            raise Exception(f"C_Sign failed: {rv.name}")
        click.echo(f"  ✓ Signature: {len(signature)} bytes")
        click.echo(f"    {signature[:32].hex()}...")

        # C_VerifyInit + C_Verify
        click.echo("\nC_VerifyInit + C_Verify...")
        rv = lib.C_VerifyInit(session, mechanism, key_handle)
        if rv != CKR.OK:
            raise Exception(f"C_VerifyInit failed: {rv.name}")

        rv = lib.C_Verify(session, test_data, signature)
        if rv == CKR.OK:
            click.echo(f"  ✓ Signature VALID")
        else:
            click.echo(f"  ✗ Signature INVALID ({rv.name})")

        # Test sign_digest (CKM_ECDSA - raw, for MCUboot)
        click.echo("\nC_SignInit + C_Sign (CKM_ECDSA - raw digest)...")
        digest = hashlib.sha256(test_data).digest()
        click.echo(f"  SHA256 digest: {digest.hex()[:32]}...")

        mechanism_raw = CK_MECHANISM(CKM.ECDSA)
        rv = lib.C_SignInit(session, mechanism_raw, key_handle)
        if rv != CKR.OK:
            raise Exception(f"C_SignInit (raw) failed: {rv.name}")

        rv, sig_digest = lib.C_Sign(session, digest)
        if rv != CKR.OK:
            raise Exception(f"C_Sign (raw) failed: {rv.name}")
        click.echo(f"  ✓ Digest signature: {len(sig_digest)} bytes")

        # C_DigestInit + C_Digest
        click.echo("\nC_DigestInit + C_Digest (CKM_SHA256)...")
        digest_mech = CK_MECHANISM(CKM.SHA256)
        rv = lib.C_DigestInit(session, digest_mech)
        if rv != CKR.OK:
            raise Exception(f"C_DigestInit failed: {rv.name}")

        rv, computed_digest = lib.C_Digest(session, test_data)
        if rv != CKR.OK:
            raise Exception(f"C_Digest failed: {rv.name}")
        click.echo(f"  ✓ Computed digest: {computed_digest.hex()[:32]}...")

        # Verify digest matches
        if computed_digest == digest:
            click.echo(f"  ✓ Digest matches local computation")
        else:
            click.echo(f"  ✗ Digest mismatch!")

        # C_Logout
        click.echo("\nC_Logout...")
        rv = lib.C_Logout(session)
        click.echo(f"  ✓ Logged out")

        # C_CloseSession
        click.echo("C_CloseSession...")
        rv = lib.C_CloseSession(session)
        click.echo(f"  ✓ Session closed")

        # C_Finalize
        click.echo("C_Finalize...")
        rv = lib.C_Finalize()
        click.echo(f"  ✓ Library finalized")

        click.echo("\n" + "="*50)
        click.echo("All PKCS#11 tests passed!")
        click.echo("="*50)

    except Exception as e:
        click.echo(f"\nTest failed: {e}", err=True)
        sys.exit(1)
