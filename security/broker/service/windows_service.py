"""
Windows Service wrapper for the crypto broker.

This module implements a Windows Service (SCM integration) for running
the crypto broker as a system service on Windows.

Installation:
    python windows_service.py install
    python windows_service.py start

Or via CLI:
    python -m cli broker service install
    python -m cli broker service start

Management via sc.exe:
    sc query CryptoBroker
    sc start CryptoBroker
    sc stop CryptoBroker
"""

import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any

# Only import win32 modules on Windows
if sys.platform == "win32":
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager


def _default_aws_region() -> str:
    try:
        from config.settings import DEFAULT_AWS_REGION
        return DEFAULT_AWS_REGION
    except Exception:
        return "eu-central-1"


# Service configuration
SERVICE_NAME = "CryptoBroker"
SERVICE_DISPLAY_NAME = "Crypto Broker Service"
SERVICE_DESCRIPTION = (
    "PKCS#11 broker service for AWS KMS cryptographic operations. "
    "Required for RA8M1 provisioning tool secure key management."
)


def get_service_config_path() -> Path:
    """
    Get path to project_config.json (single source of truth).
    """
    provisioning_tool_dir = Path(__file__).parent.parent.parent
    return provisioning_tool_dir / "project_config.json"


def get_service_policies_path() -> Path:
    """
    Get path to authorization policies file.

    Returns:
        Path to broker_policies.json or broker_policies_windows.json
    """
    # Broker config directory (security/broker/config/)
    broker_config_dir = Path(__file__).parent.parent / "config"
    
    candidates = [
        Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "CryptoBroker" / "broker_policies.json",
        broker_config_dir / "broker_policies_windows.json",
        broker_config_dir / "broker_policies.json",
    ]

    for path in candidates:
        if path.exists():
            return path

    return candidates[0]


def get_service_log_path() -> Path:
    """
    Get path to service log file.

    Returns:
        Path to broker.log
    """
    log_dir = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "CryptoBroker" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "broker.log"


if sys.platform == "win32":

    class CryptoBrokerService(win32serviceutil.ServiceFramework):
        """
        Windows Service wrapper for the crypto broker.

        Implements the Windows Service Control Manager (SCM) interface
        to run the broker as a system service.
        """

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            """Initialize the service."""
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.broker = None
            self._running = False

        def SvcStop(self):
            """Handle service stop request."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._running = False
            win32event.SetEvent(self.stop_event)

            if self.broker:
                try:
                    self.broker.stop()
                except Exception:
                    pass

            self._log_event("Service stop requested")

        def SvcDoRun(self):
            """Main service entry point."""
            self._log_event("Service starting")
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            try:
                self._running = True
                self._run_broker()
            except Exception as e:
                self._log_error(f"Service failed: {e}")
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)
                raise

        def _run_broker(self):
            """Run the broker daemon."""
            from security.broker.service.daemon import WindowsBrokerDaemon
            from security.broker.authorization import AuthorizationManager

            # Setup logging to file
            log_path = get_service_log_path()
            self._setup_logging(log_path)

            self._log_event(f"Log file: {log_path}")

            # Load configuration
            kms_config = self._load_kms_config()

            # Load authorization policies
            auth_manager = None
            policies_path = get_service_policies_path()
            if policies_path.exists():
                try:
                    auth_manager = AuthorizationManager(str(policies_path))
                    self._log_event(f"Loaded policies from: {policies_path}")
                except Exception as e:
                    self._log_error(f"Failed to load policies: {e}")

            # Create broker daemon
            pipe_name = r"\\.\pipe\crypto_broker"
            self._log_event(f"Starting broker on {pipe_name}")

            self.broker = WindowsBrokerDaemon(
                pipe_name=pipe_name,
                kms_config=kms_config,
                authorization_manager=auth_manager,
                session_timeout=3600.0,
                max_sessions=100,
                pid_file=None,  # Service doesn't need PID file
            )

            # Run broker until stop event
            try:
                self.broker.start(foreground=True)
            except Exception as e:
                self._log_error(f"Broker error: {e}")
                raise

            self._log_event("Service stopped")

        def _load_kms_config(self) -> Dict[str, Any]:
            """
            Load KMS configuration from project_config.json (single source of truth).
            
            Fallback: environment variables, then AWS CLI default profile.
            """
            config = {}
            source = "none"

            config_path = get_service_config_path()
            if config_path.exists():
                try:
                    import json
                    with open(config_path) as f:
                        data = json.load(f)

                    aws_cfg = data.get("aws", {})
                    broker_cfg = data.get("broker", {})

                    if aws_cfg.get("access_key_id"):
                        config = {
                            "aws_region": aws_cfg.get("region"),
                            "aws_access_key_id": aws_cfg["access_key_id"],
                            "aws_secret_access_key": aws_cfg.get("secret_access_key"),
                            "key_prefix": broker_cfg.get("key_prefix", "renesas_"),
                        }
                        source = f"project_config.json ({config_path})"

                    self._log_event(f"Loaded config from: {config_path}")
                except Exception as e:
                    self._log_error(f"Failed to load config: {e}")

            # Fallback to environment variables
            if not config.get("aws_access_key_id"):
                env_key = os.environ.get("AWS_ACCESS_KEY_ID")
                env_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
                if env_key:
                    config["aws_access_key_id"] = env_key
                    config["aws_secret_access_key"] = env_secret
                    config.setdefault("key_prefix", os.environ.get("BROKER_KEY_PREFIX", "renesas_"))
                    source = "environment variables"

            if not config.get("aws_region"):
                config["aws_region"] = (
                    os.environ.get("AWS_DEFAULT_REGION")
                    or os.environ.get("AWS_REGION")
                    or _default_aws_region()
                )

            if config.get("aws_access_key_id"):
                masked_key = config["aws_access_key_id"][:4] + "****"
                self._log_event(f"AWS credentials source: {source} (key: {masked_key})")
                self._log_event(f"AWS region: {config['aws_region']}")
            else:
                self._log_event(
                    "No AWS credentials found. Provide via: "
                    "(1) project_config.json aws section, "
                    "(2) setx /M AWS_ACCESS_KEY_ID <key>, "
                    "(3) aws configure"
                )

            return config

        def _setup_logging(self, log_path: Path):
            """Configure logging to file."""
            import logging
            from utils.logging import get_logger

            # Ensure log directory exists
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Configure root logger
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                handlers=[
                    logging.FileHandler(str(log_path)),
                ]
            )

        def _log_event(self, message: str):
            """Log an informational event."""
            try:
                servicemanager.LogInfoMsg(f"{SERVICE_NAME}: {message}")
            except Exception:
                pass

        def _log_error(self, message: str):
            """Log an error event."""
            try:
                servicemanager.LogErrorMsg(f"{SERVICE_NAME}: {message}")
            except Exception:
                pass


def install_service(
    username: Optional[str] = None,
    password: Optional[str] = None,
    startup: str = "auto",
) -> bool:
    """
    Install the Windows service.

    Args:
        username: Service account username (None for LocalSystem)
        password: Service account password
        startup: Startup type ("auto", "manual", "disabled")

    Returns:
        True if installation succeeded
    """
    if sys.platform != "win32":
        print("Windows service installation only available on Windows")
        return False

    try:
        # Map startup type
        startup_map = {
            "auto": win32service.SERVICE_AUTO_START,
            "manual": win32service.SERVICE_DEMAND_START,
            "disabled": win32service.SERVICE_DISABLED,
        }
        start_type = startup_map.get(startup.lower(), win32service.SERVICE_AUTO_START)

        # Get path to this script
        script_path = Path(__file__).resolve()

        # Install the service
        win32serviceutil.InstallService(
            CryptoBrokerService._svc_reg_class_,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            startType=start_type,
            userName=username,
            password=password,
            description=SERVICE_DESCRIPTION,
        )

        print(f"Service '{SERVICE_NAME}' installed successfully")

        # Configure service recovery options
        _configure_service_recovery()

        return True

    except Exception as e:
        print(f"Failed to install service: {e}")
        return False


def uninstall_service() -> bool:
    """
    Uninstall the Windows service.

    Returns:
        True if uninstallation succeeded
    """
    if sys.platform != "win32":
        print("Windows service uninstallation only available on Windows")
        return False

    try:
        # Stop the service first if running
        try:
            win32serviceutil.StopService(SERVICE_NAME)
            time.sleep(2)
        except Exception:
            pass

        # Remove the service
        win32serviceutil.RemoveService(SERVICE_NAME)
        print(f"Service '{SERVICE_NAME}' uninstalled successfully")
        return True

    except Exception as e:
        print(f"Failed to uninstall service: {e}")
        return False


def start_service() -> bool:
    """
    Start the Windows service.

    Returns:
        True if service started successfully
    """
    if sys.platform != "win32":
        print("Windows service start only available on Windows")
        return False

    try:
        win32serviceutil.StartService(SERVICE_NAME)
        print(f"Service '{SERVICE_NAME}' started")
        return True
    except Exception as e:
        print(f"Failed to start service: {e}")
        return False


def stop_service() -> bool:
    """
    Stop the Windows service.

    Returns:
        True if service stopped successfully
    """
    if sys.platform != "win32":
        print("Windows service stop only available on Windows")
        return False

    try:
        win32serviceutil.StopService(SERVICE_NAME)
        print(f"Service '{SERVICE_NAME}' stopped")
        return True
    except Exception as e:
        print(f"Failed to stop service: {e}")
        return False


def get_service_status() -> Optional[str]:
    """
    Get Windows service status.

    Returns:
        Status string or None if service not installed
    """
    if sys.platform != "win32":
        return None

    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        state = status[1]

        state_map = {
            win32service.SERVICE_STOPPED: "STOPPED",
            win32service.SERVICE_START_PENDING: "START_PENDING",
            win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
            win32service.SERVICE_RUNNING: "RUNNING",
            win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
            win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
            win32service.SERVICE_PAUSED: "PAUSED",
        }

        return state_map.get(state, f"UNKNOWN ({state})")

    except Exception:
        return None


def _configure_service_recovery():
    """Configure service recovery options (restart on failure)."""
    if sys.platform != "win32":
        return

    import subprocess

    try:
        # Configure automatic restart on failure
        # sc failure <service> reset= <seconds> actions= restart/<ms>/restart/<ms>/restart/<ms>
        subprocess.run(
            [
                "sc", "failure", SERVICE_NAME,
                "reset=", "86400",  # Reset failure count after 1 day
                "actions=", "restart/5000/restart/10000/restart/30000"  # Restart delays
            ],
            check=True,
            capture_output=True,
        )
        print("Configured service recovery options")
    except Exception as e:
        print(f"Warning: Could not configure recovery options: {e}")


def main():
    """Main entry point for service management."""
    if sys.platform != "win32":
        print("Windows service only available on Windows")
        sys.exit(1)

    if len(sys.argv) == 1:
        # Running as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CryptoBrokerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command-line management
        win32serviceutil.HandleCommandLine(CryptoBrokerService)


if __name__ == "__main__":
    main()
