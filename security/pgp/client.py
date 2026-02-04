"""
PGP client for encryption and decryption.

This module provides a Python interface to GnuPG for encrypting
and decrypting UFPK files for DLM server communication.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict

from config.settings import PGPConfig
from utils.exceptions import PGPError
from utils.logging import get_logger

logger = get_logger(__name__)


class PGPClient:
    """
    PGP client for encryption and decryption operations.

    This class provides a Python interface to GnuPG for:
    - Encrypting UFPK with Renesas public key
    - Decrypting wrapped UFPK with customer private key
    """

    def __init__(self, config: PGPConfig):
        """
        Initialize PGP client.

        Args:
            config: PGP configuration

        Raises:
            PGPError: If GnuPG is not found or configuration is invalid
        """
        self.config = config
        self._verify_gpg_installation()

    def _verify_gpg_installation(self) -> None:
        """
        Verify that GnuPG is installed and accessible.

        Raises:
            PGPError: If GnuPG is not found
        """
        try:
            result = subprocess.run(
                [self.config.gpg_path, "--version"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                raise PGPError(
                    f"GnuPG not found at {self.config.gpg_path}. "
                    "Please install GnuPG or set gpg_path in configuration."
                )
            logger.debug(f"GnuPG found: {result.stdout.decode().split()[2]}")
        except FileNotFoundError:
            raise PGPError(
                f"GnuPG executable not found at {self.config.gpg_path}. "
                "Please install GnuPG (https://www.gnupg.org/download/) "
                "or set gpg_path in configuration."
            )

    def encrypt_file(
        self, input_file: Path, recipient_key_file: Path, output_file: Path
    ) -> None:
        """
        Encrypt a file using PGP with recipient's public key.

        Args:
            input_file: Path to file to encrypt
            recipient_key_file: Path to recipient's public key file
            output_file: Path to output encrypted file

        Raises:
            PGPError: If encryption fails
        """
        if not input_file.exists():
            raise PGPError(f"Input file not found: {input_file}")

        if not recipient_key_file.exists():
            raise PGPError(f"Recipient key file not found: {recipient_key_file}")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                keyring_dir = Path(tmpdir)
                if self.config.keyring_dir:
                    keyring_dir = Path(self.config.keyring_dir)
                    keyring_dir.mkdir(parents=True, exist_ok=True)

                # Ensure keyring directory exists and has required files
                keyring_dir.mkdir(parents=True, exist_ok=True)
                
                # Create gpg.conf if it doesn't exist
                gpg_conf = keyring_dir / "gpg.conf"
                if not gpg_conf.exists():
                    with open(gpg_conf, 'w') as f:
                        f.write("no-auto-key-locate\n")
                
                # Create empty keyring files if they don't exist (to force legacy format)
                pubring_path = keyring_dir / "pubring.gpg"
                secring_path = keyring_dir / "secring.gpg"
                if not pubring_path.exists():
                    pubring_path.touch()
                if not secring_path.exists():
                    secring_path.touch()
                
                # Delete pubring.kbx if it exists to prevent keyboxd usage
                keybox_path = keyring_dir / "pubring.kbx"
                if keybox_path.exists():
                    keybox_path.unlink()
                
                # Convert path for Git Bash if needed (Windows path conversion)
                import os
                gpg_homedir = str(keyring_dir)
                is_git_bash = os.name == 'nt' and ('git' in self.config.gpg_path.lower() or '/usr/bin' in self.config.gpg_path.lower().replace('\\', '/'))
                if is_git_bash:
                    keyring_dir_win = str(keyring_dir.resolve())
                    if len(keyring_dir_win) > 1 and keyring_dir_win[1] == ':':
                        drive = keyring_dir_win[0].lower()
                        path_part = keyring_dir_win[2:].replace('\\', '/')
                        gpg_homedir = f"/{drive}{path_part}"

                cmd = [
                    self.config.gpg_path,
                    "--homedir",
                    gpg_homedir,
                    "--trust-model",
                    "always",
                    "--batch",
                    "--yes",
                    "--import",
                    str(recipient_key_file),
                ]

                logger.debug(f"Importing recipient key: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd, capture_output=True, timeout=30, check=False
                )

                if result.returncode != 0:
                    logger.warning(
                        f"Key import warning: {result.stderr.decode()}"
                    )

                recipient_fingerprint = self._get_key_fingerprint(
                    recipient_key_file, keyring_dir, gpg_homedir
                )

                cmd = [
                    self.config.gpg_path,
                    "--homedir",
                    gpg_homedir,
                    "--trust-model",
                    "always",
                    "--batch",
                    "--yes",
                    "--armor",
                    "--encrypt",
                    "--recipient",
                    recipient_fingerprint,
                    "--output",
                    str(output_file),
                    str(input_file),
                ]

                logger.info(f"Encrypting file: {input_file} -> {output_file}")
                logger.debug(f"PGP command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd, capture_output=True, timeout=30, check=False
                )

                if result.returncode != 0:
                    error_msg = result.stderr.decode() or result.stdout.decode()
                    raise PGPError(f"PGP encryption failed: {error_msg}")

                if not output_file.exists():
                    raise PGPError("Encrypted file was not created")

                logger.info(f"File encrypted successfully: {output_file}")

        except subprocess.TimeoutExpired:
            raise PGPError("PGP encryption timed out")
        except Exception as e:
            if isinstance(e, PGPError):
                raise
            raise PGPError(f"Unexpected error during encryption: {str(e)}") from e

    def decrypt_file(
        self,
        input_file: Path,
        private_key_file: Path,
        passphrase: Optional[str] = None,
        output_file: Optional[Path] = None,
    ) -> Path:
        """
        Decrypt a PGP-encrypted file using private key.

        Args:
            input_file: Path to encrypted file
            private_key_file: Path to private key file
            passphrase: Optional passphrase for private key
            output_file: Optional output file path (default: input_file without .gpg/.asc)

        Returns:
            Path to decrypted file

        Raises:
            PGPError: If decryption fails
        """
        if not input_file.exists():
            raise PGPError(f"Input file not found: {input_file}")

        if not private_key_file.exists():
            raise PGPError(f"Private key file not found: {private_key_file}")

        if output_file is None:
            output_file = input_file.with_suffix("")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                keyring_dir = Path(tmpdir)
                if self.config.keyring_dir:
                    keyring_dir = Path(self.config.keyring_dir)
                    keyring_dir.mkdir(parents=True, exist_ok=True)

                # Ensure keyring directory exists and has required files
                keyring_dir.mkdir(parents=True, exist_ok=True)
                
                # Create gpg.conf if it doesn't exist
                gpg_conf = keyring_dir / "gpg.conf"
                if not gpg_conf.exists():
                    with open(gpg_conf, 'w') as f:
                        f.write("no-auto-key-locate\n")
                
                # Create empty keyring files if they don't exist (to force legacy format)
                pubring_path = keyring_dir / "pubring.gpg"
                secring_path = keyring_dir / "secring.gpg"
                if not pubring_path.exists():
                    pubring_path.touch()
                if not secring_path.exists():
                    secring_path.touch()
                
                # Delete pubring.kbx if it exists to prevent keyboxd usage
                keybox_path = keyring_dir / "pubring.kbx"
                if keybox_path.exists():
                    keybox_path.unlink()
                
                # Convert path for Git Bash if needed (Windows path conversion)
                import os
                gpg_homedir = str(keyring_dir)
                is_git_bash = os.name == 'nt' and ('git' in self.config.gpg_path.lower() or '/usr/bin' in self.config.gpg_path.lower().replace('\\', '/'))
                if is_git_bash:
                    keyring_dir_win = str(keyring_dir.resolve())
                    if len(keyring_dir_win) > 1 and keyring_dir_win[1] == ':':
                        drive = keyring_dir_win[0].lower()
                        path_part = keyring_dir_win[2:].replace('\\', '/')
                        gpg_homedir = f"/{drive}{path_part}"

                # Use --homedir instead of --no-default-keyring for better compatibility
                # First, import the private key
                cmd = [
                    self.config.gpg_path,
                    "--homedir", gpg_homedir,
                    "--trust-model", "always",
                    "--batch", "--yes",
                    "--import", str(private_key_file),
                ]

                logger.debug(f"Importing private key: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd, capture_output=True, timeout=30, check=False
                )

                import_output = result.stdout.decode() or result.stderr.decode()
                if result.returncode != 0:
                    logger.warning(f"Key import warning: {import_output[:300]}")
                else:
                    logger.debug(f"Key import output: {import_output[:300]}")

                # Verify key was imported and get key ID
                cmd = [
                    self.config.gpg_path,
                    "--homedir", gpg_homedir,
                    "--list-secret-keys",
                    "--with-colons",
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
                secret_keys_output = result.stdout.decode() or ""
                logger.debug(f"Secret keys in keyring: {secret_keys_output[:300]}")
                
                # Extract key IDs from secret keys
                imported_key_ids = []
                for line in secret_keys_output.split("\n"):
                    if line.startswith("fpr:"):
                        key_id = line.split(":")[9]
                        imported_key_ids.append(key_id)
                        logger.debug(f"Found secret key fingerprint: {key_id[:16]}...")
                
                if not imported_key_ids:
                    # Try listing without colons format
                    cmd = [
                        self.config.gpg_path,
                        "--homedir", gpg_homedir,
                        "--list-secret-keys",
                    ]
                    result = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
                    logger.debug(f"Secret keys (plain): {result.stdout.decode()[:300]}")

                # Decrypt using the keyring
                cmd = [
                    self.config.gpg_path,
                    "--homedir", gpg_homedir,
                    "--trust-model", "always",
                    "--batch", "--yes",
                    "--decrypt",
                    "--output", str(output_file),
                    str(input_file),
                ]

                if passphrase:
                    cmd.extend(["--passphrase", passphrase])

                logger.info(f"Decrypting file: {input_file} -> {output_file}")
                logger.debug(f"PGP command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd, capture_output=True, timeout=30, check=False
                )

                if result.returncode != 0:
                    error_msg = result.stderr.decode() or result.stdout.decode()
                    logger.error(f"Decryption error output: {error_msg}")
                    
                    # If "No secret key" error, provide helpful message
                    if "No secret key" in error_msg:
                        # Try to extract the key ID from error
                        import re
                        key_id_match = re.search(r'ID\s+([0-9A-F]+)', error_msg)
                        if key_id_match:
                            required_key_id = key_id_match.group(1)
                            raise PGPError(
                                f"PGP decryption failed: No secret key found for key ID {required_key_id}.\n"
                                f"   The file was encrypted with a key that doesn't match your private key.\n"
                                f"   Please verify that '{private_key_file}' is the private key that corresponds\n"
                                f"   to the public key you sent to Renesas during PGP key exchange."
                            )
                    
                    raise PGPError(f"PGP decryption failed: {error_msg}")

                if not output_file.exists():
                    raise PGPError("Decrypted file was not created")

                logger.info(f"File decrypted successfully: {output_file}")
                return output_file

        except subprocess.TimeoutExpired:
            raise PGPError("PGP decryption timed out")
        except Exception as e:
            if isinstance(e, PGPError):
                raise
            raise PGPError(f"Unexpected error during decryption: {str(e)}") from e

    def _get_key_fingerprint(
        self, key_file: Path, keyring_dir: Path, gpg_homedir: Optional[str] = None
    ) -> str:
        """
        Get fingerprint of a key file.

        Args:
            key_file: Path to key file
            keyring_dir: Keyring directory
            gpg_homedir: GnuPG homedir path (converted for Git Bash if needed)

        Returns:
            Key fingerprint

        Raises:
            PGPError: If fingerprint extraction fails
        """
        if gpg_homedir is None:
            gpg_homedir = str(keyring_dir)
        
        try:
            # First try to get fingerprint directly from key file
            cmd = [
                self.config.gpg_path,
                "--homedir",
                gpg_homedir,
                "--with-fingerprint",
                "--with-colons",
                str(key_file),
            ]

            result = subprocess.run(
                cmd, capture_output=True, timeout=10, check=False
            )

            if result.returncode != 0:
                # If that fails, import key first, then list
                cmd = [
                    self.config.gpg_path,
                    "--homedir",
                    gpg_homedir,
                    "--import",
                    str(key_file),
                ]
                subprocess.run(cmd, capture_output=True, timeout=10, check=False)

                cmd = [
                    self.config.gpg_path,
                    "--homedir",
                    gpg_homedir,
                    "--list-keys",
                    "--with-fingerprint",
                    "--with-colons",
                ]

                result = subprocess.run(
                    cmd, capture_output=True, timeout=10, check=False
                )

            output = result.stdout.decode() + result.stderr.decode()
            for line in output.split("\n"):
                if line.startswith("fpr:"):
                    fingerprint = line.split(":")[9]
                    return fingerprint

            raise PGPError("Could not extract key fingerprint")

        except Exception as e:
            if isinstance(e, PGPError):
                raise
            raise PGPError(f"Failed to get key fingerprint: {str(e)}") from e

    def export_public_key_from_private(
        self,
        private_key_file: Path,
        output_file: Optional[Path] = None,
        armor: bool = True,
    ) -> Path:
        """
        Export public key from a private key file.
        
        Args:
            private_key_file: Path to private key file
            output_file: Optional output file path
            armor: If True, export in ASCII armor format (.asc), else binary (.gpg)
        
        Returns:
            Path to exported public key file
        
        Raises:
            PGPError: If export fails
        """
        if not private_key_file.exists():
            raise PGPError(f"Private key file not found: {private_key_file}")
        
        if output_file is None:
            ext = ".asc" if armor else ".gpg"
            output_file = private_key_file.parent / f"{private_key_file.stem}_public{ext}"
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                keyring_dir = Path(tmpdir)
                
                # Import private key
                cmd = [
                    self.config.gpg_path,
                    "--no-default-keyring",
                    "--keyring", str(keyring_dir / "pubring.gpg"),
                    "--secret-keyring", str(keyring_dir / "secring.gpg"),
                    "--trust-model", "always",
                    "--batch", "--yes",
                    "--import", str(private_key_file),
                ]
                
                logger.debug(f"Importing private key: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
                
                if result.returncode != 0:
                    error_msg = result.stderr.decode() or result.stdout.decode()
                    logger.warning(f"Key import warning: {error_msg[:200]}")
                
                # List secret keys to get key ID
                cmd = [
                    self.config.gpg_path,
                    "--no-default-keyring",
                    "--keyring", str(keyring_dir / "pubring.gpg"),
                    "--secret-keyring", str(keyring_dir / "secring.gpg"),
                    "--list-secret-keys",
                    "--with-colons",
                ]
                
                result = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
                
                if result.returncode != 0:
                    # Try listing public keys instead
                    cmd = [
                        self.config.gpg_path,
                        "--no-default-keyring",
                        "--keyring", str(keyring_dir / "pubring.gpg"),
                        "--list-keys",
                        "--with-colons",
                    ]
                    result = subprocess.run(cmd, capture_output=True, timeout=10, check=False)
                
                if result.returncode != 0:
                    raise PGPError("Could not list imported keys")
                
                # Extract key ID from output
                output = result.stdout.decode()
                key_id = None
                for line in output.split("\n"):
                    if line.startswith("fpr:"):
                        key_id = line.split(":")[9]
                        break
                    elif line.startswith("pub:") and not key_id:
                        # Fallback: use key ID from pub line
                        parts = line.split(":")
                        if len(parts) > 4:
                            key_id = parts[4]
                
                if not key_id:
                    # Last resort: try to export all keys
                    logger.warning("Could not extract specific key ID, exporting all keys")
                    cmd = [
                        self.config.gpg_path,
                        "--no-default-keyring",
                        "--keyring", str(keyring_dir / "pubring.gpg"),
                        "--secret-keyring", str(keyring_dir / "secring.gpg"),
                    ]
                    
                    if armor:
                        cmd.extend(["--armor", "--export"])
                    else:
                        cmd.extend(["--export"])
                    
                    cmd.extend(["--output", str(output_file)])
                    
                    logger.info(f"Exporting all public keys: {private_key_file} -> {output_file}")
                    logger.debug(f"PGP command: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
                    
                    if result.returncode != 0:
                        error_msg = result.stderr.decode() or result.stdout.decode()
                        raise PGPError(f"PGP export failed: {error_msg}")
                    
                    if not output_file.exists():
                        raise PGPError("Exported key file was not created")
                    
                    logger.info(f"Public key exported successfully: {output_file}")
                    return output_file
                
                # Export public key using key ID
                cmd = [
                    self.config.gpg_path,
                    "--no-default-keyring",
                    "--keyring", str(keyring_dir / "pubring.gpg"),
                    "--secret-keyring", str(keyring_dir / "secring.gpg"),
                ]
                
                if armor:
                    cmd.extend(["--armor", "--export"])
                else:
                    cmd.extend(["--export"])
                
                cmd.extend([key_id, "--output", str(output_file)])
                
                logger.info(f"Exporting public key from private key: {private_key_file} -> {output_file}")
                logger.debug(f"PGP command: {' '.join(cmd)}")
                logger.debug(f"Using key ID: {key_id}")
                
                result = subprocess.run(cmd, capture_output=True, timeout=30, check=False)
                
                stdout_msg = result.stdout.decode() if result.stdout else ""
                stderr_msg = result.stderr.decode() if result.stderr else ""
                
                # Check multiple possible locations first
                possible_locations = [
                    output_file,
                    keyring_dir / output_file.name,
                    Path.cwd() / output_file.name,
                    private_key_file.parent / output_file.name,
                ]
                
                exported_file = None
                for loc in possible_locations:
                    if loc.exists() and loc.stat().st_size > 0:
                        exported_file = loc
                        logger.debug(f"Found exported file at: {exported_file} (size: {loc.stat().st_size} bytes)")
                        break
                
                if exported_file and exported_file != output_file:
                    import shutil
                    shutil.move(exported_file, output_file)
                    logger.info(f"Moved exported file to: {output_file}")
                
                if output_file.exists() and output_file.stat().st_size > 0:
                    logger.info(f"Public key exported successfully: {output_file}")
                    return output_file
                
                # If file doesn't exist or is empty, try alternative method
                if result.returncode != 0:
                    error_msg = stderr_msg or stdout_msg
                    logger.warning(f"Export with key ID failed (returncode={result.returncode}): {error_msg[:200]}")
                
                # Try alternative: export without specifying key ID (export all)
                logger.warning("Trying to export all keys from keyring...")
                cmd_alt = [
                    self.config.gpg_path,
                    "--no-default-keyring",
                    "--keyring", str(keyring_dir / "pubring.gpg"),
                    "--secret-keyring", str(keyring_dir / "secring.gpg"),
                ]
                
                if armor:
                    cmd_alt.append("--armor")
                cmd_alt.extend(["--export", "--output", str(output_file)])
                
                logger.debug(f"Alternative PGP command: {' '.join(cmd_alt)}")
                result_alt = subprocess.run(cmd_alt, capture_output=True, timeout=30, check=False)
                
                stdout_alt = result_alt.stdout.decode() if result_alt.stdout else ""
                stderr_alt = result_alt.stderr.decode() if result_alt.stderr else ""
                
                if result_alt.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
                    logger.info(f"Public key exported successfully (all keys): {output_file}")
                    return output_file
                else:
                    # Final attempt: use --homedir approach
                    logger.warning("Trying --homedir approach...")
                    with tempfile.TemporaryDirectory() as tmpdir2:
                        # Import key
                        import_cmd = [
                            self.config.gpg_path,
                            "--homedir", tmpdir2,
                            "--batch", "--yes",
                            "--import", str(private_key_file),
                        ]
                        subprocess.run(import_cmd, capture_output=True, timeout=30, check=False)
                        
                        # Export public key
                        export_cmd = [
                            self.config.gpg_path,
                            "--homedir", tmpdir2,
                        ]
                        if armor:
                            export_cmd.append("--armor")
                        export_cmd.extend(["--export", "--output", str(output_file)])
                        
                        result_final = subprocess.run(export_cmd, capture_output=True, timeout=30, check=False)
                        
                        if result_final.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
                            logger.info(f"Public key exported successfully (homedir method): {output_file}")
                            return output_file
                    
                    # All methods failed
                    error_details = f"Key ID method: returncode={result.returncode}, stdout={stdout_msg[:100]}, stderr={stderr_msg[:100]}. "
                    error_details += f"All keys method: returncode={result_alt.returncode}, stdout={stdout_alt[:100]}, stderr={stderr_alt[:100]}"
                    raise PGPError(f"Exported key file was not created at {output_file}. {error_details}")
                
                logger.info(f"Public key exported successfully: {output_file}")
                return output_file
                
        except subprocess.TimeoutExpired:
            raise PGPError("PGP export timed out")
        except Exception as e:
            if isinstance(e, PGPError):
                raise
            raise PGPError(f"Unexpected error during export: {str(e)}") from e

    def export_public_key(
        self,
        key_id: str,
        output_file: Optional[Path] = None,
        armor: bool = True,
    ) -> Path:
        """
        Export a public key from GnuPG keyring.

        Args:
            key_id: Key ID or email address
            output_file: Optional output file path (default: key_id.asc or key_id.gpg)
            armor: If True, export in ASCII armor format (.asc), else binary (.gpg)

        Returns:
            Path to exported public key file

        Raises:
            PGPError: If export fails
        """
        if output_file is None:
            ext = ".asc" if armor else ".gpg"
            output_file = Path(f"{key_id.replace('@', '_').replace(' ', '_')}{ext}")

        try:
            keyring_dir = Path(tempfile.gettempdir())
            if self.config.keyring_dir:
                keyring_dir = Path(self.config.keyring_dir)
                keyring_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                self.config.gpg_path,
                "--keyring",
                str(keyring_dir / "pubring.gpg"),
                "--secret-keyring",
                str(keyring_dir / "secring.gpg"),
            ]

            # Use default keyring if customer keys are configured
            if self.config.customer_private_key:
                # Import customer key to get public key
                if Path(self.config.customer_private_key).exists():
                    import_cmd = cmd + [
                        "--import",
                        str(self.config.customer_private_key),
                    ]
                    subprocess.run(import_cmd, capture_output=True, timeout=10, check=False)

            if armor:
                cmd.extend(["--armor", "--export"])
            else:
                cmd.extend(["--export"])

            cmd.extend([key_id, "--output", str(output_file)])

            logger.info(f"Exporting public key: {key_id} -> {output_file}")
            logger.debug(f"PGP command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, timeout=30, check=False
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode() or result.stdout.decode()
                raise PGPError(f"PGP export failed: {error_msg}")

            if not output_file.exists():
                raise PGPError("Exported key file was not created")

            logger.info(f"Public key exported successfully: {output_file}")
            return output_file

        except subprocess.TimeoutExpired:
            raise PGPError("PGP export timed out")
        except Exception as e:
            if isinstance(e, PGPError):
                raise
            raise PGPError(f"Unexpected error during export: {str(e)}") from e

    def list_keys(self) -> list:
        """
        List all keys in GnuPG keyring.

        Returns:
            List of key information dictionaries
        """
        try:
            keyring_dir = Path(tempfile.gettempdir())
            if self.config.keyring_dir:
                keyring_dir = Path(self.config.keyring_dir)

            cmd = [
                self.config.gpg_path,
                "--keyring",
                str(keyring_dir / "pubring.gpg"),
                "--list-keys",
                "--with-colons",
            ]

            result = subprocess.run(
                cmd, capture_output=True, timeout=10, check=False
            )

            keys = []
            if result.returncode == 0:
                output = result.stdout.decode()
                current_key = {}
                for line in output.split("\n"):
                    if line.startswith("pub:"):
                        parts = line.split(":")
                        current_key = {
                            "type": "public",
                            "trust": parts[1],
                            "key_length": parts[2],
                            "algorithm": parts[3],
                            "key_id": parts[4],
                            "creation_date": parts[5],
                            "expiry_date": parts[6],
                        }
                    elif line.startswith("uid:") and current_key:
                        parts = line.split(":")
                        if "uids" not in current_key:
                            current_key["uids"] = []
                        current_key["uids"].append(parts[9])
                    elif line.startswith("fpr:") and current_key:
                        parts = line.split(":")
                        current_key["fingerprint"] = parts[9]
                        keys.append(current_key.copy())
                        current_key = {}

            return keys

        except Exception as e:
            logger.warning(f"Failed to list keys: {str(e)}")
            return []



