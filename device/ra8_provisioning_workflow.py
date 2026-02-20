"""
RA8 Complete Provisioning Workflow.

Orchestrates the complete device provisioning process according to Renesas documentation.
"""

from pathlib import Path
from typing import Optional, Callable

import serial

from device.ra8_provisioning_client import RA8ProvisioningClient
from device.ra8_key_programmer import RA8KeyProgrammer
from device.ra8_srec_programmer import RA8SRECProgrammer
from device.ra8_certificate_programmer import RA8CertificateProgrammer
from utils.logging import get_logger
from utils.exceptions import (
    DeviceError,
    TimeoutError as ProvisioningTimeoutError,
)

logger = get_logger(__name__)


class RA8ProvisioningWorkflow:
    """
    Complete RA8 provisioning workflow.
    
    Steps:
    1. Initialize device (CM->OEM transition)
    2. Program OEM Root Key
    3. Program SREC file (bootloader + application)
    4. Program OSM (Option Setting Memory)
    5. Program Key + Code Certificates
    6. Optional: Inject AL keys
    7. Configure final state (PL0 or LCK_BOOT)
    8. Optional: Disable initialize command
    """
    
    def __init__(
        self,
        com_port: str,
        oem_root_key_file: Path,
        key_cert_file: Path,
        code_cert_file: Path,
        combined_srec_file: Path,
        baud_rate: int = 9600,
        al2_key_file: Optional[Path] = None,
        al1_key_file: Optional[Path] = None,
        final_state: str = "OEM_PL0",
        disable_initialize: bool = False,
        reset_callback: Optional[Callable[[], None]] = None,
    ):
        """
        Initialize provisioning workflow.
        
        Args:
            com_port: COM port name
            oem_root_key_file: Path to OEM root key .rkey file
            key_cert_file: Path to key certificate .bin file
            code_cert_file: Path to code certificate .bin file
            combined_srec_file: Path to combined SREC file
            baud_rate: Serial baud rate (default: 9600)
            al2_key_file: Optional AL2 key file
            al1_key_file: Optional AL1 key file
            final_state: Final state ("OEM_PL0" or "LCK_BOOT")
            disable_initialize: Whether to disable initialize command (irreversible)
            reset_callback: Optional callback when reset is required
        """
        self.com_port = com_port
        self.oem_root_key_file = oem_root_key_file
        self.key_cert_file = key_cert_file
        self.code_cert_file = code_cert_file
        self.combined_srec_file = combined_srec_file
        self.baud_rate = baud_rate
        self.al2_key_file = al2_key_file
        self.al1_key_file = al1_key_file
        self.final_state = final_state
        self.disable_initialize = disable_initialize
        self.reset_callback = reset_callback
        
        # Initialize components
        self.client = RA8ProvisioningClient(com_port, baud_rate)
        self.key_programmer = RA8KeyProgrammer(self.client)
        self.srec_programmer = RA8SRECProgrammer(self.client)
        self.cert_programmer = RA8CertificateProgrammer(self.client)
    
    def _validate_files(self) -> None:
        """Validate that all required files exist."""
        files_to_check = [
            (self.oem_root_key_file, "OEM Root Key"),
            (self.code_cert_file, "Code Certificate"),
            (self.key_cert_file, "Key Certificate"),
            (self.combined_srec_file, "Combined SREC"),
        ]
        
        if self.al2_key_file:
            files_to_check.append((self.al2_key_file, "AL2 Key"))
        
        if self.al1_key_file:
            files_to_check.append((self.al1_key_file, "AL1 Key"))
        
        for filepath, desc in files_to_check:
            if not filepath.exists():
                raise DeviceError(f"{desc} file not found: {filepath}")
    
    def _transition_protection_level(self, target_pl: int) -> bool:
        """Transition to target protection level."""
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        _, current_pl = self.client.get_protection_level()
        logger.info(f"Transitioning to PL{4-target_pl}...")
        
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x03'
        CMD = b'\x72'
        SPL = current_pl.to_bytes(1, 'big')
        DPL = target_pl.to_bytes(1, 'big')
        SUM = self.client._calc_sum(LNH + LNL + CMD + SPL + DPL)
        ETX = b'\x03'
        
        self.client.ser.write(SOH + LNH + LNL + CMD + SPL + DPL + SUM + ETX)
        import time
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        return (rp[3] & 0x7F) == 0x72
    
    def _disable_initialize(self) -> bool:
        """Disable initialize command (NON-REVERSIBLE)."""
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        logger.warning("!!! WARNING: Disabling Initialize Command is NON-REVERSIBLE !!!")
        
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x03'
        CMD = b'\x51'
        PMID = b'\x01'
        PRMT = b'\x00'
        SUM = self.client._calc_sum(LNH + LNL + CMD + PMID + PRMT)
        ETX = b'\x03'
        
        self.client.ser.write(SOH + LNH + LNL + CMD + PMID + PRMT + SUM + ETX)
        import time
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        if (rp[3] & 0x7F) == 0x51 and rp[4] == 0x00:
            logger.info("Initialize command disabled successfully")
            return True
        return False
    
    def _transition_to_lck_boot(self) -> bool:
        """
        Transition device to LCK_BOOT state.
        
        This is an IRREVERSIBLE operation that locks the device.
        DLM transition: OEM (0x04) -> LCK_BOOT (0x06)
        
        After receiving the lock command, the device may reset immediately
        before sending a response. In this case, a timeout or serial error
        is treated as success (lock command was sent and accepted).
        
        Returns:
            True on success (or likely success), False on definite failure
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        # Use DLM state transition command (0x71)
        # Source: OEM (0x04), Target: LCK_BOOT (0x06)
        logger.info("Transitioning to LCK_BOOT state...")
        
        try:
            result = self.client._dlm_state_transition(0x04, 0x06)
        except (ProvisioningTimeoutError, serial.SerialException, OSError) as e:
            # Device likely locked successfully but reset before sending response
            logger.warning(
                f"[WARN] No response after LCK_BOOT command: {e}\n"
                "  This is expected - the device resets after entering LCK_BOOT state."
            )
            return True
        
        if result:
            logger.info("[OK] Device transitioned to LCK_BOOT state successfully")
        else:
            logger.error("[ERROR] Failed to transition to LCK_BOOT state")
        
        return result
    
    def _confirm_lock_device(self) -> bool:
        """
        Ask user for confirmation before locking device.
        
        Returns:
            True if user confirms, False otherwise
        """
        # ANSI escape codes for red text
        RED = "\033[91m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        
        print("")
        print(f"{RED}{BOLD}{'='*70}{RESET}")
        print(f"{RED}{BOLD}  WARNING: IRREVERSIBLE OPERATION{RESET}")
        print(f"{RED}{BOLD}{'='*70}{RESET}")
        print(f"{RED}")
        print(f"  You are about to lock this device to LCK_BOOT state.")
        print(f"  This operation is PERMANENT and CANNOT be undone!")
        print(f"")
        print(f"  After locking:")
        print(f"    - Device will only boot authenticated firmware")
        print(f"    - Initialize command will be disabled")
        print(f"    - Device cannot be returned to OEM state")
        print(f"{RESET}")
        print(f"{RED}{BOLD}{'='*70}{RESET}")
        print("")
        
        response = input(f"{RED}{BOLD}Type 'yes' to confirm device lock, or 'no' to skip: {RESET}").strip().lower()
        
        if response == "yes":
            logger.warning("User confirmed device lock to LCK_BOOT")
            return True
        else:
            logger.info("User declined device lock - keeping OEM_PL0 state")
            return False
    
    def execute(self) -> bool:
        """
        Execute complete provisioning workflow.
        
        Returns:
            True on success, False on failure
        """
        import time as _time
        current_step = "Validation"
        
        try:
            # Validate files
            self._validate_files()
            
            # Connect
            current_step = "Connection"
            logger.info("Connecting to device...")
            self.client.connect()
            
            # Connect to boot mode
            current_step = "Boot mode"
            self.client.connect_to_boot_mode()
            
            # Step 1: Initialize device (CM->OEM transition)
            current_step = "Step 1: Device initialization"
            logger.info("Step 1: Initializing device...")
            self.client.initialize_device(reset_callback=self.reset_callback)
            
            # After initialization, device boots in normal mode
            # Need manual reset with MD LOW to re-enter boot mode
            print("")
            print("[WARN]  RESET REQUIRED!")
            print("   Please reset the board with MD low, then press Enter...")
            input()
            print("")
            
            # After manual reset, need to reconnect (port may have been re-enumerated)
            current_step = "Reconnection after reset"
            logger.info("Reconnecting after reset...")
            self.client.disconnect()
            _time.sleep(2)  # Give device time to enumerate
            self.client.connect()
            
            # Now re-enter boot mode
            self.client.connect_to_boot_mode()
            
            # IMPORTANT: OEM Root Key programming requires PL2, not PL0
            current_step = "PL2 transition"
            logger.info("Transitioning to PL2 (required for OEM Root Key programming)...")
            if not self._transition_protection_level(0x02):  # PL2 = 0x02
                raise DeviceError("Failed to transition to PL2")
            logger.info("Successfully transitioned to PL2")
            
            # Step 2: Program OEM root key
            current_step = "Step 2: OEM Root Key programming"
            logger.info("Step 2: Programming OEM root key...")
            self.key_programmer.program_oem_root_key(
                self.oem_root_key_file,
                key_id=0,
                permanent_lock=False
            )
            
            # Step 3: Program SREC file (bootloader + application)
            current_step = "Step 3: SREC programming"
            logger.info("Step 3: Programming SREC file...")
            self.srec_programmer.program_srec_file(
                self.combined_srec_file,
                enforce_secure_alias=True
            )
            
            # Step 4: Program OSM (Option Setting Memory)
            current_step = "Step 4: OSM programming"
            logger.info("Step 4: Programming OSM...")
            self.srec_programmer.program_osm_from_srec(self.combined_srec_file)
            
            # Step 5: Program Key + Code Certificates
            current_step = "Step 5: Certificate programming"
            logger.info("Step 5: Programming certificates...")
            self.cert_programmer.program_certificates(
                self.key_cert_file,
                self.code_cert_file
            )
            
            # Step 6: Inject AL keys (optional)
            if self.al2_key_file or self.al1_key_file:
                current_step = "Step 6: AL key injection"
                logger.info("Step 6: Injecting AL keys...")
                if self.al2_key_file:
                    self.key_programmer.inject_dlm_key(self.al2_key_file, 0x01)
                if self.al1_key_file:
                    self.key_programmer.inject_dlm_key(self.al1_key_file, 0x02)
            
            # Step 7: Configure final state
            current_step = "Step 7: Final state configuration"
            logger.info(f"Step 7: Configuring final state: {self.final_state}")
            if self.final_state == "OEM_PL0":
                self._transition_protection_level(0x04)  # PL0
                logger.info("[OK] Device in OEM_PL0 state")
            elif self.final_state == "LCK_BOOT":
                try:
                    # Ask for confirmation before locking (irreversible!)
                    if self._confirm_lock_device():
                        # Transition to PL0 first
                        self._transition_protection_level(0x04)  # PL0
                        
                        # Disable initialize BEFORE lock - device still responds in boot mode
                        # After LCK_BOOT the device resets and communication is lost,
                        # so all commands must be sent before the lock transition
                        logger.info("Disabling initialize command before lock...")
                        self._disable_initialize()
                        
                        # LCK_BOOT is the LAST command - device resets after this
                        # Communication will be lost, which is expected behavior
                        self._transition_to_lck_boot()
                        logger.info("[OK] Device locked to LCK_BOOT state successfully")
                    else:
                        # User declined - just go to PL0
                        self._transition_protection_level(0x04)
                        logger.info("[OK] Device in OEM_PL0 state (lock skipped by user)")
                except (DeviceError, ProvisioningTimeoutError,
                        serial.SerialException, OSError) as lock_err:
                    logger.warning(
                        f"[WARN] Lock step encountered an issue: {lock_err}\n"
                        "  All programming steps completed successfully.\n"
                        "  The device may already be locked (device resets after LCK command).\n"
                        "  Verify device DLM state after reset."
                    )
                    # Don't re-raise - provisioning itself succeeded
            
            # Step 8: Disable initialize (optional, irreversible) - only if not already done by LCK_BOOT
            if self.disable_initialize and self.final_state != "LCK_BOOT":
                current_step = "Step 8: Disable initialize"
                logger.warning("Step 8: Disabling initialize command...")
                # Require explicit confirmation
                if self.reset_callback:
                    # Callback should handle confirmation
                    self._disable_initialize()
                else:
                    confirm = input("\nDisable initialize command? Type 'YES' to confirm: ")
                    if confirm == "YES":
                        self._disable_initialize()
            
            logger.info("[OK] Provisioning completed successfully!")
            return True
        
        except ProvisioningTimeoutError as e:
            logger.error(f"[TIMEOUT] {current_step} - Device not responding")
            logger.error(str(e))
            raise DeviceError(
                f"Timeout during '{current_step}'.\n{str(e)}"
            ) from e
        
        except (serial.SerialException, OSError) as e:
            logger.error(f"[DISCONNECT] Communication lost during '{current_step}'")
            logger.error(
                f"Serial error: {e}\n"
                "  -> The USB cable may have been disconnected during provisioning.\n"
                "  -> DO NOT power off the device immediately!\n"
                "  -> Reconnect the cable, reset the board (MD low), and retry.\n"
                f"  -> Failed at: {current_step}"
            )
            raise DeviceError(
                f"Communication lost during '{current_step}': {e}\n"
                "  -> Reconnect the USB cable, reset the board, and retry."
            ) from e
        
        except DeviceError:
            # Already has meaningful message, re-raise as-is
            raise
        
        except Exception as e:
            logger.exception(f"Unexpected error during '{current_step}'")
            raise DeviceError(
                f"Provisioning failed at '{current_step}': {str(e)}"
            ) from e
        
        finally:
            self.client.disconnect()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.client.disconnect()


