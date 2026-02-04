"""
RA8 Complete Provisioning Workflow.

Orchestrates the complete device provisioning process according to Renesas documentation.
"""

from pathlib import Path
from typing import Optional, Callable

from device.ra8_provisioning_client import RA8ProvisioningClient
from device.ra8_key_programmer import RA8KeyProgrammer
from device.ra8_srec_programmer import RA8SRECProgrammer
from device.ra8_certificate_programmer import RA8CertificateProgrammer
from utils.logging import get_logger
from utils.exceptions import DeviceError

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
        
        Returns:
            True on success, False on failure
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        # Use DLM state transition command (0x71)
        # Source: OEM (0x04), Target: LCK_BOOT (0x06)
        logger.info("Transitioning to LCK_BOOT state...")
        
        result = self.client._dlm_state_transition(0x04, 0x06)
        
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
        try:
            # Validate files
            self._validate_files()
            
            # Connect
            logger.info("Connecting to device...")
            self.client.connect()
            
            # Connect to boot mode
            self.client.connect_to_boot_mode()
            
            # Step 1: Initialize device (CM->OEM transition)
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
            logger.info("Reconnecting after reset...")
            self.client.disconnect()
            import time
            time.sleep(2)  # Give device time to enumerate
            self.client.connect()
            
            # Now re-enter boot mode
            self.client.connect_to_boot_mode()
            
            # IMPORTANT: OEM Root Key programming requires PL2, not PL0
            # Transition to PL2 before programming key
            logger.info("Transitioning to PL2 (required for OEM Root Key programming)...")
            if not self._transition_protection_level(0x02):  # PL2 = 0x02
                raise DeviceError("Failed to transition to PL2")
            logger.info("Successfully transitioned to PL2")
            
            # Step 2: Program OEM root key
            logger.info("Step 2: Programming OEM root key...")
            self.key_programmer.program_oem_root_key(
                self.oem_root_key_file,
                key_id=0,
                permanent_lock=False
            )
            
            # Step 3: Program SREC file (bootloader + application)
            logger.info("Step 3: Programming SREC file...")
            self.srec_programmer.program_srec_file(
                self.combined_srec_file,
                enforce_secure_alias=True
            )
            
            # Step 4: Program OSM (Option Setting Memory)
            logger.info("Step 4: Programming OSM...")
            self.srec_programmer.program_osm_from_srec(self.combined_srec_file)
            
            # Step 5: Program Key + Code Certificates
            logger.info("Step 5: Programming certificates...")
            self.cert_programmer.program_certificates(
                self.key_cert_file,
                self.code_cert_file
            )
            
            # Step 6: Inject AL keys (optional)
            if self.al2_key_file or self.al1_key_file:
                logger.info("Step 6: Injecting AL keys...")
                if self.al2_key_file:
                    self.key_programmer.inject_dlm_key(self.al2_key_file, 0x01)
                if self.al1_key_file:
                    self.key_programmer.inject_dlm_key(self.al1_key_file, 0x02)
            
            # Step 7: Configure final state
            logger.info(f"Step 7: Configuring final state: {self.final_state}")
            if self.final_state == "OEM_PL0":
                self._transition_protection_level(0x04)  # PL0
                logger.info("[OK] Device in OEM_PL0 state")
            elif self.final_state == "LCK_BOOT":
                # Ask for confirmation before locking (irreversible!)
                if self._confirm_lock_device():
                    # First transition to PL0, then to LCK_BOOT
                    self._transition_protection_level(0x04)  # PL0
                    if self._transition_to_lck_boot():
                        # Also disable initialize command when locking
                        self._disable_initialize()
                        logger.info("[OK] Device locked to LCK_BOOT state")
                    else:
                        logger.error("[ERROR] Failed to lock device - staying in OEM state")
                else:
                    # User declined - just go to PL0
                    self._transition_protection_level(0x04)
                    logger.info("[OK] Device in OEM_PL0 state (lock skipped by user)")
            
            # Step 8: Disable initialize (optional, irreversible) - only if not already done by LCK_BOOT
            if self.disable_initialize and self.final_state != "LCK_BOOT":
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
        
        except Exception as e:
            logger.exception("Provisioning workflow failed")
            raise DeviceError(f"Provisioning failed: {str(e)}") from e
        
        finally:
            self.client.disconnect()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.client.disconnect()


