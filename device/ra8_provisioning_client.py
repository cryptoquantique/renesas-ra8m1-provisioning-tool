"""
RA8 Production Programming Client.

This module provides a clean, class-based interface for RA8 device provisioning
according to Renesas documentation and production requirements.
"""

import serial
import serial.tools.list_ports
import time
import base64
import struct
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Callable
from enum import IntEnum

from utils.logging import get_logger
from utils.exceptions import DeviceError

logger = get_logger(__name__)


class DLMState(IntEnum):
    """Device Lifecycle Management states."""
    CM = 0x01
    OEM = 0x04
    LCK_BOOT = 0x06
    RMA_REQ = 0x07
    RMA_ACK = 0x08
    RMA_RET = 0x09


class ProtectionLevel(IntEnum):
    """Protection levels."""
    PL2 = 0x02
    PL1 = 0x03
    PL0 = 0x04


class AuthenticationLevel(IntEnum):
    """Authentication levels."""
    AL2 = 0x02
    AL1 = 0x03
    AL0 = 0x04


class RA8ProvisioningClient:
    """
    RA8 Production Programming Client.
    
    Handles all device provisioning operations including:
    - Boot mode connection and initialization
    - OEM Root Key programming
    - SREC file programming (bootloader + application)
    - Option Setting Memory (OSM) programming
    - Certificate programming (Key + Code)
    - AL key injection (optional)
    - Final state configuration
    """
    
    # Configuration constants
    SECURE_ALIAS_BASE = 0x02000000
    SECURE_ALIAS_LIMIT = 0x021F7FFF
    NONSEC_ALIAS_BASE = 0x12008000
    NONSEC_ALIAS_LIMIT = 0x121F7FFF
    ERASE_SECTOR_SIZE = 32 * 1024  # 32KB
    BOOT_BLK_START = 0x02000000
    BOOT_BLK_END = 0x02007FFF
    FLASH_BLOCK_SIZE = 128  # 128 bytes
    
    # OSM regions
    CF_OSM_SEC_BASE = 0x0300A100
    CF_OSM_SEC_SIZE = 384
    CF_OSM_PARAM_BASE = 0x0300A200
    DF_OSM_BASE = 0x27030080
    DF_OSM_SIZE = 720
    
    # Timing
    SHORT_DELAY = 0.15
    LONG_DELAY = 3.0
    FLASH_WRITE_DELAY = 0.05
    INITIALIZE_DELAY = 5.0
    
    def __init__(self, com_port: str, baud_rate: int = 9600):
        """
        Initialize RA8 provisioning client.
        
        Args:
            com_port: COM port name (e.g., "COM3")
            baud_rate: Baud rate (default: 9600)
        """
        self.com_port = com_port
        self.baud_rate = baud_rate
        self.ser: Optional[serial.Serial] = None
        self._connected = False
        
    def connect(self) -> None:
        """Open serial connection."""
        try:
            self.ser = serial.Serial(
                self.com_port,
                self.baud_rate,
                timeout=1,
                write_timeout=1
            )
            time.sleep(self.LONG_DELAY)
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            self._connected = True
            logger.info(f"Connected to {self.ser.name}")
        except Exception as e:
            raise DeviceError(f"Failed to open serial port {self.com_port}: {e}")
    
    def disconnect(self) -> None:
        """Close serial connection."""
        if self.ser and self.ser.is_open:
            self.ser.close()
            self._connected = False
            logger.info("Disconnected from device")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
    
    # ===== Low-level communication =====
    
    def _calc_sum(self, data: bytes) -> bytes:
        """Calculate checksum for packet."""
        count = sum(data) % 256
        summation = (256 - count) % 256
        return summation.to_bytes(1, "big")
    
    def _receive_data_packet(self) -> bytearray:
        """Receive data packet: SOD=0x81, reads length, then payload + SUM + ETX."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        packet = bytearray()
        
        # Wait for SOD with timeout
        logger.debug("Waiting for response SOD...")
        SOD = self.ser.read(1)
        
        if len(SOD) == 0:
            logger.error("No response from device (timeout)")
            # Check if there's any data in buffer
            available = self.ser.in_waiting
            if available > 0:
                buffer_data = self.ser.read(available)
                logger.error(f"Buffer contains {available} bytes: {buffer_data.hex()}")
            raise DeviceError("No response from device")
        
        logger.debug(f"Received SOD: {SOD.hex()}")
        
        # Check if it's an error packet (SOH = 0x01) instead of data packet (SOD = 0x81)
        if SOD == b'\x01':
            logger.warning("Received error packet (SOH=0x01), reading error details...")
            error_packet = bytearray(SOD)
            # Read at least 7 more bytes: LNH, LNL, RES, data, SUM, ETX
            error_packet += self.ser.read(7)
            logger.error(f"Error packet: {error_packet.hex()}")
            raise DeviceError(f"Device returned error packet: {error_packet.hex()}")
        
        if SOD != b'\x81':
            logger.error(f"Unexpected SOD: expected 0x81, got {SOD.hex()}")
            raise DeviceError(f"Unexpected SOD: {SOD.hex()}")
        
        packet += SOD
        LNH = self.ser.read()
        packet += LNH
        LNL = self.ser.read()
        packet += LNL
        
        length = (int.from_bytes(LNH, "big") * 256) + int.from_bytes(LNL, "big") + 2
        
        for _ in range(length):
            packet += self.ser.read()
        
        return packet
    
    def _decode_status_packet(self, pkt: bytes) -> Dict:
        """Decode RES/STS/ST2 and optional ADR for diagnostics."""
        st = {"raw": pkt.hex()}
        try:
            st["SOD"] = pkt[0]
            st["LNH"] = pkt[1]
            st["LNL"] = pkt[2]
            st["RES_RAW"] = pkt[3]
            st["RES"] = pkt[3] & 0x7F  # mask MSB
            st["STS"] = pkt[4] if len(pkt) > 4 else None
            st["ST2"] = pkt[5] if len(pkt) > 5 else None
            st["LEN"] = (st["LNH"] << 8) | st["LNL"]
            
            if len(pkt) >= 10:
                st["ADR"] = int.from_bytes(pkt[6:10], "big")
        except Exception:
            pass
        return st
    
    def _communication_setting(self) -> bool:
        """Establish UART/USB boot firmware handshake."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        logger.debug("Establishing communication with boot firmware...")
        loopcount = 20
        
        while loopcount != 0:
            self.ser.write(b'\x00\x00\x00')
            time.sleep(self.SHORT_DELAY)
            h = self.ser.read()
            if h == b'\x00':
                logger.debug("ACK received")
                return True
            loopcount -= 1
            time.sleep(self.SHORT_DELAY)
        
        return False
    
    def _command_inquiry(self) -> None:
        """Send inquiry command."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        command = b'\x01\x00\x01\x00\xFF\x03'
        self.ser.write(command)
        time.sleep(self.LONG_DELAY)
    
    def _command_signature_request(self) -> int:
        """Request device signature."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        logger.debug("Requesting device signature...")
        command = b'\x01\x00\x01\x3A\xC5\x03'
        self.ser.write(command)
        time.sleep(self.LONG_DELAY)
        
        return_packet = self._receive_data_packet()
        RES = return_packet[3] & 0x7F
        
        if RES != 0x3A:
            raise DeviceError("Signature request failed")
        
        return RES
    
    def get_dlm_state(self) -> Tuple[int, int]:
        """Get current DLM state."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        command = b'\x01\x00\x01\x2C\xD3\x03'
        self.ser.write(command)
        time.sleep(self.LONG_DELAY)
        
        rp = self._receive_data_packet()
        RES = rp[3] & 0x7F
        DLM = rp[4] if RES == 0x2C else 0xFF
        
        dlm_states = {
            0x01: "CM", 0x04: "OEM", 0x06: "LCK_BOOT",
            0x07: "RMA_REQ", 0x08: "RMA_ACK", 0x09: "RMA_RET"
        }
        logger.info(f"Current DLM state: {dlm_states.get(DLM, 'Unknown')}")
        
        return RES, DLM
    
    def get_protection_level(self) -> Tuple[int, int]:
        """Get current protection level."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        command = b'\x01\x00\x01\x73\x8C\x03'
        self.ser.write(command)
        time.sleep(self.LONG_DELAY)
        
        rp = self._receive_data_packet()
        RES = rp[3] & 0x7F
        CPL = rp[4] if RES == 0x73 else 0xFF
        
        pl_states = {0x02: "PL2", 0x03: "PL1", 0x04: "PL0"}
        logger.info(f"Current Protection Level: {pl_states.get(CPL, 'Unknown')}")
        
        return RES, CPL
    
    def get_authentication_level(self) -> Tuple[int, int]:
        """Get current authentication level."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x01'
        CMD = b'\x75'
        SUM = b'\x8A'
        ETX = b'\x03'
        cmd = SOH + LNH + LNL + CMD + SUM + ETX
        
        logger.debug("Sending Authentication Level Request command")
        self.ser.write(cmd)
        time.sleep(self.LONG_DELAY)
        
        rp = self._receive_data_packet()
        RES = rp[3] & 0x7F
        CAL = rp[4] if RES == 0x75 else 0xFF
        
        if RES != 0x75:
            raise DeviceError("Read Authentication Level - FAIL")
        
        al_states = {0x02: "AL2", 0x03: "AL1", 0x04: "AL0"}
        logger.info(f"Current Authentication Level: {al_states.get(CAL, 'Unknown')}")
        
        return RES, CAL
    
    def _dlm_state_transition(self, source_state: int, target_state: int) -> bool:
        """Transition DLM state."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        logger.info(f"Transitioning DLM state: {source_state:02X} -> {target_state:02X}")
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x03'
        CMD = b'\x71'
        SDLM = source_state.to_bytes(1, "big")
        DDLM = target_state.to_bytes(1, "big")
        SUM = self._calc_sum(LNH + LNL + CMD + SDLM + DDLM)
        ETX = b'\x03'
        
        self.ser.write(SOH + LNH + LNL + CMD + SDLM + DDLM + SUM + ETX)
        time.sleep(self.LONG_DELAY)
        
        rp = self._receive_data_packet()
        RES = rp[3] & 0x7F
        return RES == 0x71
    
    def initialize_device(self, reset_callback: Optional[Callable[[], None]] = None) -> None:
        """
        Initialize device (CM->OEM transition via Initialize command).
        
        Args:
            reset_callback: Optional callback function to call when reset is required.
                           If None, will prompt user via input().
        """
        if not self.ser:
            raise DeviceError("Not connected")
        
        logger.info("Initializing MCU")
        
        # Get current DLM state
        _, dlm = self.get_dlm_state()
        
        # Initialize command transitions device to OEM/PL2 regardless of current DLM
        # It clears: User area, Data area, Config area, EEP, Boundary, Key index
        # AND sets PL to PL2 (critical for OEM Root Key programming)
        
        if dlm == 0x01:  # CM
            logger.info("Device in CM state - transitioning to OEM first...")
            self._dlm_state_transition(0x01, 0x04)
            dlm = 0x04  # Update to OEM for Initialize command
        
        if dlm == 0x04:  # OEM (now includes both original OEM and transitioned from CM)
            logger.info(f"Sending Initialize command (will set device to OEM/PL2)...")
            
            # Send Initialize command
            SOH = b'\x01'
            LNH = b'\x00'
            LNL = b'\x03'
            CMD = b'\x50'
            SDLM = dlm.to_bytes(1, "big")  # 0x04 (OEM)
            DDLM = b'\x04'  # target OEM
            SUM = self._calc_sum(LNH + LNL + CMD + SDLM + DDLM)
            ETX = b'\x03'
            
            self.ser.write(SOH + LNH + LNL + CMD + SDLM + DDLM + SUM + ETX)
            time.sleep(self.INITIALIZE_DELAY)
            
            rp = self._receive_data_packet()
            RES = rp[3] & 0x7F
            
            if RES != 0x50:
                raise DeviceError("Initialize failed")
            
            logger.info("Initialize successful - device will be in OEM/PL2 after reset")
            logger.warning("!!! RESET REQUIRED - Please reset the board with MD low !!!")
            
            if reset_callback:
                reset_callback()
            else:
                input("Press Enter after reset...")
            
            # Reconnect
            self.disconnect()
            time.sleep(self.LONG_DELAY)
            self.connect()
            
            if not self._communication_setting():
                raise DeviceError("Failed to reconnect after initialize")
            
            self.ser.write(b'\x55')
            time.sleep(self.SHORT_DELAY)
            _ = self.ser.read()
        else:
            logger.warning(f"Device in DLM state 0x{dlm:02X} - Initialize not available")
        
        # Verify final state
        _, dlm2 = self.get_dlm_state()
        _, pl2 = self.get_protection_level()
        _, al2 = self.get_authentication_level()
        
        logger.info("Initialization Complete")
        logger.info(f"DLM: 0x{dlm2:02X} (expect 0x04 = OEM)")
        logger.info(f"PL : 0x{pl2:02X} (0x04=PL0, 0x03=PL1, 0x02=PL2)")
        logger.info(f"AL : 0x{al2:02X} (0x04=AL0, 0x03=AL1, 0x02=AL2)")
    
    def connect_to_boot_mode(self) -> None:
        """Connect to boot mode."""
        if not self.ser:
            raise DeviceError("Not connected")
        
        logger.info("Connecting to Boot Mode")
        
        if not self._communication_setting():
            self._command_inquiry()
            rp = self._receive_data_packet()
            if (rp[3] & 0x7F) != 0x00:
                raise DeviceError("Failed to connect to boot mode")
        
        self.ser.write(b'\x55')
        time.sleep(self.SHORT_DELAY)
        boot_code = self.ser.read()
        
        logger.info(f"Boot code received: {boot_code.hex() if boot_code else 'EMPTY'} (expected: c6)")
        
        if boot_code != b'\xC6':
            raise DeviceError(f"Unexpected boot code: {boot_code.hex() if boot_code else 'EMPTY'}. "
                            "Please enter BOOT MODE: 1) Hold SW1, 2) Press RESET, "
                            "3) Release RESET, 4) Release SW1 after 1-2 sec")
        
        self._command_signature_request()
    
    @staticmethod
    def find_ra_com_port() -> Optional[str]:
        """Find RA USB Boot COM port automatically."""
        ports = list(serial.tools.list_ports.comports())
        for p in ports:
            if 'RA USB Boot' in p.description or 'Renesas' in p.description:
                logger.info(f"Auto-selected COM port: {p.name}")
                return p.name
        return None
    
    @staticmethod
    def list_com_ports() -> List[str]:
        """List all available COM ports."""
        ports = list(serial.tools.list_ports.comports())
        return [p.name for p in ports]


