"""
RA8 Key Programming Module.

Handles OEM Root Key and AL key programming.
"""

import base64
import time
from pathlib import Path
from typing import Optional

from device.ra8_provisioning_client import RA8ProvisioningClient
from utils.logging import get_logger
from utils.exceptions import DeviceError

logger = get_logger(__name__)


class RA8KeyProgrammer:
    """Handles key programming operations for RA8 devices."""
    
    def __init__(self, client: RA8ProvisioningClient):
        """
        Initialize key programmer.
        
        Args:
            client: RA8ProvisioningClient instance
        """
        self.client = client
    
    def _parse_rkey_file(self, filename: Path) -> tuple[Optional[bytes], Optional[int]]:
        """Parse .rkey (Renesas wrapped key) file."""
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            # Remove header/footer and get base64 data
            data_lines = []
            in_data = False
            for line in lines:
                line = line.strip()
                if line == "-----BEGIN RENESAS KEY-----":
                    in_data = True
                    continue
                elif line == "-----END RENESAS KEY-----":
                    break
                elif in_data and line:
                    data_lines.append(line)
            
            if not data_lines:
                raise ValueError("No data found in rkey file")
            
            # Decode base64
            data = ''.join(data_lines)
            message_bytes = base64.b64decode(data)
            
            if message_bytes[0:4] != b'REK1':
                raise ValueError(f"Invalid magic code in rkey file: {message_bytes[0:4].hex()}")
            
            encrypted_key_size = int.from_bytes(message_bytes[16:20], "big")
            logger.info(f"Parsed RKEY file: {len(message_bytes)} bytes, encrypted size: {encrypted_key_size}")
            return message_bytes, encrypted_key_size
        
        except Exception as e:
            logger.error(f"Error parsing rkey file {filename}: {e}")
            return None, None
    
    def program_oem_root_key(
        self,
        oem_key_file: Path,
        key_id: int = 0,
        permanent_lock: bool = False
    ) -> None:
        """
        Program OEM Root Public Key into key slot.
        
        Args:
            oem_key_file: Path to .rkey file
            key_id: Key slot ID (default: 0)
            permanent_lock: Whether to permanently lock the key (irreversible)
        
        Raises:
            DeviceError: If programming fails
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        # ============================================================
        # DETAILED LOGGING: Show EXACTLY which RKEY file is used
        # ============================================================
        logger.info("="*70)
        logger.info("OEM ROOT KEY PROGRAMMING")
        logger.info(f"RKEY file: {oem_key_file}")
        logger.info(f"RKEY file exists: {oem_key_file.exists()}")
        logger.info(f"RKEY file size: {oem_key_file.stat().st_size if oem_key_file.exists() else 'N/A'} bytes")
        logger.info(f"Key slot ID: {key_id}")
        logger.info(f"Permanent lock: {'YES (irreversible!)' if permanent_lock else 'NO'}")
        logger.info("="*70)
        
        message_bytes, encrypted_key_size = self._parse_rkey_file(oem_key_file)
        if message_bytes is None:
            raise DeviceError(f"Failed to parse OEM root key file: {oem_key_file}. Check logs for details.")
        
        logger.info(f"RKEY File Details:")
        logger.info(f"Total size: {len(message_bytes)} bytes")
        logger.info(f"Magic: {message_bytes[0:4].hex()} (expected: REK1)")
        logger.info(f"Encrypted key size: {encrypted_key_size} bytes")
        logger.info("")
        
        # Command packet: 0x2E, KID, PLK
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x03'
        CMD = b'\x2E'
        KID = key_id.to_bytes(1, "big")
        PLK = (b'\x00' if permanent_lock else b'\xFF')  # 0x00=lock, 0xFF=no-lock
        SUM = self.client._calc_sum(LNH + LNL + CMD + KID + PLK)
        ETX = b'\x03'
        
        command = SOH + LNH + LNL + CMD + KID + PLK + SUM + ETX
        
        logger.info(f"Sending OEM root key command packet (0x2E, KID={key_id}, PLK={'locked' if permanent_lock else 'unlocked'})...")
        logger.debug(f"Command packet: {command.hex()}")
        self.client.ser.write(command)
        time.sleep(self.client.LONG_DELAY)
        
        logger.debug("Waiting for command packet response...")
        rp = self.client._receive_data_packet()
        
        # ============================================================
        # DETAILED LOGGING: Show EXACTLY what device responds
        # ============================================================
        logger.info("="*70)
        logger.info("OEM ROOT KEY COMMAND RESPONSE (CMD 0x2E):")
        logger.info(f"   Raw packet: {rp.hex()}")
        
        # Decode response status
        RES = rp[3] & 0x7F
        STS = rp[4] if len(rp) > 4 else None
        
        logger.info(f"   RES = 0x{RES:02X} (expected: 0x2E)")
        if STS is not None:
            logger.info(f"   STS = 0x{STS:02X} (expected: 0x00)")
        else:
            logger.info(f"   STS = None")
        
        # Interpret STS codes
        sts_codes = {
            0x00: "Success",
            0xE4: "Device not ready / state error",
            0xDB: "Key already programmed (warning)",
        }
        if STS is not None and STS != 0x00:
            sts_meaning = sts_codes.get(STS, "Unknown error code")
            logger.info(f"   STS Meaning: {sts_meaning}")
        logger.info("="*70)
        
        if RES != 0x2E:
            logger.error(f"[ERROR] OEM ROOT KEY COMMAND FAILED: RES=0x{RES:02X}, expected 0x2E")
            raise DeviceError(f"OEM root key command failed: device returned RES=0x{RES:02X}")

        if STS is not None and STS != 0x00:
            logger.warning(f"[WARN] Command returned warning status: STS=0x{STS:02X}")
            logger.warning(f"   This is typically NOT fatal - will proceed with data packet")
            logger.warning(f"   Device may still accept the OEM Root Key data")

        message_data = message_bytes[24:]

        if len(message_data) < 128:
            message_data = message_data + (b'\xFF' * (128 - len(message_data)))
            logger.debug(f"Padded message_data to 128 bytes (was {len(message_data)} bytes)")
        
        SOD = b'\x81'
        LNH = b'\x00'
        LNL = b'\x85'
        RES = b'\x2E'
        SKR = b'\x00' * 4

        key_data = SKR + message_data[0:32] + message_data[32:48] + message_data[48:128]
        
        logger.debug(f"Key data length: {len(key_data)} bytes (expected: 132)")
        logger.debug(f"Key data breakdown:")
        logger.debug(f"  SKR: {SKR.hex()}")
        logger.debug(f"  [0:32] (IV+encrypted first part): {message_data[0:32].hex()}")
        logger.debug(f"  [32:48] (encrypted middle): {message_data[32:48].hex()}")
        logger.debug(f"  [48:128] (encrypted last + padding): {message_data[48:128].hex()}")
        logger.debug(f"  Full key_data: {key_data.hex()}")
        
        SUM = self.client._calc_sum(LNH + LNL + RES + key_data)
        ETX = b'\x03'
        
        packet = SOD + LNH + LNL + RES + key_data + SUM + ETX
        
        logger.info(f"Data packet details:")
        logger.info(f"  Key data length: {len(key_data)} bytes (expected: 132)")
        logger.info(f"  Total packet length: {len(packet)} bytes (expected: 138)")
        logger.info(f"  LNL value: 0x{LNL.hex()} (should be 0x85 = 133 bytes for RES + key_data)")
        logger.info(f"  Packet header: {packet[:10].hex()}")
        
        logger.info("Sending OEM root key data packet...")
        self.client.ser.write(packet)
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        
        # ============================================================
        # DETAILED LOGGING: Show OEM Root Key data response
        # ============================================================
        logger.info("="*70)
        logger.info("OEM ROOT KEY DATA RESPONSE:")
        logger.info(f"   Raw packet: {rp.hex()}")
        
        # Decode data response
        RES = rp[3] & 0x7F
        STS = rp[4] if len(rp) > 4 else None
        
        logger.info(f"   RES = 0x{RES:02X} (expected: 0x2E)")
        if STS is not None:
            logger.info(f"   STS = 0x{STS:02X} (expected: 0x00)")
        else:
            logger.info(f"   STS = None")
        
        # Interpret STS codes for data response
        sts_codes = {
            0x00: "Success - Key programmed",
            0xDB: "Key already programmed (Config Area 2 cannot be erased)",
            0xE4: "Device state error / not ready",
            0xD0: "Key format error",
            0xD1: "Key verification failed",
        }
        if STS is not None and STS != 0x00:
            sts_meaning = sts_codes.get(STS, "Unknown error code")
            logger.info(f"   STS Meaning: {sts_meaning}")
        logger.info("="*70)
        
        if RES != 0x2E:
            logger.error(f"[ERROR] OEM ROOT KEY DATA FAILED: RES=0x{RES:02X}, expected 0x2E")
            raise DeviceError(f"OEM root key data response failed: RES=0x{RES:02X}")
        
        if STS is not None and STS != 0x00:
            if STS == 0xDB:
                raise DeviceError(
                    "OEM Root Key already programmed (STS=0xDB). "
                    "Full chip erase required! See logs for details."
                )
            else:
                logger.error(f"[ERROR] OEM ROOT KEY PROGRAMMING FAILED: STS=0x{STS:02X}")
                logger.error(f"Possible causes:")
                logger.error(f"RKEY file format error")
                logger.error(f"UFPK mismatch (RKEY encrypted with wrong UFPK)")
                logger.error(f"Device not in correct state (need PL2)")
                raise DeviceError(f"OEM root key programming failed: STS=0x{STS:02X}")
        
        logger.info("OEM root public key programmed successfully (STS=0x00)")
    
    def inject_dlm_key(self, key_file: Path, key_type: int) -> bool:
        """
        Inject DLM AL key (AL2=0x01, AL1=0x02) from .rkey file.
        
        Args:
            key_file: Path to .rkey file
            key_type: 0x01 for AL2, 0x02 for AL1
        
        Returns:
            True on success, False on failure
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        key_names = {0x01: "AL2", 0x02: "AL1"}
        logger.info(f"Injecting {key_names.get(key_type, 'Unknown')} key...")
        
        message_bytes, encrypted_key_size = self._parse_rkey_file(key_file)
        if message_bytes is None:
            return False
        
        SOH = b'\x01'
        LNH = b'\x00'
        LNL = b'\x02'
        CMD = b'\x28'
        KYTY = key_type.to_bytes(1, 'big')
        SUM = self.client._calc_sum(LNH + LNL + CMD + KYTY)
        ETX = b'\x03'
        
        self.client.ser.write(SOH + LNH + LNL + CMD + KYTY + SUM + ETX)
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        if (rp[3] & 0x7F) != 0x28:
            return False
        
        SOD = b'\x81'
        LNH = b'\x00'
        LNL = b'\x55'
        RES = b'\x28'
        SKR = b'\x00' * 4
        key_data = SKR + message_bytes[24:56] + message_bytes[56:72] + message_bytes[72:72+encrypted_key_size]
        SUM = self.client._calc_sum(LNH + LNL + RES + key_data)
        ETX = b'\x03'
        
        self.client.ser.write(SOD + LNH + LNL + RES + key_data + SUM + ETX)
        time.sleep(self.client.LONG_DELAY)
        
        rp = self.client._receive_data_packet()
        if (rp[3] & 0x7F) == 0x28 and rp[4] == 0x00:
            logger.info(f"{key_names.get(key_type, 'Unknown')} key injected successfully")
            return True
        
        return False


