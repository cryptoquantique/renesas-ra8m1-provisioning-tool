"""
RA8 Certificate Programming Module.

Handles Key Certificate and Code Certificate programming.
"""

import time
from pathlib import Path

from device.ra8_provisioning_client import RA8ProvisioningClient
from utils.logging import get_logger
from utils.exceptions import DeviceError

logger = get_logger(__name__)


class RA8CertificateProgrammer:
    """Handles certificate programming operations for RA8 devices."""
    
    def __init__(self, client: RA8ProvisioningClient):
        """
        Initialize certificate programmer.
        
        Args:
            client: RA8ProvisioningClient instance
        """
        self.client = client
    
    def _send_cert_single(self, keydata: bytes, certdata: bytes) -> bytearray:
        """
        Send certificate data in single packet (≤1024B).
        
        Packet format:
        SOD (1 byte) 81h
        LNH (1 byte) N + M + 1 (Higher 1 byte)
        LNL (1 byte) N + M + 1 (Lower 1 byte)
        RES (1 byte) 26h (OK)
        KCD (N bytes) Key certificate data
        CCD (M bytes) Code certificate data
        SUM (1 byte) Sum data
        ETX (1 byte) 03h
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        length = len(keydata) + len(certdata) + 1  # RES(1) + Data(N+M)
        SOD = b'\x81'
        LNH = (length >> 8).to_bytes(1, 'big')
        LNL = (length & 0xFF).to_bytes(1, 'big')
        RES = b'\x26'
        SUM = self.client._calc_sum(LNH + LNL + RES + keydata + certdata)
        ETX = b'\x03'
        
        pkt = SOD + LNH + LNL + RES + keydata + certdata + SUM + ETX
        
        logger.info("Sending certificate data packet...")
        logger.info(f"  Packet length: {len(pkt)} bytes")
        logger.info(f"  Data length: KCS={len(keydata)}, CCS={len(certdata)}, Total={len(keydata)+len(certdata)}")
        logger.info(f"  Packet header: {pkt[:10].hex()}")
        
        self.client.ser.reset_input_buffer()
        self.client.ser.reset_output_buffer()
        self.client.ser.write(pkt)
        time.sleep(self.client.LONG_DELAY)
        time.sleep(self.client.LONG_DELAY)
        
        logger.info("Waiting for certificate data response...")
        ack = self.client._receive_data_packet()
        logger.info(f"Certificate data response: {ack.hex()}")
        return ack
    
    def program_certificates(self, key_cert_file: Path, code_cert_file: Path) -> None:
        """
        Program Key Certificate and Code Certificate (CMD 0x26).
        
        Args:
            key_cert_file: Path to key certificate binary file
            code_cert_file: Path to code certificate binary file
        
        Raises:
            DeviceError: If programming fails
        """
        if not self.client.ser:
            raise DeviceError("Not connected")
        
        # ============================================================
        # DETAILED LOGGING: Show EXACTLY which certificate files are used
        # ============================================================
        logger.info("="*70)
        logger.info("CERTIFICATE PROGRAMMING")
        logger.info(f"   Key Certificate: {key_cert_file}")
        logger.info(f"   Code Certificate: {code_cert_file}")
        logger.info(f"   Key Cert exists: {key_cert_file.exists()}")
        logger.info(f"   Code Cert exists: {code_cert_file.exists()}")
        
        # Extract version from filename if present (e.g., key_cert_v50.bin)
        key_cert_name = key_cert_file.stem
        if '_v' in key_cert_name:
            cert_version = key_cert_name.split('_v')[-1]
            logger.info(f"   Certificate Version: {cert_version}")
        else:
            logger.info(f"   Certificate Version: (no version in filename)")
        logger.info("="*70)
        logger.info("")
        
        # Load certificate files
        try:
            with open(key_cert_file, 'rb') as f:
                key_cert_data = f.read()
            with open(code_cert_file, 'rb') as f:
                code_cert_data = f.read()
        except Exception as e:
            raise DeviceError(f"Failed to read certificate files: {e}")
        
        # Validate sizes
        if len(key_cert_data) > 0xFFFF or len(code_cert_data) > 0xFFFF:
            raise DeviceError("Certificate too large (>65535 bytes).")
        
        # Data packet limit per spec: ≤1024 bytes
        if len(key_cert_data) > 1024:
            raise DeviceError(f"KeyCert exceeds 1024-byte data packet limit ({len(key_cert_data)}).")
        
        if len(code_cert_data) > 1024:
            raise DeviceError(f"CodeCert exceeds 1024-byte data packet limit ({len(code_cert_data)}).")
        
        logger.info(f"KCS={len(key_cert_data)} bytes (0x{len(key_cert_data):04X})")
        logger.info(f"CCS={len(code_cert_data)} bytes (0x{len(code_cert_data):04X})")
        logger.debug(f"KeyCert head: {key_cert_data[:16].hex() if key_cert_data else '(skipped)'}")
        logger.debug(f"CodeCert head: {code_cert_data[:16].hex()}")
        
        # Command phase (0x26)
        SOH = b'\x01'
        CMD = b'\x26'
        MAC = b'\x02'  # HMAC-SHA256
        KCS = len(key_cert_data).to_bytes(2, 'big')
        CCS = len(code_cert_data).to_bytes(2, 'big')
        LNH = b'\x00'
        LNL = b'\x06'  # CMD+MAC+KCS+CCS = 6 bytes
        SUM = self.client._calc_sum(LNH + LNL + CMD + MAC + KCS + CCS)
        ETX = b'\x03'
        
        cmd = SOH + LNH + LNL + CMD + MAC + KCS + CCS + SUM + ETX
        
        logger.info("Sending code certificate command...")
        logger.info(f"Command packet: {cmd.hex()}")
        logger.info(f"  KCS={len(key_cert_data)}, CCS={len(code_cert_data)}")
        self.client.ser.write(cmd)
        time.sleep(self.client.LONG_DELAY)
        
        ack_cmd = self.client._receive_data_packet()
        st_cmd = self.client._decode_status_packet(ack_cmd)
        
        # ============================================================
        # DETAILED LOGGING: Show EXACTLY what device responds
        # ============================================================
        logger.info("="*70)
        logger.info("CERTIFICATE COMMAND RESPONSE (CMD 0x26):")
        logger.info(f"Raw packet: {ack_cmd.hex()}")
        logger.info(f"Decoded: {st_cmd}")
        logger.info(f"RES = 0x{st_cmd.get('RES', 0):02X} (expected: 0x26)")
        logger.info(f"STS = 0x{st_cmd.get('STS', 0):02X} (expected: 0x00)")
        
        # Interpret STS codes
        sts_codes = {
            0x00: "Success",
            0xD3: "Certificates already programmed (cannot reprogram without erase)",
            0xDB: "Certificate programming warning/error",
            0xDC: "Certificate version too low - INCREASE VERSION in project_config.json",
            0xE4: "Device state error",
        }
        sts_val = st_cmd.get("STS")
        if sts_val is not None:
            sts_meaning = sts_codes.get(sts_val, f"Unknown error code")
            logger.info(f"   STS Meaning: {sts_meaning}")
        logger.info("="*70)
        
        if st_cmd.get("RES") != 0x26:
            raise DeviceError(f"Code certificate command failed (RES != 0x26, got 0x{st_cmd.get('RES', 0):02X})")
        
        if st_cmd.get("STS") not in (0x00, None):

            if st_cmd.get("STS") == 0xD3:
                logger.info("Code certificate programming skipped (already present)")
                return
            else:
                # Any other non-zero STS is a real error!
                logger.error(f"CERTIFICATE COMMAND FAILED: STS=0x{st_cmd.get('STS'):02X}")
                logger.error(f"   Device rejected certificate command!")
                raise DeviceError(f"Certificate command failed with STS=0x{st_cmd.get('STS'):02X}")

        logger.info("Sending certificate data packet...")
        cert_ret = self._send_cert_single(key_cert_data, code_cert_data)
        cert_stat = self.client._decode_status_packet(cert_ret)
        
        # ============================================================
        # DETAILED LOGGING: Show certificate data response
        # ============================================================
        logger.info("="*70)
        logger.info("CERTIFICATE DATA RESPONSE:")
        logger.info(f"   Raw packet: {cert_ret.hex()}")
        logger.info(f"   Decoded: {cert_stat}")
        logger.info(f"   RES = 0x{cert_stat.get('RES', 0):02X} (expected: 0x26)")
        logger.info(f"   STS = 0x{cert_stat.get('STS', 0):02X} (expected: 0x00)")
        
        sts_val = cert_stat.get("STS")
        if sts_val is not None and sts_val != 0x00:
            sts_meaning = sts_codes.get(sts_val, f"Unknown error code")
            logger.info(f"   STS Meaning: {sts_meaning}")
        logger.info("="*70)
        
        if cert_stat.get("RES") != 0x26:
            raise DeviceError(f"Code certificate programming failed (RES != 0x26, got 0x{cert_stat.get('RES', 0):02X})")
        
        if cert_stat.get("STS") not in (0x00, None):
            sts = cert_stat.get('STS')
            logger.error(f"CERTIFICATE DATA REJECTED: STS=0x{sts:02X}")
            
            if sts == 0xDC:
                # Certificate version error - user needs to increase version
                logger.error("")
                logger.error("="*70)
                logger.error("CERTIFICATE VERSION ERROR (0xDC)")
                logger.error("="*70)
                logger.error("")
                logger.error("The certificate version is too low or certificates already exist.")
                logger.error("")
                logger.error("SOLUTION: Increase the certificate version in project_config.json:")
                logger.error("")
                logger.error('   "certificates": {')
                logger.error('       "version": 26,    <-- Increase this value (e.g., 25 -> 26)')
                logger.error('       ...')
                logger.error('   }')
                logger.error("")
                logger.error("Then regenerate certificates:")
                logger.error("   invoke gen-fsbl-certs")
                logger.error("")
                logger.error("="*70)
                raise DeviceError(
                    f"Certificate version too low (STS=0xDC). "
                    f"Increase 'certificates.version' in project_config.json and regenerate certificates."
                )
            else:
                logger.error(f"   Possible causes:")
                logger.error(f"   - Public key mismatch (certificate key != OEM Root Key)")
                logger.error(f"   - Certificate format error")
                logger.error(f"   - Certificate signature invalid")
                logger.error(f"   - RKEY not programmed correctly")
                raise DeviceError(f"Certificate programming failed with STS=0x{sts:02X}")
        
        logger.info("Code certificate programmed successfully (STS=0x00)")


