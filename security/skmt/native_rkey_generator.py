"""
Native RKEY Generator - Pure Python implementation.

Generates RKEY files (wrapped OEM Root Public Key) without requiring SKMT.
This eliminates the dependency on the Windows-only Renesas SKMT tool.

The RKEY wraps the OEM Root Public Key (Qx||Qy, 64 bytes) using the UFPK
(32-byte User Factory Programming Key) with AES-CBC encryption + CBC-MAC
authentication.

RKEY binary format (REK1):
    Bytes  0- 3: Magic "REK1" (ASCII)
    Bytes  4- 7: Suite version (big-endian uint32, default=1)
    Bytes  8-14: Reserved (7 bytes, zeros)
    Byte     15: Key type (0xFD = OEM_ROOT_PK)
    Bytes 16-19: Encrypted key size (big-endian uint32)
    Bytes 20-55: Wrapped UFPK from DLM (36 bytes)
    Bytes 56-71: IV (16 bytes, random)
    Bytes 72-151: Encrypted key data (80 bytes: 64 CBC + 16 MAC block)
    Bytes 152-155: CRC32 MSB-first (4 bytes)

Encryption uses AES-CBC + CBC-MAC (NOT AES-CCM!):
    cbc_key = UFPK[:16]   (first 16 bytes for AES-CBC encryption)
    mac_key = UFPK[16:]   (last 16 bytes for AES-CBC-MAC)
"""

import base64
import os
import struct
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from models.keys import WrappedKey
from utils.exceptions import SKMTError
from utils.logging import get_logger

logger = get_logger(__name__)


# RKEY format constants
RKEY_MAGIC = b'REK1'
RKEY_KEY_TYPE_OEM_ROOT_PK = 0xFD
RKEY_DEFAULT_SUITE_VERSION = 1


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """
    Encrypt a single 16-byte block with AES-ECB.
    
    Args:
        key: 16-byte AES key
        block: 16-byte plaintext block
        
    Returns:
        16-byte ciphertext block
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def crc32_msb(data: bytes, poly: int = 0x04C11DB7, init: int = 0xFFFFFFFF) -> int:
    """
    Calculate CRC32 using MSB-first (non-reflected) polynomial.
    
    This matches the Renesas RKEY CRC32 format:
        - Polynomial: 0x04C11DB7 (MSB-first, NOT reflected)
        - Initial value: 0xFFFFFFFF
        - NO final XOR
    
    Args:
        data: Input bytes
        poly: CRC polynomial (default: 0x04C11DB7)
        init: Initial CRC value (default: 0xFFFFFFFF)
        
    Returns:
        32-bit CRC value
    """
    crc = init
    for b in data:
        crc ^= (b << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def extract_ecc_p256_raw_key(pem_data: bytes) -> bytes:
    """
    Extract raw ECC P-256 public key as Qx||Qy (64 bytes) from PEM.
    
    CRITICAL: Returns Qx||Qy WITHOUT the 0x04 uncompressed point prefix!
    This matches the Renesas RSIP-E51A expected format.
    
    Args:
        pem_data: PEM-encoded public key bytes
        
    Returns:
        64-byte raw key: Qx (32 bytes) || Qy (32 bytes)
        
    Raises:
        SKMTError: If key extraction fails
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        
        pub_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise SKMTError("Key is not an ECC key")
        
        if not isinstance(pub_key.curve, ec.SECP256R1):
            raise SKMTError(f"Expected P-256 curve, got {pub_key.curve.name}")
        
        # Get uncompressed point (0x04 || Qx || Qy)
        raw_point = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        
        # Strip the 0x04 prefix → return Qx||Qy (64 bytes)
        if len(raw_point) == 65 and raw_point[0] == 0x04:
            return raw_point[1:]
        elif len(raw_point) == 64:
            return raw_point
        else:
            raise SKMTError(f"Unexpected key size: {len(raw_point)} bytes (expected 64 or 65)")
        
    except SKMTError:
        raise
    except Exception as e:
        raise SKMTError(f"Failed to extract ECC P-256 public key: {e}") from e


def wrap_user_key(user_key: bytes, ufpk: bytes, iv: bytes) -> bytes:
    """
    Wrap (encrypt) a user key using Renesas AES-CBC + CBC-MAC scheme.
    
    The UFPK (32 bytes) is split into two 16-byte keys:
        - cbc_key = UFPK[:16]  → used for AES-CBC encryption
        - mac_key = UFPK[16:]  → used for AES-CBC-MAC authentication
    
    For each 16-byte block of the user key:
        1. MAC update:  mac = AES_ECB(mac_key, block XOR mac)
        2. CBC encrypt: ct  = AES_ECB(cbc_key, block XOR current_iv)
        3. Update IV to ciphertext for next block
    
    Final block: AES_ECB(cbc_key, mac XOR last_iv)
    
    Args:
        user_key: Plaintext key to wrap (must be multiple of 16 bytes)
        ufpk: 32-byte User Factory Programming Key
        iv: 16-byte initialization vector
        
    Returns:
        Encrypted key data: len(user_key) + 16 bytes (includes MAC block)
        
    Raises:
        SKMTError: If parameters are invalid
    """
    if len(ufpk) != 32:
        raise SKMTError(f"UFPK must be 32 bytes, got {len(ufpk)}")
    if len(iv) != 16:
        raise SKMTError(f"IV must be 16 bytes, got {len(iv)}")
    if len(user_key) % 16 != 0:
        raise SKMTError(f"User key must be multiple of 16 bytes, got {len(user_key)}")

    cbc_key = ufpk[:16]   # First 16 bytes: AES-CBC encryption key
    mac_key = ufpk[16:]   # Last 16 bytes:  AES-CBC-MAC key

    mac = bytes(16)        # MAC accumulator (starts as zeros)
    current_iv = iv        # CBC IV (updated each block)
    encrypted_blocks = []

    for i in range(0, len(user_key), 16):
        block = user_key[i:i + 16]

        # Update MAC: mac = AES_ECB(mac_key, block XOR mac)
        mac = aes_ecb_encrypt(
            mac_key,
            bytes(a ^ b for a, b in zip(block, mac))
        )

        # CBC encrypt: ct = AES_ECB(cbc_key, block XOR current_iv)
        ct = aes_ecb_encrypt(
            cbc_key,
            bytes(a ^ b for a, b in zip(block, current_iv))
        )

        encrypted_blocks.append(ct)
        current_iv = ct  # Update IV to ciphertext for next block

    # Final block: AES_ECB(cbc_key, mac XOR last_iv)
    final_block = aes_ecb_encrypt(
        cbc_key,
        bytes(a ^ b for a, b in zip(mac, current_iv))
    )

    return b"".join(encrypted_blocks) + final_block


def generate_rkey_native(
    oem_root_pk_pem: bytes,
    ufpk: bytes,
    w_ufpk: bytes,
    output_file: Optional[Path] = None,
    iv: Optional[bytes] = None,
) -> Tuple[bytes, Path]:
    """
    Generate RKEY file natively in Python (no SKMT required).
    
    Wraps the OEM Root Public Key using the Renesas AES-CBC + CBC-MAC
    scheme and packages it in the REK1 binary format.
    
    Args:
        oem_root_pk_pem: OEM Root Public Key in PEM format
        ufpk: 32-byte plain UFPK (User Factory Programming Key)
        w_ufpk: 36-byte wrapped UFPK from DLM
        output_file: Optional output file path for .rkey file
        iv: Optional 16-byte IV (random if None)
        
    Returns:
        Tuple of (rkey_binary_data, output_path)
        
    Raises:
        SKMTError: If generation fails
    """
    # Validate inputs
    if len(ufpk) != 32:
        raise SKMTError(f"UFPK must be 32 bytes, got {len(ufpk)}")
    if len(w_ufpk) != 36:
        raise SKMTError(f"Wrapped UFPK must be 36 bytes, got {len(w_ufpk)}")
    
    # Extract raw public key bytes: Qx||Qy (64 bytes, NO 0x04 prefix)
    raw_pk = extract_ecc_p256_raw_key(oem_root_pk_pem)
    if len(raw_pk) != 64:
        raise SKMTError(f"OEM Root PK must be 64 bytes (Qx||Qy), got {len(raw_pk)} bytes")
    logger.info(f"OEM Root PK: {len(raw_pk)} bytes (Qx||Qy, ECC P-256)")
    
    # Generate random IV if not provided
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise SKMTError(f"IV must be 16 bytes, got {len(iv)}")
    
    # Wrap the public key using AES-CBC + CBC-MAC
    encrypted_key = wrap_user_key(raw_pk, ufpk, iv)
    # encrypted_key = 64 bytes encrypted blocks + 16 bytes MAC block = 80 bytes
    logger.info(f"Encrypted key data: {len(encrypted_key)} bytes (64 CBC + 16 MAC)")
    
    # Build REK1 binary
    binary = bytearray()
    binary += RKEY_MAGIC                                          # Magic "REK1" (4 bytes)
    binary += struct.pack(">I", RKEY_DEFAULT_SUITE_VERSION)       # Suite Version (4 bytes)
    binary += b"\x00" * 7                                         # Reserved (7 bytes)
    binary += struct.pack("B", RKEY_KEY_TYPE_OEM_ROOT_PK)         # Key Type 0xFD (1 byte)
    binary += struct.pack(">I", len(encrypted_key))               # Encrypted Key Size (4 bytes)
    binary += w_ufpk                                              # Wrapped UFPK (36 bytes)
    binary += iv                                                  # IV (16 bytes)
    binary += encrypted_key                                       # Encrypted Key (80 bytes)
    
    # CRC32 MSB-first over all preceding bytes
    crc = crc32_msb(bytes(binary))
    binary += struct.pack(">I", crc)
    
    rkey_binary = bytes(binary)
    
    logger.info(f"RKEY binary: {len(rkey_binary)} bytes total")
    logger.info(f"  Header: 20 bytes (magic + suite + reserved + type + size)")
    logger.info(f"  W-UFPK: 36 bytes")
    logger.info(f"  IV: 16 bytes")
    logger.info(f"  Encrypted key: {len(encrypted_key)} bytes")
    logger.info(f"  CRC32: 0x{crc:08X}")
    
    # Convert to PEM-like format
    b64_data = base64.b64encode(rkey_binary).decode('ascii')
    b64_lines = [b64_data[i:i + 64] for i in range(0, len(b64_data), 64)]
    pem_content = (
        "-----BEGIN RENESAS KEY-----\n"
        + "\n".join(b64_lines) + "\n"
        + "-----END RENESAS KEY-----\n"
    )
    
    # Write to file
    if output_file:
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(pem_content, encoding='utf-8')
        logger.info(f"RKEY file generated (native): {output_file}")
    
    return rkey_binary, output_file


def generate_rkey_from_files(
    oem_root_pk_file: Path,
    ufpk_file: Path,
    output_file: Path,
    w_ufpk_file: Optional[Path] = None,
) -> WrappedKey:
    """
    Generate RKEY from OEM Root PK, plain UFPK and wrapped UFPK files.
    
    Args:
        oem_root_pk_file: Path to OEM Root Public Key (PEM format)
        ufpk_file: Path to plain UFPK file (32 bytes)
        output_file: Path to output .rkey file
        w_ufpk_file: Path to wrapped UFPK file from DLM (36 bytes).
                     If None, searches in same directory as ufpk_file.
        
    Returns:
        WrappedKey object with generated RKEY data
        
    Raises:
        SKMTError: If generation fails
    """
    if not oem_root_pk_file.exists():
        raise SKMTError(f"OEM Root PK file not found: {oem_root_pk_file}")
    if not ufpk_file.exists():
        raise SKMTError(f"UFPK file not found: {ufpk_file}")
    
    # Find wrapped UFPK if not provided
    if w_ufpk_file is None:
        w_ufpk_file = ufpk_file.parent / "ufpk_wrapped_decrypted.key"
    
    if not w_ufpk_file.exists():
        raise SKMTError(
            f"Wrapped UFPK file not found: {w_ufpk_file}\n"
            "The RKEY requires both the plain UFPK (32 bytes) and the "
            "wrapped UFPK from DLM (36 bytes).\n"
            "Run 'invoke prepare-ufpk' to generate both files."
        )
    
    # Read inputs
    oem_root_pk_pem = oem_root_pk_file.read_bytes()
    ufpk = ufpk_file.read_bytes()
    w_ufpk = w_ufpk_file.read_bytes()
    
    # Validate UFPK size
    if len(ufpk) != 32:
        raise SKMTError(
            f"Plain UFPK must be exactly 32 bytes, got {len(ufpk)} bytes.\n"
            f"File: {ufpk_file}"
        )
    
    if len(w_ufpk) != 36:
        raise SKMTError(
            f"Wrapped UFPK must be exactly 36 bytes, got {len(w_ufpk)} bytes.\n"
            f"File: {w_ufpk_file}"
        )
    
    logger.info(f"UFPK: {len(ufpk)} bytes (plain)")
    logger.info(f"W-UFPK: {len(w_ufpk)} bytes (wrapped from DLM)")
    
    # Generate RKEY
    rkey_binary, out_path = generate_rkey_native(
        oem_root_pk_pem=oem_root_pk_pem,
        ufpk=ufpk,
        w_ufpk=w_ufpk,
        output_file=output_file,
    )
    
    return WrappedKey(
        key_type="OEM_ROOT_PK",
        wrapped_data=rkey_binary,
        file_path=str(output_file),
    )
