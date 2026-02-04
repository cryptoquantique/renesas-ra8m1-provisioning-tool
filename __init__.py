"""
RA8M1 PC Provisioning Tool

A Python-based CLI tool for provisioning the Renesas RA8M1 microcontroller
with secure boot capabilities.

This tool is provided as an example in support to the document "Secure Boot - 
Bare Metal Practical Guide - RA8M1"

This package provides functionality for:
- Device communication via USB and UART using Renesas Boot Firmware protocol
- Firmware programming and verification (bootloader and application)
- Cryptographic key provisioning via HSM (AWS KMS)
- Certificate management and provisioning (Key Certificate, Code Certificate)
- Secure firmware signing using HSM
- Production-level provisioning workflows
"""

__version__ = "1.0.0"
__author__ = "Crypto Quantique"
__work_package__ = "Secure Boot - Bare Metal Practical Guide - RA8M1"

