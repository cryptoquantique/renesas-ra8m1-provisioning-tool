# RA8M1 Provisioning Tool

A secure provisioning solution for Renesas RA8M1 microcontrollers with MCUboot secure boot. This tool provides end-to-end automation for device provisioning including key management via AWS KMS, certificate generation, firmware signing, and device programming.

---

## System Architecture

```
+==============================================================================+
|                              PROVISIONING WORKFLOW                            |
+==============================================================================+

    +------------------+         +------------------+         +------------------+
    |   AWS KMS        |         |   PREREQUISITES  |         |   OUTPUT         |
    |------------------|         |------------------|         |------------------|
    | - OEM Root SK    |         | - bootloader.srec|         | - combined.srec  |
    | - OEM BL SK      |         | - application.bin|         | - key_cert.bin   |
    | - Customer SK    |         | - project_config |         | - code_cert.bin  |
    +--------+---------+         +--------+---------+         +--------+---------+
             |                            |                            ^
             v                            v                            |
    +--------+----------------------------+----------------------------+--------+
    |                                                                           |
    |   +-----------------+    +-----------------+    +-----------------+       |
    |   |   SIGN-APP      |    | MAKE-COMBINED   |    | GEN-FSBL-CERTS  |       |
    |   |-----------------|    |-----------------|    |-----------------|       |
    |   | 1. Load app.bin | -> | 1. Inject key   | -> | 1. Key Cert     |       |
    |   | 2. MCUboot hdr  |    | 2. Combine SREC |    | 2. Code Cert    |       |
    |   | 3. AWS KMS sign |    | 3. Verify       |    | 3. CRC check    |       |
    |   +-----------------+    +-----------------+    +-----------------+       |
    |                                                                           |
    +--------+------------------------------------------------------------------+
             |
             v
    +--------+----------------------------+
    |      PROGRAM-DEVICE                 |
    |-------------------------------------|
    | 1. Flash RKEY (wrapped OEM Root PK) |
    | 2. Flash Key Certificate            |
    | 3. Flash Code Certificate           |
    | 4. Flash combined.srec              |
    +-------------------------------------+
             |
             v
    +-------------------------------------+
    |      RA8M1 DEVICE                   |
    |-------------------------------------|
    | - Secure boot enabled               |
    | - Chain of trust verified           |
    | - Application running               |
    +-------------------------------------+


                              CHAIN OF TRUST

    +-------------------+
    | Renesas Root      |  (Factory programmed)
    +--------+----------+
             |
             v signs
    +--------+----------+
    | OEM Root PK       |  (Wrapped as RKEY with UFPK)
    +--------+----------+
             |
             v signs
    +--------+----------+
    | Key Certificate   |  Contains: OEM BL PK Hash
    +--------+----------+
             |
             v authenticates
    +--------+----------+
    | OEM Bootloader PK |
    +--------+----------+
             |
             v signs
    +--------+----------+
    | Code Certificate  |  Contains: Bootloader CRC
    +--------+----------+
             |
             v authenticates
    +--------+----------+
    | Bootloader        |  With injected Customer PK
    +--------+----------+
             |
             v verifies
    +--------+----------+
    | Application       |  Signed with Customer SK
    +-------------------+


                              DATA FLOW

    application.bin ─────────────────────────────────────────────────────┐
         │                                                               │
         ▼                                                               │
    ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
    │  sign-app   │ ──► │ app.bin.signed   │ ──► │ app_offset.srec  │   │
    └─────────────┘     └──────────────────┘     └────────┬─────────┘   │
         │                                                 │            │
         │ AWS KMS                                         │            │
         │ Customer SK                                     │            │
         ▼                                                 │            │
    customer_public.pem                                    │            │
                                                           │            │
    bootloader.srec ───────────────────────────────────────┼────────────┤
         │                                                 │            │
         ▼                                                 ▼            │
    ┌───────────────────────┐     ┌────────────────────────────────┐   │
    │ Key Injection         │ ──► │ bootloader_with_aws_key.srec   │   │
    │ (Customer PK @addr)   │     └────────────────┬───────────────┘   │
    └───────────────────────┘                      │                   │
         │                                         │                   │
         │ AWS KMS                                 ▼                   │
         │ Customer PK                    ┌────────────────┐           │
         ▼                                │ make-combined  │           │
    ┌───────────────────┐                 │     -srec      │           │
    │ gen-fsbl-certs    │                 └───────┬────────┘           │
    │                   │                         │                    │
    │ AWS KMS:          │                         ▼                    │
    │ - OEM Root SK     │                 ┌───────────────┐            │
    │ - OEM BL SK       │                 │ combined.srec │            │
    └────────┬──────────┘                 └───────────────┘            │
             │                                    │                    │
             ▼                                    │                    │
    ┌────────────────┐                            │                    │
    │ key_cert.bin   │ ◄──────────────────────────┼────────────────────┘
    │ code_cert.bin  │                            │
    └────────────────┘                            │
             │                                    │
             └────────────────────┬───────────────┘
                                  │
                                  ▼
                         ┌────────────────┐
                         │ program-device │
                         └───────┬────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │  RA8M1 Device  │
                         └────────────────┘
```

---

## Table of Contents

0. [System Architecture](#system-architecture)

1. [Project Setup and Configuration](#1-project-setup-and-configuration)
   - [System Requirements](#11-system-requirements)
   - [Installation](#12-installation)
   - [AWS Configuration](#13-aws-configuration)
   - [Project Configuration File](#14-project-configuration-file)
   - [Prerequisites Folder](#15-prerequisites-folder)

2. [Provisioning Tool Usage](#2-provisioning-tool-usage)
   - [Workflow Overview](#21-workflow-overview)
   - [One-Time Setup Commands](#22-one-time-setup-commands)
   - [Firmware Build Commands](#23-firmware-build-commands)
   - [Complete Workflow Command](#24-complete-workflow-command)
   - [Configuration Reference](#25-configuration-reference)

3. [Device Programming](#3-device-programming)
   - [Hardware Setup](#31-hardware-setup)
   - [Program Device Command](#32-program-device-command)
   - [Programming Procedure](#33-programming-procedure)
   - [Reset Procedure](#34-reset-procedure)

4. [Troubleshooting](#4-troubleshooting)
   - [Common Errors](#41-common-errors)
   - [Verification Commands](#42-verification-commands)
   - [Debug Procedures](#43-debug-procedures)

5. [API Documentation](#5-api-documentation)
   - [Generating Documentation](#51-generating-documentation)
   - [Documentation Structure](#52-documentation-structure)
   - [Class Diagrams](#53-class-diagrams)

---

## 1. Project Setup and Configuration

### 1.1 System Requirements

#### Operating System
- Windows 10/11 (64-bit)
- Linux and macOS are not supported

#### Hardware
- Renesas EK-RA8M1 evaluation board (or compatible RA8M1 device)
- J-Link debugger (integrated on EK-RA8M1)
- USB cable for power and debug connection

#### Software Prerequisites
- Python 3.10 or later
- AWS CLI v2
- GnuPG 2.4 or later (Gpg4win recommended)
- Renesas Security Key Management Tool (SKMT) 1.1.1 or later
- Renesas Flash Programmer (RFP) 3.12 or later

---

### 1.2 Installation

#### Step 1: Clone or Extract the Repository

```bash
git clone <repository-url> ra8m1-provisioning-tool
cd ra8m1-provisioning-tool
```

#### Step 2: Create Python Virtual Environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `click` - Command-line interface framework
- `invoke` - Task execution framework
- `boto3` - AWS SDK for Python
- `cryptography` - Cryptographic operations
- `pyserial` - Serial communication
- `python-gnupg` - GnuPG wrapper

#### Step 4: Install External Tools

**GnuPG (Gpg4win):**
1. Download from https://gnupg.org/download/
2. Install with default settings
3. Verify: `gpg --version`

**AWS CLI:**
1. Download from https://aws.amazon.com/cli/
2. Install MSI package
3. Verify: `aws --version`

**Renesas SKMT:**
1. Download from Renesas website (requires registration)
2. Install to default path: `C:\Renesas\SecurityKeyManagementTool\`
3. Verify: `"C:\Renesas\SecurityKeyManagementTool\cli\skmt.exe" /?`

**Renesas Flash Programmer (RFP):**
1. Download from Renesas website
2. Install with default settings
3. Verify by launching RFP GUI

#### Step 5: Verify Installation

```bash
invoke --list
```

You should see all available commands listed.

---

### 1.3 AWS Configuration

The provisioning tool uses AWS Key Management Service (KMS) for secure key storage and signing operations. Private keys never leave the AWS HSM.

#### 1.3.1 Create AWS IAM User

1. Log in to AWS Console
2. Navigate to IAM > Users > Create User
3. Create a user with programmatic access
4. Attach the following policy (minimum required permissions):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Sign",
                "kms:GetPublicKey",
                "kms:DescribeKey",
                "kms:CreateKey",
                "kms:TagResource"
            ],
            "Resource": "*"
        }
    ]
}
```

5. Save the Access Key ID and Secret Access Key

#### 1.3.2 Create Environment File

Create a `.env` file in the `provisioning_tool` directory:

```bash
# AWS Credentials
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_DEFAULT_REGION=eu-west-2
```

The tool reads credentials from this file automatically. The file is excluded from version control via `.gitignore`.

**Alternative:** Use AWS CLI configuration:
```bash
aws configure
```

#### 1.3.3 Create AWS KMS Keys

You need three ECC P-256 keys in AWS KMS:

| Key Name | Purpose | Usage |
|----------|---------|-------|
| OEM Root Key | Root of trust for device | Signs Key Certificate |
| OEM Bootloader Key | Bootloader authentication | Signs Code Certificate |
| MCUboot App Key | Application signing | Signs application firmware |

**Create keys via AWS Console:**

1. Navigate to KMS > Customer managed keys > Create key
2. Select:
   - Key type: Asymmetric
   - Key usage: Sign and verify
   - Key spec: ECC_NIST_P256
3. Set alias (e.g., `oem-root-key`, `oem-bootloader-key`, `mcuboot-app-key`)
4. Configure key policy to allow your IAM user
5. Copy the Key ID (UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

**Create keys via AWS CLI:**

```bash
# Create OEM Root Key
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --description "OEM Root Key for RA8M1"

# Create OEM Bootloader Key
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --description "OEM Bootloader Key for RA8M1"

# Create MCUboot App Key
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --description "MCUboot Application Signing Key"
```

#### 1.3.4 Changing AWS Region

To use a different AWS region:

1. Update `.env` file:
   ```bash
   AWS_DEFAULT_REGION=us-east-1
   ```

2. Update `project_config.json`:
   ```json
   {
     "aws": {
       "region": "us-east-1"
     }
   }
   ```

3. Ensure your KMS keys exist in the new region (keys are region-specific)

#### 1.3.5 Verify AWS Access

```bash
# List your KMS keys
aws kms list-keys

# Verify specific key access
aws kms describe-key --key-id YOUR_KEY_ID

# Test signing permission
aws kms get-public-key --key-id YOUR_KEY_ID
```

---

### 1.4 Project Configuration File

The `project_config.json` file is the central configuration for the provisioning tool. All parameters are read from this file.

#### 1.4.1 Create Configuration File

Copy or modify the existing file: [project_config.json](./project_config.json)

#### 1.4.2 Configuration Structure

```json
{
    "project_name": "Renesas RA8M1 Secure Boot Provisioning",
    "version": "1.0.0",
    
    "aws": {
        "region": "eu-west-2",
        "kms": {
            "oem_root_key_id": "3ce24d75-caec-4ba9-b10a-38f7c3ff6dc0",
            "oem_bootloader_key_id": "dc603d76-09dd-48ec-bc24-ae0c033746cf",
            "mcuboot_app_key_id": "2f6a02f8-2fc9-4592-b22a-ed86ba1d0ed9"
        }
    },
    
    "paths": {
        "bootloader_srec": "prerequisites/bootloader.srec",
        "application_bin": "prerequisites/application.bin",
        "output_dir": "output"
    },
    
    "firmware": {
        "inject_customer_key": true,
        "mcuboot_pubkey_addr": "0x02009114",
        "app_offset": "0x02010000"
    },
    
    "certificates": {
        "load_addr": "0x02000000",
        "oembl_size": "0x00030000",
        "cfsize": "0x200000"
    },
    
    "versioning": {
        "certificate_version": 23,
        "app_version": "1.0.0"
    },
    
    "imgtool": {
        "align": 128,
        "header_size": 512,
        "slot_size": 131072,
        "pad_header": true,
        "confirm": true
    }
}
```

#### 1.4.3 Configuration Parameters Explained

**AWS Section:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `region` | AWS region where KMS keys are located | `eu-west-2` |
| `oem_root_key_id` | Key ID for OEM Root Key (signs Key Certificate) | UUID |
| `oem_bootloader_key_id` | Key ID for OEM Bootloader Key (signs Code Certificate) | UUID |
| `mcuboot_app_key_id` | Key ID for MCUboot App Key (signs application) | UUID |

**Paths Section:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `bootloader_srec` | Path to MCUboot bootloader SREC | `prerequisites/bootloader.srec` |
| `application_bin` | Path to application binary | `prerequisites/application.bin` |
| `output_dir` | Output directory for generated files | `output` |

**Firmware Section:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `inject_customer_key` | Inject AWS KMS public key into bootloader | `true` |
| `mcuboot_pubkey_addr` | Address for key injection in bootloader | `0x02009114` |
| `app_offset` | Application start address in flash | `0x02010000` |

**Certificates Section:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `load_addr` | Bootloader load address | `0x02000000` |
| `oembl_size` | Bootloader region size (192KB) | `0x00030000` |
| `cfsize` | Code flash size filter | `0x200000` |

**Versioning Section:**

| Parameter | Description | Notes |
|-----------|-------------|-------|
| `certificate_version` | Anti-rollback version (1-64) | Increment for each production build |
| `app_version` | Application version string | Semantic versioning |

**Imgtool Section (MCUboot parameters):**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `align` | Flash alignment (Renesas RA8 specific) | `128` |
| `header_size` | MCUboot header size | `512` |
| `slot_size` | Application slot size | `131072` |
| `pad_header` | Pad header to header_size | `true` |
| `confirm` | Set image as confirmed | `true` |

---

### 1.5 Prerequisites Folder

Place the following files in the `prerequisites/` directory before running the workflow:

| File | Source | Description |
|------|--------|-------------|
| `bootloader.srec` | Your build system | Compiled MCUboot bootloader in SREC format |
| `application.bin` | Your build system | Application binary to sign |
| `keywrap-pub.key` | Renesas DLM | Public key for UFPK encryption (after registration) |

If you already have a W-UFPK, include the following in the `prerequisites/` directory:
- `ufpk.key`
- `ufpk_wrapped_decrypted.key`

Which will allow you to skip the wrapping phase via Renesas DLM.
---

## 2. Provisioning Tool Usage

### 2.1 Workflow Overview

The provisioning process is divided into two phases:

**Phase 1: One-Time Setup (per device type)**
```
invoke prepare-ufpk      Generate and wrap UFPK via Renesas DLM
invoke generate-rkey     Create RKEY (wrapped OEM Root Public Key)
```

**Phase 2: Firmware Build (per firmware version)**
```
invoke sign-app              Sign application with AWS KMS
invoke make-combined-srec    Combine bootloader + signed app
invoke gen-fsbl-certs        Generate FSBL certificates
invoke program-device        Flash to device
```

**Quick Start (Phase 2 combined):**
```
invoke workflow-all          Runs sign-app + make-combined-srec + gen-fsbl-certs
invoke program-device        Flash to device
```

---

### 2.2 One-Time Setup Commands

#### prepare-ufpk

Generates the User Factory Programming Key (UFPK) and processes it through Renesas DLM.

```bash
invoke prepare-ufpk
```

**What it does:**
1. Generates random 256-bit UFPK
2. Encrypts UFPK with Renesas public key
3. Opens browser for DLM upload
4. Waits for user to download wrapped UFPK from email
5. Decrypts wrapped UFPK with your PGP private key

**Prerequisites:**
- `prerequisites/keywrap-pub.key` (from Renesas after PGP registration)
- PGP key pair in GnuPG keyring

**Outputs:**
- `output/reuse_ufpk/ufpk.key` - Plain UFPK
- `output/reuse_ufpk/ufpk_wrapped_decrypted.key` - Wrapped UFPK from DLM

**When to run:**
Once per device type. The UFPK is reused for all devices.

---

#### generate-rkey

Creates the RKEY file (OEM Root Public Key wrapped with UFPK).

```bash
invoke generate-rkey
```

**What it does:**
1. Locates UFPK files (searches flow folders and reuse_ufpk/)
2. Exports OEM Root Public Key from AWS KMS
3. Wraps public key with UFPK using SKMT tool
4. Saves RKEY to reusable folder

**Prerequisites:**
- UFPK files from `prepare-ufpk`
- AWS KMS access configured
- `oem_root_key_id` in `project_config.json`

**Outputs:**
- `output/reuse_ufpk/oem_root_key.rkey` - Wrapped OEM Root Public Key

**When to run:**
Once per device type. The RKEY is reused for all firmware builds.

---

### 2.3 Firmware Build Commands

The firmware build commands must be executed in this order:

```
1. invoke sign-app
2. invoke make-combined-srec
3. invoke gen-fsbl-certs
```

This order is critical because each command depends on outputs from the previous command.

---

#### sign-app

Signs the application binary using AWS KMS in MCUboot format.

```bash
invoke sign-app
```

**What it does:**
1. Loads application binary from `project_config.json` path
2. Generates MCUboot header and TLV structure
3. Calculates SHA256 hash of protected region
4. Signs hash with AWS KMS (ECDSA P-256)
5. Injects signature into TLV
6. Pads to slot size and adds trailer

**Configuration used:**
- `aws.kms.mcuboot_app_key_id` - Signing key
- `imgtool.*` - MCUboot parameters
- `paths.application_bin` - Input binary

**Outputs:**
- `output/flow_*/application.bin.signed` - Signed MCUboot image
- `output/flow_*/customer_public.pem` - Signing public key

---

#### make-combined-srec

Injects the AWS KMS public key into the bootloader and creates combined SREC.

```bash
invoke make-combined-srec
```

**What it does:**
1. Converts `application.bin.signed` to SREC with correct offset
2. Injects AWS KMS `mcuboot_app_key` public key into bootloader at the specified injection address
3. Combines `bootloader_with_aws_key.srec` + `application_offset.srec`
4. Verifies no address overlaps

**Configuration used:**
- `paths.bootloader_srec` - Original bootloader
- `firmware.inject_customer_key` - Enable/disable key injection
- `firmware.mcuboot_pubkey_addr` - Key injection address
- `firmware.app_offset` - Application start address

**Outputs:**
- `output/flow_*/bootloader_with_aws_key.srec` - Bootloader with injected key
- `output/flow_*/application.bin_offset.srec` - Application at correct offset
- `output/flow_*/combined.srec` - Final combined SREC

**Important:**
This command creates `bootloader_with_aws_key.srec` which is required for correct CRC calculation in the next step.

---

#### gen-fsbl-certs

Generates Key Certificate and Code Certificate for Renesas FSBL.

```bash
invoke gen-fsbl-certs
```

**What it does:**
1. Exports OEM Root and OEM Bootloader public keys from AWS KMS
2. Generates Key Certificate (signed with OEM_ROOT_SK)
3. Generates Code Certificate (signed with OEM_BL_SK)
4. Calculates CRC32 on `bootloader_with_aws_key.srec` (auto-detected)
5. Verifies certificate chain (KEYHASH == SIGNER_ID)

**Configuration used:**
- `aws.kms.oem_root_key_id` - OEM Root Key
- `aws.kms.oem_bootloader_key_id` - OEM Bootloader Key
- `certificates.load_addr` - Bootloader load address
- `certificates.oembl_size` - Bootloader region size
- `versioning.certificate_version` - Anti-rollback version

**Outputs:**
- `output/flow_*/certs/oem_key_cert_vNN.bin` - Key Certificate
- `output/flow_*/certs/oem_code_cert_vNN.bin` - Code Certificate

**Important:**
The CRC is calculated on `bootloader_with_aws_key.srec`. Run `make-combined-srec` before this command.

---

### 2.4 Complete Workflow Command

#### workflow-all

Executes the complete firmware build workflow in correct order.

```bash
invoke workflow-all
```

**What it does:**
1. Runs `sign-app` - Signs application with AWS KMS
2. Runs `make-combined-srec` - Injects key and creates combined SREC
3. Runs `gen-fsbl-certs` - Generates certificates with correct CRC

**This is the recommended command for firmware builds.**

**Outputs:**
All outputs from the three individual commands:
- `application.bin.signed`
- `bootloader_with_aws_key.srec`
- `combined.srec`
- `certs/oem_key_cert_vNN.bin`
- `certs/oem_code_cert_vNN.bin`

---

### 2.5 Configuration Reference

#### Where Configuration is Read From

| Data Type | Source | Notes |
|-----------|--------|-------|
| AWS credentials | `.env` file or environment variables | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| AWS region | `project_config.json` > `aws.region` | Or `AWS_DEFAULT_REGION` env var |
| KMS Key IDs | `project_config.json` > `aws.kms.*` | UUID format |
| Bootloader path | `project_config.json` > `paths.bootloader_srec` | Relative to provisioning_tool/ |
| Application path | `project_config.json` > `paths.application_bin` | Relative to provisioning_tool/ |
| MCUboot params | `project_config.json` > `imgtool.*` | Must match bootloader build |
| Certificate params | `project_config.json` > `certificates.*` | Must match device memory map |

#### Validating Configuration

```bash
# Show loaded configuration
invoke sign-app --help

# The command will display configuration errors if any required field is missing
```

---

## 3. Device Programming

### 3.1 Hardware Setup

#### Required Hardware
- EK-RA8M1 evaluation board
- USB to micro-USB cable
- Power via USB or external power supply

#### Board Configuration
1. Connect USB cable to J11 (USB full speed)
2. Enable BOOT MODE (J16 closed)
3. Ensure no serial terminal applications are connected to the COM port
4. Board should be powered on

#### Finding the COM Port
The J-Link interface appears as a virtual COM port. To find it:

**Windows:**
1. Open Device Manager
2. Expand "Ports (COM & LPT)"
3. Look for "JLink CDC UART Port (COMx)"

**Command line:**
```bash
mode
```

---

### 3.2 Program Device Command

```bash
invoke program-device
```

**What it does:**
1. Locates all required files (RKEY, certificates, combined.srec)
2. Connects to device via Renesas Flash Programmer
3. Programs OEM Root Key
4. Programs Key and Code Certificates
5. Programs combined.srec (bootloader + application)

**File locations (auto-detected):**
- RKEY: `output/reuse_ufpk/oem_root_key.rkey` or `output/flow_*/oem_root_key.rkey`
- Key Cert: `output/flow_*/certs/oem_key_cert_vNN.bin`
- Code Cert: `output/flow_*/certs/oem_code_cert_vNN.bin`
- Combined SREC: `output/flow_*/combined.srec`

**Options:**
```bash
invoke program-device --com-port COM3    # Specify COM port
invoke program-device --lock-device      # Lock device after programming
```

---

### 3.3 Programming Procedure

#### Step-by-Step Process

1. **Prepare files:**
   ```bash
   invoke workflow-all
   ```
   Verify output files exist in `output/flow_*/`

2. **Connect device:**
   - Connect USB cable to USB Full Speed Port
   - Verify COM port in Device Manager

3. **Enter boot mode:**
   - Press and hold RESET button
   - Release RESET (device enters boot mode)

4. **Run programming:**
   ```bash
   invoke program-device
   ```

5. **Follow prompts:**
   - The tool will prompt for reset when needed
   - Follow the reset procedure exactly

6. **Verify success:**
   - Application LED should blink after programming
   - Check UART output for MCUboot messages

---

### 3.4 Reset Procedure

When the tool displays:
```
[WARN]  RESET REQUIRED!
   Please reset the board with MD low, then press Enter...
```

Perform these steps:
1. Press and hold the RESET button on the board
2. While holding RESET, ensure MD pin is LOW (default on EK-RA8M1)
3. Release RESET button
4. Press Enter in the terminal to continue

The device will re-enumerate on USB. The tool handles reconnection automatically.

---

## 4. Troubleshooting

### 4.1 Common Errors

#### RKEY Not Found

```
[ERROR] RKEY not found!

   To generate RKEY, run these commands:
     1. invoke prepare-ufpk
     2. invoke generate-rkey
```

**Cause:** UFPK has not been prepared or RKEY has not been generated.

**Solution:**
1. Run `invoke prepare-ufpk` (requires Renesas DLM registration)
2. Run `invoke generate-rkey`
3. Verify `output/reuse_ufpk/oem_root_key.rkey` exists

---

#### Certificate Not Found

```
[ERROR] Key Certificate not found!
```

**Cause:** Firmware build workflow has not been completed.

**Solution:**
Run the complete workflow:
```bash
invoke workflow-all
```

Verify certificates exist in `output/flow_*/certs/`

---

#### CRC Mismatch (Error AAAA0204)

```
Error(E1000001): An unknown error occurred in the device.
(Command: 26, Response: DB, Status: AAAA0204)
```

**Cause:** Code Certificate CRC was calculated on wrong bootloader binary. This happens when `gen-fsbl-certs` runs BEFORE `make-combined-srec`.

**Solution:**
Run commands in correct order:
```bash
invoke sign-app
invoke make-combined-srec
invoke gen-fsbl-certs
```

Or use the combined command which ensures correct order:
```bash
invoke workflow-all
```

---

#### Signature Verification Failed on Device

**Symptoms:** Device programs successfully but application does not run. MCUboot shows signature verification error.

**Cause:** Bootloader is verifying with wrong public key.

**Solution:**
1. Verify `inject_customer_key` is `true` in `project_config.json`
2. Re-run the complete workflow:
   ```bash
   invoke workflow-all
   invoke program-device
   ```
3. Verify the key injection address matches bootloader expectation (`0x02009114`)

---

#### AWS KMS Access Denied

```
[ERROR] AWS KMS access denied
```

**Cause:** AWS credentials invalid or missing KMS permissions.

**Solution:**
1. Check `.env` file contains valid credentials:
   ```
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   ```

2. Verify IAM user has required permissions:
   - `kms:Sign`
   - `kms:GetPublicKey`
   - `kms:DescribeKey`

3. Verify KMS key policy allows your IAM user

4. Test access:
   ```bash
   aws kms describe-key --key-id YOUR_KEY_ID
   ```

---

#### COM Port Access Denied

**Cause:** Another application has the COM port open.

**Solution:**
1. Close all serial terminal applications (PuTTY, TeraTerm, etc.)
2. Close Renesas Flash Programmer if open
3. Verify correct COM port in Device Manager
4. Try a different USB port
5. Restart the device

---

### 4.2 Verification Commands

#### Verify AWS Configuration

```bash
# List KMS keys
aws kms list-keys

# Test specific key access
aws kms get-public-key --key-id YOUR_KEY_ID

# Verify region
aws configure get region
```

#### Verify Generated Files

```bash
# List flow folder contents
dir output\flow_*

# Verify certificate sizes
dir output\flow_*\certs

# Expected sizes:
# - oem_key_cert_vNN.bin: 208 bytes
# - oem_code_cert_vNN.bin: 216 bytes
```

#### Verify Signed Application

The tool automatically verifies:
- SHA256 hash integrity
- Signature validity
- TLV structure

Look for these log messages:
```
[OK] SHA256 hash verified!
[OK] SIGNATURE IS VALID!
```

---

### 4.3 Debug Procedures

#### Enable Verbose Logging

The tool automatically logs to console. Look for:
- `[OK]` - Successful operation
- `[WARN]` - Warning (may continue)
- `[ERROR]` - Error (operation failed)

#### Check Certificate CRC

If you suspect CRC issues, verify the CRC source:
```
CRC Source: bootloader_with_aws_key.srec (auto-detected, WITH AWS KEY!)
```

If you see:
```
CRC Source: bootloader.srec (ORIGINAL - no AWS key!)
```

Then `make-combined-srec` was not run before `gen-fsbl-certs`. Re-run the workflow.

#### Verify Key Injection

Check the log during `make-combined-srec`:
```
Step 1.5: Inject AWS KMS public key into bootloader
[OK] Injected AWS KMS key at 0x02009114
```

If injection fails, verify:
- `firmware.inject_customer_key` is `true` in config
- `firmware.mcuboot_pubkey_addr` matches bootloader expectation
- AWS KMS key is accessible

#### Workflow Order Verification

The firmware build commands MUST be executed in this order:

| Order | Command | Creates |
|-------|---------|---------|
| 1 | `sign-app` | `application.bin.signed` |
| 2 | `make-combined-srec` | `bootloader_with_aws_key.srec`, `combined.srec` |
| 3 | `gen-fsbl-certs` | `oem_key_cert_vNN.bin`, `oem_code_cert_vNN.bin` |
| 4 | `program-device` | Programs device |

Use `invoke workflow-all` to ensure correct order for steps 1-3.

---

## CLI Help

For interactive help, run:
```bash
invoke cli-help
```

For specific sections:
```bash
invoke cli-help --section flow           # Workflow overview
invoke cli-help --section commands       # All commands
invoke cli-help --section files          # File reference
invoke cli-help --section troubleshooting # Common issues
```

For command-specific help:
```bash
invoke sign-app --help
invoke make-combined-srec --help
invoke gen-fsbl-certs --help
invoke program-device --help
```

---

## 5. API Documentation

This project includes comprehensive API documentation generated from source code docstrings using Sphinx.

### 5.1 Generating Documentation

#### Prerequisites

Install documentation tools (one-time setup):

```bash
pip install sphinx sphinx-rtd-theme pylint
```

#### Method 1: Using Invoke Task

```bash
# Generate HTML documentation only
invoke generate-docs

# Generate documentation with class diagrams
invoke generate-docs --diagrams
```

#### Method 2: Using Sphinx Directly

```bash
# Navigate to docs folder
cd docs

# Build HTML documentation
python -m sphinx -b html . _build/html

# On Windows with make.bat
make.bat html
```

#### Method 3: Using Batch Script

```bash
# Run from provisioning_tool folder
docs\generate_docs.bat
```

### 5.2 Documentation Structure

After generation, documentation is located in `docs/_build/html/`:

```
docs/
  _build/
    html/
      index.html              # Main page (open this)
      architecture.html       # System architecture overview
      modules/
        cli.html              # CLI commands documentation
        device.html           # Device programming module
        firmware.html         # Firmware signing module
        security.html         # Security operations (HSM, SKMT)
        utils.html            # Utility functions
        models.html           # Data models
        config.html           # Configuration module
      _modules/               # Source code with syntax highlighting
      genindex.html           # General index
      search.html             # Search page
  diagrams/                   # Class diagrams (if generated)
    classes_ProvisioningTool.dot
    packages_ProvisioningTool.dot
```

#### Viewing Documentation

```bash
# Windows - open in default browser
start docs\_build\html\index.html
```

### 5.3 Class Diagrams

Class diagrams are generated using `pyreverse` (part of pylint). Output format is DOT (Graphviz).

#### Generating Diagrams

```bash
# Generate DOT files
python -m pylint.pyreverse.main -o dot -p ProvisioningTool cli device firmware security utils models config -d docs\diagrams
```

#### Converting to PNG (requires Graphviz)

1. Install Graphviz: https://graphviz.org/download/
2. Add Graphviz to PATH
3. Convert:

```bash
dot -Tpng docs\diagrams\classes_ProvisioningTool.dot -o docs\diagrams\classes.png
dot -Tpng docs\diagrams\packages_ProvisioningTool.dot -o docs\diagrams\packages.png
```

#### Online DOT Viewer

If Graphviz is not installed, view DOT files online:
- https://dreampuf.github.io/GraphvizOnline/
- https://edotor.net/
