# RA8M1 Provisioning Tool

A secure provisioning solution for Renesas RA8M1 microcontrollers with MCUboot secure boot. This tool provides end-to-end automation for device provisioning including key management via AWS KMS (through a PKCS#11 Crypto Broker for credential isolation), certificate generation, firmware signing, and direct serial/USB device programming.

---

## System Architecture

```
+==============================================================================+
|                              PROVISIONING WORKFLOW                            |
+==============================================================================+

    +------------------+         +------------------+         +------------------+
    |   AWS KMS        |         |   PREREQUISITES  |         |   OUTPUT         |
    |  (via PKCS#11    |         |------------------|         |------------------|
    |   Crypto Broker) |         | - bootloader.srec|         | - combined.srec  |
    |------------------|         | - application.bin|         | - key_cert.bin   |
    | - OEM Root SK    |         | - project_config |         | - code_cert.bin  |
    | - OEM BL SK      |         +--------+---------+         +--------+---------+
    | - Customer SK    |                  |                            ^
    +--------+---------+                  |                            |
             |                            v                            |
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

4. [PKCS#11 Crypto Broker](#4-pkcs11-crypto-broker)
   - [Architecture](#41-architecture)
   - [Broker Commands](#42-broker-commands)
   - [Windows Service](#43-windows-service)

5. [Troubleshooting](#5-troubleshooting)
   - [Common Errors](#51-common-errors)
   - [Verification Commands](#52-verification-commands)
   - [Debug Procedures](#53-debug-procedures)

6. [API Documentation](#6-api-documentation)
   - [Generating Documentation](#61-generating-documentation)
   - [Documentation Structure](#62-documentation-structure)
   - [Class Diagrams](#63-class-diagrams)

---

## 1. Project Setup and Configuration

### 1.1 System Requirements

#### Operating System
- Windows 10/11 (64-bit) - Primary supported platform
- Linux support available (all operations use native Python)

#### Hardware
- Renesas EK-RA8M1 evaluation board (or compatible RA8M1 device)
- J-Link debugger (integrated on EK-RA8M1)
- USB cable for power and debug connection

#### Software Prerequisites
- Python 3.10 or later
- AWS CLI v2
- GnuPG 2.4 or later (Gpg4win recommended)

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
pip install -e .
```

This installs the project and its dependencies (see `pyproject.toml`), including:
- `click` - Command-line interface framework
- `invoke` - Task execution framework
- `boto3` - AWS SDK for Python
- `cryptography` - Cryptographic operations
- `pyserial` - Serial communication

#### Step 4: Install External Tools

**GnuPG (Gpg4win):**
1. Download from https://gnupg.org/download/
2. Install with default settings
3. Verify: `gpg --version`

**AWS CLI:**
1. Download from https://aws.amazon.com/cli/
2. Install MSI package
3. Verify: `aws --version`

#### Step 5: Verify Installation

```bash
invoke --list
```

You should see all available commands listed.

---

### 1.3 AWS Configuration

The provisioning tool uses AWS Key Management Service (KMS) for secure key storage and signing operations, accessed through the **PKCS#11 Crypto Broker** - a local security daemon that provides credential isolation. Private keys never leave the AWS HSM.

> **PKCS#11 Crypto Broker:** AWS credentials are stored only in the broker daemon process, never in the provisioning tool itself. The broker auto-starts when cryptographic operations are requested. Communication uses Named Pipes (Windows) or Unix Sockets (Linux) with JSON-RPC 2.0 protocol.

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

#### 1.3.2 Configure AWS Credentials

AWS credentials are loaded by the PKCS#11 Crypto Broker in this priority order:

1. **`project_config.json`** (recommended) - `aws.access_key_id` and `aws.secret_access_key` fields
2. **Environment variables** - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
3. **AWS CLI default profile** - configured via `aws configure`

**Option A: In project_config.json (recommended):**
```json
{
  "aws": {
    "access_key_id": "AKIAXXXXXXXXXXXXXXXX",
    "secret_access_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "region": "eu-west-2",
    "hsm_type": "broker"
  }
}
```

**Option B: Environment variables:**
```bash
set AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
set AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
set AWS_DEFAULT_REGION=eu-west-2
```

**Option C: AWS CLI configuration:**
```bash
aws configure
```

> **Security Note:** The Crypto Broker isolates credentials from the provisioning tool process. AWS access keys exist only in the broker daemon memory.

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
  "project": {
    "name": "Renesas RA8M1 Secure Boot Provisioning",
    "version": "1.2.0"
  },
  
  "aws": {
    "access_key_id": "",
    "secret_access_key": "",
    "region": "",
    "hsm_type": "broker",
    "kms": {
      "oem_root_key_id": "",
      "oem_bootloader_key_id": "",
      "mcuboot_app_key_id": ""
    }
  },
  
  "paths": {
    "bootloader_srec": "prerequisites/mcuboot_ra8m1.srec",
    "application_bin": "prerequisites/app_ra8m1.bin",
    "output_dir": "output"
  },
  
  "firmware": {
    "app_offset": "0x2010000",
    "mcuboot_pubkey_addr": "0x02009114",
    "inject_customer_key": true
  },
  
  "imgtool": {
    "header_size": "0x200",
    "align": 128,
    "max_align": 128,
    "slot_size": "0x20000",
    "max_sectors": 4,
    "version": "1.0.0",
    "pad_header": true,
    "pad": true,
    "confirm": true
  },
  
  "certificates": {
    "load_addr": "0x02000000",
    "dest_addr": "0x02000000",
    "cfsize": "0x200000",
    "oembl_size": "0x00030000",
    "mode": "signature",
    "version": 0,
    "build_number": 0,
    "application_version": "1.0.0",
    
    "key_certificate": {
      "magic": "0x6B657963",
      "manifest_version": "0x00010000",
      "flags": "0x00000000",
      "tlv_ecc_pubkey_type_length": "0x00088010",
      "tlv_keyhash_type_length": "0x10144008",
      "tlv_expected_sig_type_length": "0x20088410"
    },
    
    "code_certificate": {
      "magic": "0x636F6463",
      "manifest_version": "0x00010000",
      "flags": "0x00000000",
      "tlv_ecc_pubkey_type_length": "0x01088010",
      "tlv_expected_crc_type_length": "0x40000001",
      "tlv_signer_id_type_length": "0x10144008",
      "tlv_expected_sig_type_length": "0x25088410"
    }
  }
}
```

#### 1.4.3 Configuration Parameters Explained

**AWS Section:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `region` | AWS region where KMS keys are located (default: `config.settings.DEFAULT_AWS_REGION`) | e.g. `eu-west-2` |
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
2. Exports OEM Root Public Key from AWS KMS (via PKCS#11 Crypto Broker)
3. Wraps public key with UFPK
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
| AWS credentials | `project_config.json` > `aws.*` or environment variables | Loaded by PKCS#11 Crypto Broker |
| AWS region | `project_config.json` > `aws.region` | Or `AWS_DEFAULT_REGION` env var |
| HSM type | `project_config.json` > `aws.hsm_type` | `broker` (recommended) or `aws_kms` (direct) |
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
2. Connects to device via direct serial/USB communication with boot firmware
3. Programs OEM Root Key (RKEY)
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

## 4. PKCS#11 Crypto Broker

The PKCS#11 Crypto Broker is a security daemon that provides **credential isolation** between the provisioning tool and AWS KMS.

### 4.1 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Provisioning Tool                      │
│                                                          │
│   sign-app / gen-fsbl-certs / make-combined-srec        │
│              │                                           │
│              ▼                                           │
│   ┌──────────────────────┐                              │
│   │  BrokerHSMClient     │  (PKCS#11 interface)        │
│   └──────────┬───────────┘                              │
│              │ Named Pipe (Windows)                      │
│              │ Unix Socket (Linux)                       │
│              ▼                                           │
│   ┌──────────────────────┐                              │
│   │  Crypto Broker       │  (Daemon process)            │
│   │  - Holds AWS creds   │                              │
│   │  - JSON-RPC 2.0      │                              │
│   │  - Auto-starts       │                              │
│   └──────────┬───────────┘                              │
│              │ boto3 (AWS SDK)                           │
└──────────────┼──────────────────────────────────────────┘
               ▼
        ┌──────────────┐
        │   AWS KMS    │
        │  (HSM-backed │
        │   signing)   │
        └──────────────┘
```

**Key Benefits:**
- AWS credentials never exposed to provisioning tool process
- OS-level authentication (Windows SID / Linux UID)
- Auto-starts when cryptographic operations are requested
- Can run as a Windows Service for headless environments

### 4.2 Broker Commands

```bash
# Start broker in foreground (for development)
invoke broker-start

# Start broker as background daemon
invoke broker-start --daemon

# Check broker status
invoke broker-status

# Stop broker
invoke broker-stop

# Initialize broker policies
invoke broker-init-policies
```

### 4.3 Windows Service

For production or headless environments, the broker can run as a Windows Service:

```bash
# Install Windows Service
scripts\install_broker_service.bat

# Start in foreground for testing
scripts\start_broker_foreground.bat

# Uninstall service
scripts\uninstall_broker_service.bat
```

The Windows Service loads AWS credentials from:
1. `broker_config.json` (if present)
2. `project_config.json`
3. System-wide environment variables
4. AWS CLI default profile

> **Configuration:** Set `"hsm_type": "broker"` in `project_config.json` to use the Crypto Broker (this is the default and recommended setting).

---

## 5. Troubleshooting

### 5.1 Common Errors

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

**Cause:** AWS credentials invalid or missing KMS permissions, or Crypto Broker cannot access credentials.

**Solution:**
1. Check `project_config.json` contains valid credentials:
   ```json
   "aws": {
     "access_key_id": "AKIA...",
     "secret_access_key": "..."
   }
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
2. Close any other applications using the COM port
3. Verify correct COM port in Device Manager
4. Try a different USB port
5. Restart the device

---

### 5.2 Verification Commands

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

### 5.3 Debug Procedures

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