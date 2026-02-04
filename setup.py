"""
Setup script for RA8M1 Provisioning Tool.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README if exists
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="ra8m1-provisioning-tool",
    version="1.0.0",
    description="RA8M1 Secure Boot Provisioning Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Crypto Quantique",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "boto3>=1.26.0",
        "cryptography>=3.4.8",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "imgtool>=1.10.0",
        "pyserial>=3.5",
        "invoke>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "workflow=cli.commands.workflow:workflow_main",
            "provisioning-tool=cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)

