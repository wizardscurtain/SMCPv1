#!/usr/bin/env python3
"""Setup script for smcp-security PyPI package"""

import os
import sys
from pathlib import Path

# Add the SMCPv1/code directory to Python path
code_dir = Path(__file__).parent.parent.parent / "SMCPv1" / "code"
sys.path.insert(0, str(code_dir))

from setuptools import setup, find_packages

# Read version from package
try:
    from smcp_security import __version__
except ImportError:
    __version__ = "1.0.0"

# Read README
readme_path = Path(__file__).parent / "README.md"
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "Secure Model Context Protocol (SMCP) v1 - Comprehensive Security Framework"

# Read requirements
requirements_path = code_dir / "requirements.txt"
with open(requirements_path, "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Development requirements
dev_requirements_path = code_dir / "requirements-dev.txt"
with open(dev_requirements_path, "r", encoding="utf-8") as f:
    dev_requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="smcp-security",
    version=__version__,
    author="SMCP Security Team",
    author_email="security@smcp-framework.org",
    description="Secure Model Context Protocol (SMCP) v1 - Comprehensive Security Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wizardscurtain/SMCPv1",
    project_urls={
        "Bug Reports": "https://github.com/wizardscurtain/SMCPv1/issues",
        "Source": "https://github.com/wizardscurtain/SMCPv1",
        "Documentation": "https://smcp-security.dev",
        "Funding": "https://github.com/sponsors/wizardscurtain",
    },
    packages=find_packages(where=str(code_dir)),
    package_dir={"": str(code_dir)},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Framework :: FastAPI",
        "Framework :: AsyncIO",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "ml": [
            "transformers>=4.35.0",
            "torch>=2.1.0",
        ],
        "all": [
            "transformers>=4.35.0",
            "torch>=2.1.0",
        ] + dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "smcp-security=smcp_security.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "smcp_security": [
            "data/*.json",
            "templates/*.html",
            "static/*",
        ],
    },
    zip_safe=False,
    keywords=[
        "security", "mcp", "ai", "protocol", "authentication", 
        "authorization", "middleware", "framework", "cybersecurity",
        "model-context-protocol", "ai-security", "threat-detection"
    ],
)
