#!/usr/bin/env python3
"""
Setup script for HakCheck.
"""

from setuptools import setup, find_packages

# Read requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Read the long description from README.md
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="hakcheck",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A utility for safely detecting malicious USB devices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/hak_check",
    packages=find_packages(),
    package_data={
        "": ["*.md"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Hardware :: Hardware Drivers",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "hakcheck=src.main:main",
        ],
    },
)