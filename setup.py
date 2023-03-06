#!/usr/bin/env python3
# -*- coding:utf8 -*-

from setuptools import setup, find_packages
from setuptools.command import easy_install
from setuptools.command.install import install

import re

MRE = r"__([a-z]+)__\s*=\s*['\"]([^'\"]*)['\"]"

# Retrieve all metadata from project
with open("__metadata.py", "rt") as meta_file:
    metadata = dict(re.findall(MRE, meta_file.read()))
    meta_file.close()

# Get required packages from requirements.txt
# Make it compatible with setuptools and pip
with open("requirements.txt", "rt") as f:
    requirements = f.read().splitlines()

setup(
    name="syswhispers3",
    description="SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls",
    url="https://github.com/x42en/SysWhispers3",
    license="Apache License 2.0",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Software Development :: Code Generators",
    ],
    author=metadata["author"],
    author_email=metadata["authoremail"],
    version=metadata["version"],
    packages=find_packages(),
    install_requires=requirements,
    package_data={
        metadata["name"]: ["data/*.json", "data/*.asm", "data/*.c", "data/*.h"]
    },
)