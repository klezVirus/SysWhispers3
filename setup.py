#!/usr/bin/env python3
# -*- coding:utf8 -*-

from setuptools import setup, find_packages
from setuptools.command import easy_install
from setuptools.command.install import install

import re, subprocess

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
    url="https://www.prohacktive.io",
    license="Proprietary",
    classifiers=["License :: Other/Proprietary License"],
    author=metadata["author"],
    author_email=metadata["authoremail"],
    version=metadata["version"],
    packages=find_packages(),
    install_requires=requirements,
)