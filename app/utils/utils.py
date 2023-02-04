# -*- coding:utf-8 -*-

from pathlib import Path
from enum import Enum

def get_project_root() -> Path:
    return Path(__file__).parent

base_directory = get_project_root()

class Arch(Enum):
    Any = ""
    x86 = "x86"
    x64 = "x64"

    @staticmethod
    def from_string(label:str):
        if label.lower() in ["any", "all", "arch.all"]:
            return Arch.Any
        elif label.lower() in ["32", "86", "x86", "i386", "arch.x86"]:
            return Arch.x86
        elif label.lower() in ["64", "x64", "amd64", "x86_64", "arch.x64"]:
            return Arch.x64


class Compiler(Enum):
    All = ""
    MSVC = "MSVC"
    MINGW = "MinGW"

    @staticmethod
    def from_string(label:str):
        if label.lower() in ["all", "compiler.all"]:
            return Compiler.All
        elif label.lower() in ["msvc", "compiler.msvc"]:
            return Compiler.MSVC
        elif label.lower() in ["mingw", "compiler.mingw"]:
            return Compiler.MINGW


# Define SyscallRecoveryType
class SyscallRecoveryType(Enum):
    EMBEDDED = 0
    EGG_HUNTER = 1
    JUMPER = 2
    JUMPER_RANDOMIZED = 3

    @classmethod
    def from_name_or_default(cls, name):
        _types = dict(map(lambda c: (c.name.lower(), c.value), SyscallRecoveryType))
        return SyscallRecoveryType(_types[name]) if name in _types.keys() else SyscallRecoveryType.EMBEDDED

    @classmethod
    def get_name(cls, value):
        if isinstance(value, str):
            value = int(value)
        _types = dict(map(lambda c: (c.value, c.name.lower()), cls))
        return _types[value] if value in _types.keys() else None

    @classmethod
    def from_name(cls, name):
        _types = dict(map(lambda c: (c.name.lower(), c.value), cls))
        return _types[name] if name in _types.keys() else None

    @classmethod
    def value_list(cls):
        return list(map(lambda c: c.value, cls))

    @classmethod
    def key_list(cls):
        return list(map(lambda c: c.name.lower(), cls))