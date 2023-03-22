# -*- coding: utf-8 -*-

import os
import re
import json
import unittest

import unittest

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from syswhispers3 import data as pkg_data

FIXTURES_PATH = os.path.join('tests','fixtures')

class CodeUtil(unittest.TestCase):
    def __init__(self, method_name):
        super().__init__(method_name)
        self.maxDiff = None
        self.prototypes:dict = json.load(pkg_resources.open_text(pkg_data, "prototypes.json"))
    
    def _load_fixture(self, name: str) -> str:
        # Open fixture
        with open(os.path.join(FIXTURES_PATH, name), 'r') as f:
            raw = f.read()
        return raw
    
    def _remove_function_hash(self, opcodes:str) -> str:
        p = re.compile(r'(0|0x)?[0-9A-F]{8}h?')
        return re.sub(p, '', opcodes)
    
    def _remove_egg(self, opcodes:str, compiler:str) -> str:
        if compiler == 'mingw':
            p = re.compile(r'0x[0-9a-f]{1,2}')
        else:
            p = re.compile(r'[0-9a-f]{1,2}h')
        return re.sub(p, '', opcodes)
        
    def _remove_seed(self, opcodes:str) -> str:
        p = re.compile(r'SW3_SEED (0|0x)?[0-9A-F]{8}h?')
        return re.sub(p, '', opcodes)