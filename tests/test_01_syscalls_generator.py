# -*- coding: utf-8 -*-

import json
import unittest

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources

from syswhispers3 import data as pkg_data
from syswhispers3.syscallsGenerator import SyscallsGenerator
from syswhispers3.constants.sysWhispersConstants import SysWhispersConstants

class TestSyscallsGenerator(unittest.TestCase):
    def __init__(self, method_name):
        super().__init__(method_name)
        self.maxDiff = None
        self.__prototypes:dict = json.load(pkg_resources.open_text(pkg_data, "prototypes.json"))
    
    def test_00_init(self):
        SyscallsGenerator()
    
    def test_01_list_supported_functions(self):
        engine = SyscallsGenerator()
        result = engine.list_supported_functions()
        self.assertEqual(type(result), list)
        self.assertEqual(len(result), len(list(self.__prototypes.keys())))

        for name, _ in self.__prototypes.items():
            self.assertIn(name, result)
    
    def test_02_list_donut_functions(self):
        engine = SyscallsGenerator()
        result = engine.list_donut_functions()
        self.assertEqual(type(result), list)
        self.assertEqual(len(result), len(SysWhispersConstants.DONUT_SYSCALLS))
        
        for name in SysWhispersConstants.DONUT_SYSCALLS:
            self.assertIn(name, result)
