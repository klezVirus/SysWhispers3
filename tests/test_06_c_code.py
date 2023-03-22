# -*- coding: utf-8 -*-

from tests.codeUtil import CodeUtil
from syswhispers3.syscallsGenerator import SyscallsGenerator

class TestCCode(CodeUtil):
    def __init__(self, method_name):
        super().__init__(method_name)
        
    def test_00_generate_msvc_embedded(self):
        engine = SyscallsGenerator()
        result = engine.generate_c_code()

        fixture = self._load_fixture('embedded_msvc.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_01_generate_mingw_embedded(self):
        engine = SyscallsGenerator(compiler='mingw')
        result = engine.generate_c_code()

        fixture = self._load_fixture('embedded_mingw.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_02_generate_msvc_jumper(self):
        engine = SyscallsGenerator()
        result = engine.generate_c_code()

        fixture = self._load_fixture('jumper_msvc.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_03_generate_mingw_jumper(self):
        engine = SyscallsGenerator(compiler='mingw')
        result = engine.generate_c_code()

        fixture = self._load_fixture('jumper_mingw.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_04_generate_msvc_jumper_randomized(self):
        engine = SyscallsGenerator()
        result = engine.generate_c_code()

        fixture = self._load_fixture('jumper_randomized_msvc.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_05_generate_mingw_jumper_randomized(self):
        engine = SyscallsGenerator(compiler='mingw')
        result = engine.generate_c_code()

        fixture = self._load_fixture('jumper_randomized_mingw.c')

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    