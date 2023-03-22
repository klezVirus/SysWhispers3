# -*- coding: utf-8 -*-

from tests.codeUtil import CodeUtil
from syswhispers3.utils import Arch
from syswhispers3.syscallsGenerator import SyscallsGenerator

class TestASMCodeEmbedded(CodeUtil):
    def __init__(self, method_name):
        super().__init__(method_name)
        
    def test_00_generate_asm_msvc_x64(self):
        engine = SyscallsGenerator()
        first_key = list(self.prototypes.keys())[0]
        result = engine.generate_asm([first_key], Arch.x64)

        raw = self._load_fixture('embedded_msvc_x64.asm')
        fixture = self._remove_function_hash(raw)
        result = self._remove_function_hash(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_01_generate_asm_msvc_x86(self):
        engine = SyscallsGenerator()
        first_key = list(self.prototypes.keys())[0]
        result = engine.generate_asm([first_key], Arch.x86)

        raw = self._load_fixture('embedded_msvc_x86.asm')
        fixture = self._remove_function_hash(raw)
        result = self._remove_function_hash(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_02_generate_asm_mingw_x64(self):
        engine = SyscallsGenerator(compiler='mingw')
        first_key = list(self.prototypes.keys())[0]
        result = engine.generate_asm([first_key], Arch.x64)

        raw = self._load_fixture('embedded_mingw_x64.asm')
        fixture = self._remove_function_hash(raw)
        result = self._remove_function_hash(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_03_generate_asm_mingw_x86(self):
        engine = SyscallsGenerator(compiler='mingw')
        first_key = list(self.prototypes.keys())[0]
        result = engine.generate_asm([first_key], Arch.x86)

        raw = self._load_fixture('embedded_mingw_x86.asm')
        fixture = self._remove_function_hash(raw)
        result = self._remove_function_hash(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)