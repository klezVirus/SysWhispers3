# -*- coding: utf-8 -*-

from tests.codeUtil import CodeUtil
from syswhispers3.utils import Arch
from syswhispers3.syscallsGenerator import SyscallsGenerator

class TestHCode(CodeUtil):
    def __init__(self, method_name):
        super().__init__(method_name)
    
    def test_00_generate_msvc_embedded(self):
        engine = SyscallsGenerator()
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('embedded.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_01_generate_mingw_embedded(self):
        engine = SyscallsGenerator(compiler='mingw')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('embedded.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_02_generate_msvc_jumper(self):
        engine = SyscallsGenerator(recovery='jumper')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('jumper.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_03_generate_mingw_jumper(self):
        engine = SyscallsGenerator(compiler='mingw',recovery='jumper')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('jumper.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_02_generate_msvc_jumper_randomized(self):
        engine = SyscallsGenerator(recovery='jumper_randomized')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('jumper_randomized.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_03_generate_mingw_jumper_randomized(self):
        engine = SyscallsGenerator(compiler='mingw',recovery='jumper_randomized')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('jumper_randomized.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_02_generate_msvc_egg_hunter(self):
        engine = SyscallsGenerator(recovery='egg_hunter')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('egg_hunter.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)
    
    def test_03_generate_mingw_egg_hunter(self):
        engine = SyscallsGenerator(compiler='mingw',recovery='egg_hunter')
        key_set = list(self.prototypes.keys())[0:3]
        result = engine.generate_h_code(key_set)

        raw = self._load_fixture('egg_hunter.h')
        fixture = self._remove_seed(raw)
        result = self._remove_seed(result)

        self.assertEqual(type(result), str)
        self.assertEqual(result, fixture)