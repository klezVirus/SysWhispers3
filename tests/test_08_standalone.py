# -*- coding: utf-8 -*-

import pytest
from tests.codeUtil import CodeUtil
from syswhispers3.utils import Arch
from syswhispers3.syscallsGenerator import SyscallsGenerator

OUTPUT_FILE = 'syscalls.h'

class TestStandAlone(CodeUtil):
    def __init__(self, method_name):
        super().__init__(method_name)
    
    def test_00_generate_msvc_embedded(self):
        engine = SyscallsGenerator()
        key_set = list(self.prototypes.keys())[0:3]
        with pytest.raises(Exception) as exc_info:
            engine.generate(key_set, standalone=True)
        self.assertEqual(type(exc_info.value), NotImplementedError)

    def test_01_generate_mingw_embedded(self):
        engine = SyscallsGenerator(compiler='mingw')
        key_set = list(self.prototypes.keys())[0:3]
        engine.generate(key_set, standalone=True)

        raw = self._load_fixture('standalone_mingw_default.h')
        fixture = self._remove_seed(raw)
        fixture = self._remove_function_hash(fixture)

        with open(OUTPUT_FILE, 'r') as f:
            result = self._remove_seed(f.read())
            result = self._remove_function_hash(result)

            self.assertEqual(result, fixture)
    
    def test_02_generate_mingw_embedded_jumper(self):
        engine = SyscallsGenerator(recovery="jumper", compiler='mingw')
        key_set = list(self.prototypes.keys())[0:3]
        engine.generate(key_set, standalone=True)

        raw = self._load_fixture('standalone_mingw_jumper.h')
        fixture = self._remove_seed(raw)
        fixture = self._remove_function_hash(fixture)

        with open(OUTPUT_FILE, 'r') as f:
            result = self._remove_seed(f.read())
            result = self._remove_function_hash(result)

            self.assertEqual(result, fixture)
    
    def test_03_generate_mingw_embedded_jumper_randomized(self):
        engine = SyscallsGenerator(recovery="jumper_randomized", compiler='mingw')
        key_set = list(self.prototypes.keys())[0:3]
        engine.generate(key_set, standalone=True)

        raw = self._load_fixture('standalone_mingw_jumper_randomized.h')
        fixture = self._remove_seed(raw)
        fixture = self._remove_function_hash(fixture)

        with open(OUTPUT_FILE, 'r') as f:
            result = self._remove_seed(f.read())
            result = self._remove_function_hash(result)

            self.assertEqual(result, fixture)
    