# -*- coding: utf-8 -*-

import json
import unittest

from syswhispers3.abstracts.abstractFactory import AbstractFactory
from syswhispers3.constants.sysWhispersConstants import SysWhispersConstants

class TestAbstract(unittest.TestCase):
    def __init__(self, method_name):
        super().__init__(method_name)

        self.data = dict({"name": None})

    def test_00_init(self):
        AbstractFactory()

    def test_01_generate_random_syscall(self):
        check = AbstractFactory()
        result = check.generate_random_syscall(SysWhispersConstants.SYSWHISPERS_KEY_LEN)
        self.assertEqual(type(result), str)
        self.assertEqual(len(result),SysWhispersConstants.SYSWHISPERS_KEY_LEN)
    
    def test_02_generate_key(self):
        check = AbstractFactory()
        result = check.generate_key(SysWhispersConstants.SYSWHISPERS_KEY_LEN)
        self.assertEqual(type(result), str)
        self.assertEqual(len(result),SysWhispersConstants.SYSWHISPERS_KEY_LEN)
    
    def test_03_generate_random_seed(self):
        check = AbstractFactory()
        result = check.generate_random_seed()
        self.assertEqual(type(result), int)
        self.assertIn(result, range((2 ** 28), (2 ** 32 - 1)))
    
    def test_04_generate_random_egg(self):
        check = AbstractFactory()
        result = check.generate_random_egg()
        self.assertEqual(type(result), list)
        self.assertEqual(len(result), 4)
        for egg in result:
            self.assertEqual(type(egg), str)
