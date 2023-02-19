# -*- coding:utf-8 -*-

import string
import random
import logging

from abc import ABC
from syswhispers3.utils.loggerSingleton import LoggerSingleton

class AbstractFactory(ABC):
    def __init__(self, log_level:int=logging.INFO) -> None:
        super().__init__()

        # Share logger for all childs
        self.logger = LoggerSingleton(log_level)

    def __generate_random_string(self, length:int, choices:list=string.ascii_letters) -> str:
        return ''.join(random.choice(choices) for _ in range(length))

    def generate_random_syscall(self, length:int) -> str:
        return self.__generate_random_string(length)
    
    def generate_key(self, lenght:int) -> str:
        return self.__generate_random_string(lenght, choices=string.ascii_letters + string.digits)

    def generate_random_seed(self) -> int:
        return random.randint(2 ** 28, 2 ** 32 - 1)
    
    def generate_random_egg(self) -> list:
        return [hex(ord(random.choices(string.ascii_lowercase, k=1)[0])), "0x0", "0x0", hex(ord(random.choices(string.ascii_lowercase, k=1)[0]))]
