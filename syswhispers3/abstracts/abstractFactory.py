# -*- coding:utf-8 -*-

import string
import random
import logging

from abc import ABC
from syswhispers3.utils.loggerSingleton import LoggerSingleton

class AbstractFactory(ABC):
    """Public factory class handling standard methods used by child instances
    """
    def __init__(self, log_level:int=logging.INFO) -> None:
        super().__init__()

        # Share logger for all childs
        self.logger = LoggerSingleton(log_level)

    def __generate_random_string(self, length:int, choices:list=string.ascii_letters) -> str:
        """Private method used to generate a random string

        Args:
            length (int): The random string length to generate
            choices (list, optional): The chars sapce to used for generation. Defaults to string.ascii_letters.

        Returns:
            str: The generated random string
        """
        return ''.join(random.choice(choices) for _ in range(length))

    def generate_random_syscall(self, length:int) -> str:
        """Public method used to generate random syscall of specific length

        Args:
            length (int): The length of random syscall string to generate

        Returns:
            str: The generated random string
        """
        return self.__generate_random_string(length)
    
    def generate_key(self, lenght:int) -> str:
        """Public method used to generate random alphanumeric key of specific length

        Args:
            length (int): The length of key string to generate

        Returns:
            str: The generated random key
        """
        return self.__generate_random_string(lenght, choices=string.ascii_letters + string.digits)

    def generate_random_seed(self) -> int:
        """Public method used to generate a random int used as seed
        Range from: 2^28 to (2^32 - 1)

        Returns:
            int: The generated random seed
        """
        return random.randint(2 ** 28, 2 ** 32 - 1)
    
    def generate_random_egg(self) -> list:
        """Public method used to generate a random EGG to use with EGG_HUNTER method

        Returns:
            list: A formatted list of hex code to use for EGG
        """
        return [hex(ord(random.choices(string.ascii_lowercase, k=1)[0])), "0x0", "0x0", hex(ord(random.choices(string.ascii_lowercase, k=1)[0]))]
