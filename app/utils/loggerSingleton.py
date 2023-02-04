# -*- coding:utf-8 -*-

import logging

from app.utils.singleton import Singleton

class LoggerSingleton(metaclass=Singleton):
    def __init__(self, log_level:int=logging.INFO) -> None:
        self.log_level = log_level
    
    def __output(self, message:str, level:int) -> None:
        if level >= self.log_level:
            print(f"{message}")
    
    def debug(self, message:str, stripped:bool=False) -> None:
        start = '[*] ' if not stripped else ''
        self.__output(f"{start}{message}", logging.DEBUG)
    
    def info(self, message:str, stripped:bool=False) -> None:
        start = '[+] ' if not stripped else ''
        self.__output(f"{start}{message}", logging.INFO)
    
    def warning(self, message:str, stripped:bool=False) -> None:
        start = '[!] ' if not stripped else ''
        self.__output(f"{start}{message}", logging.WARNING)
    
    def error(self, message:str, stripped:bool=False) -> None:
        start = '[!] ' if not stripped else ''
        self.__output(f"{start}{message}", logging.ERROR)
    
    def critical(self, message:str, stripped:bool=False) -> None:
        start = '[!!] ' if not stripped else ''
        self.__output(f"{start}{message}", logging.CRITICAL)
    
    def output(self, message:str) -> None:
        # Avoid any output on quiet mode
        if self.log_level <= logging.CRITICAL:
            print(message)

    def is_debug(self):
        return self.log_level <= logging.DEBUG
    
    def is_verbose(self):
        return self.log_level <= logging.INFO