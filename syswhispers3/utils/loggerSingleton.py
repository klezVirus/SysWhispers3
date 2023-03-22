# -*- coding:utf-8 -*-

import logging

from syswhispers3.utils.singleton import Singleton


class LoggerSingleton(metaclass=Singleton):
    """Simple Class used to ouput messages based on logging level set.
    As a singleton class the log_level will be set at the first (and only) implementation of the class, all subsequent calls will reuse this instance

    Args:
        metaclass (_type_, optional): _description_. Defaults to Singleton.
    """

    def __init__(self, log_level: int = logging.INFO) -> None:
        """Init class called once that will set log_level

        Args:
            log_level (int, optional): Logging level set. Defaults to logging.INFO.
        """
        self.log_level = log_level

    def __output(self, message: str, level: int) -> None:
        """Private method used to output message to CLI using a specific logging level

        Args:
            message (str): The message to output
            level (int): The corresponding logging level
        """
        if level >= self.log_level:
            print(f"{message}")

    def debug(self, message: str, stripped: bool = False) -> None:
        """Public method used to display a DEBUG (logging.DEBUG) message if log_level is set accordingly

        Args:
            message (str): The DEBUG message to ouput
            stripped (bool, optional): Optional flag to remove the leading chars used to identify DEBUG messages. Defaults to False.
        """
        start = "[*] " if not stripped else ""
        self.__output(f"{start}{message}", logging.DEBUG)

    def info(self, message: str, stripped: bool = False) -> None:
        """Public method used to display a INFO (logging.INFO) message if log_level is set accordingly

        Args:
            message (str): The INFO message to ouput
            stripped (bool, optional): Optional flag to remove the leading chars used to identify INFO messages. Defaults to False.
        """
        start = "[+] " if not stripped else ""
        self.__output(f"{start}{message}", logging.INFO)

    def warning(self, message: str, stripped: bool = False) -> None:
        """Public method used to display a WARNING (logging.WARNING) message if log_level is set accordingly

        Args:
            message (str): The WARNING message to ouput
            stripped (bool, optional): Optional flag to remove the leading chars used to identify WARNING messages. Defaults to False.
        """
        start = "[!] " if not stripped else ""
        self.__output(f"{start}{message}", logging.WARNING)

    def error(self, message: str, stripped: bool = False) -> None:
        """Public method used to display a ERROR (logging.ERROR) message if log_level is set accordingly

        Args:
            message (str): The ERROR message to ouput
            stripped (bool, optional): Optional flag to remove the leading chars used to identify ERROR messages. Defaults to False.
        """
        start = "[!] " if not stripped else ""
        self.__output(f"{start}{message}", logging.ERROR)

    def critical(self, message: str, stripped: bool = False) -> None:
        """Public method used to display a CRITICAL (logging.CRITICAL) message if log_level is set accordingly

        Args:
            message (str): The CRITICAL message to ouput
            stripped (bool, optional): Optional flag to remove the leading chars used to identify CRITICAL messages. Defaults to False.
        """
        start = "[!!] " if not stripped else ""
        self.__output(f"{start}{message}", logging.CRITICAL)

    def output(self, message: str) -> None:
        """Public method used to display a message with a level lower or equal to CRITICAL

        Args:
            message (str): The message to output
        """
        # Avoid any output on quiet mode
        if self.log_level <= logging.CRITICAL:
            print(message)

    def is_debug(self) -> bool:
        """Public method used to retrieve debugging state

        Returns:
            bool: Returns True if logging level is lower or equal to logging.DEBUG
        """
        return self.log_level <= logging.DEBUG

    def is_verbose(self) -> bool:
        """Public method used to retrieve verbosity state

        Returns:
            bool: Returns True if logging level is lower or equal to logging.INFO
        """
        return self.log_level <= logging.INFO