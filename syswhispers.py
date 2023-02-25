#!/usr/bin/python3
# -*- coding:utf-8 -*-

import logging
import argparse

from syswhispers3.syscallsGenerator import SyscallsGenerator
from syswhispers3.utils.loggerSingleton import LoggerSingleton

FANCY_HEADER = "                                                       \n"\
        "                  .                         ,--.       \n"\
        ",-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/       \n"\
        "`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \\      \n"\
        "`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''       \n"\
        "     /|                     |  @Jackson_T              \n"\
        "    `-'                     '  @modexpblog, 2021       \n\n"\
        "                      Edits by @klezVirus,  2022       \n"\
        "                      Edits by     @x42en,  2023       \n"\
        "SysWhispers3: Why call the kernel when you can whisper?\n\n"\

if __name__ == '__main__':
    # Set default log level
    log_level = logging.WARNING

    logger = LoggerSingleton(log_level)

    parser = argparse.ArgumentParser(description="SysWhispers3 - SysWhispers on steroids")
    parser.add_argument('-p', '--preset', help='Preset functions ("all", "donut", "common")', choices=['all', 'donut', 'common'], required=False)
    parser.add_argument('-a', '--arch', default="x64", choices=["x86", "x64", "all"], help='Architecture (default: x64)',
                        required=False)
    parser.add_argument('-c', '--compiler', default="msvc", choices=["msvc", "mingw", "all"], help='Compiler (default: msvc)',
                        required=False)
    parser.add_argument('-m', '--method', default="embedded",
                        choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                        help='Syscall recovery method (default: embedded)', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', default="syscalls", required=False)
    parser.add_argument('--int2eh', default=False, action='store_true',
                        help='Use the old `int 2eh` instruction in place of `syscall`', required=False)
    parser.add_argument('--wow64', default=False, action='store_true',
                        help='Add support for WoW64, to run x86 on x64', required=False)
    parser.add_argument('-s', '--standalone', default=False, action='store_true',
                        help='Generate a single header file', required=False)
    
    shout_level = parser.add_mutually_exclusive_group()
    shout_level.add_argument('-q', '--quiet', default=False, action='store_true',
                        help='Disable all output', required=False)
    shout_level.add_argument('-v', '--verbose', default=False, action='store_true',
                        help='Enable debug output', required=False)
    shout_level.add_argument('-d', '--debug', default=False, action='store_true',
                        help='Enable debug output and syscall debug (insert software breakpoint)', required=False)
    
    logger.output(FANCY_HEADER)
    
    args = parser.parse_args()

    if args.quiet:
        logger.log_level = 100
    if args.verbose:
        logger.log_level = logging.INFO
    if args.debug:
        logger.log_level = logging.DEBUG

    try:
        sw = SyscallsGenerator(
            arch=args.arch,
            compiler=args.compiler,
            syscall_instruction="syscall" if not args.int2eh else "int 2eh",
            recovery=args.method,
            wow64=args.wow64
        )
    except Exception as err:
        logger.critical(err)

    try:
        if args.preset == 'all':
            logger.output('All functions selected.\n')
            sw.generate(basename=args.out_file, standalone=args.standalone)

        elif args.preset in ['common', 'donut', 'all']:
            if args.preset == 'common':
                logger.output('Common functions selected.\n')
                sw.generate(basename=args.out_file, standalone=args.standalone)
            elif args.preset == 'donut':
                logger.output('Donut functions selected.\n')
                sw.generate(sw.list_donut_functions(), basename=args.out_file, standalone=args.standalone)
            elif args.preset == 'all':
                logger.output('ALL functions selected.\n')
                sw.generate(sw.list_supported_functions(), basename=args.out_file, standalone=args.standalone)

        elif not args.functions:
            logger.error('ERROR:   --preset XOR --functions switch must be specified.\n')
            logger.error('EXAMPLE: ./syswhispers.py --preset common --out-file syscalls_common')
            logger.error('EXAMPLE: ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

        else:
            functions = args.functions.split(',') if args.functions else []
            sw.generate(functions, basename=args.out_file, standalone=args.standalone)
    except Exception as err:
        logger.critical(err)
