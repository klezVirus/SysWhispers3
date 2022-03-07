#!/usr/bin/python3

import argparse
import json
import os
import random
import string
import struct
from enum import Enum
from pathlib import Path

try:
    from enums.Architectures import Arch
    from enums.SyscallRecoveryType import SyscallRecoveryType
    from utils.utils import get_project_root

    base_directory = os.path.join(get_project_root(), 'syscalls', 'syswhispersv3')
    define_search_and_replace = False

except ModuleNotFoundError:
    def get_project_root() -> Path:
        return Path(__file__).parent


    base_directory = get_project_root()
    define_search_and_replace = True


    class Arch(Enum):
        Any = ""
        x86 = "x86"
        x64 = "x64"

        @staticmethod
        def from_string(label):
            if label.lower() in ["any"]:
                return Arch.Any
            elif label.lower() in ["32", "86", "x86", "i386"]:
                return Arch.x86
            elif label.lower() in ["64", "x64", "amd64", "x86_64"]:
                return Arch.x64


    # Define SyscallRecoveryType
    class SyscallRecoveryType(Enum):
        EMBEDDED = 0
        EGG_HUNTER = 1
        JUMPER = 2
        JUMPER_RANDOMIZED = 3

        @classmethod
        def from_name_or_default(cls, name):
            _types = dict(map(lambda c: (c.name.lower(), c.value), cls))
            return SyscallRecoveryType(_types[name]) if name in _types.keys() else SyscallRecoveryType.EMBEDDED

        @classmethod
        def get_name(cls, value):
            if isinstance(value, str):
                value = int(value)
            _types = dict(map(lambda c: (c.value, c.name.lower()), cls))
            return _types[value] if value in _types.keys() else None

        @classmethod
        def from_name(cls, name):
            _types = dict(map(lambda c: (c.name.lower(), c.value), cls))
            return _types[name] if name in _types.keys() else None

        @classmethod
        def value_list(cls):
            return list(map(lambda c: c.value, cls))

        @classmethod
        def key_list(cls):
            return list(map(lambda c: c.name.lower(), cls))


class SysWhispers(object):
    def __init__(
            self,
            arch: Arch = Arch.x64,
            recovery: SyscallRecoveryType = SyscallRecoveryType.EMBEDDED,
            syscall_instruction: str = "syscall",
            wow64: bool = False,
            verbose: bool = False,
            debug: bool = False):
        self.arch = arch
        self.recovery = recovery
        self.wow64 = wow64
        self.syscall_instruction = syscall_instruction
        self.egg = [hex(ord(random.choices(string.ascii_lowercase, k=1)[0])), "0x0", "0x0",
                    hex(ord(random.choices(string.ascii_lowercase, k=1)[0]))]
        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.typedefs: list = json.load(
            open(os.path.join(base_directory, 'data', 'typedefs.json')))
        self.prototypes: dict = json.load(
            open(os.path.join(base_directory, 'data', 'prototypes.json')))
        self.verbose = verbose
        self.debug = debug
        self.validate()

    def validate(self):
        if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
            if self.arch == Arch.x86 and self.wow64:
                print(r"[*] In WOW64 syscall is performed by jumping to "
                      r"KiFastSystemCall (no difference from embedded)")
                self.recovery = SyscallRecoveryType.EMBEDDED
        elif self.recovery == SyscallRecoveryType.EGG_HUNTER:
            if self.arch == Arch.x86 and self.wow64:
                print("[-] Egg-Hunter not compatible with WoW64")
                exit(1)
            print(r"[*] With the egg-hunter, you need to use a search-replace functionality:")
            print(f"  unsigned char egg[] = {{ {', '.join([hex(int(x, 16)) for x in self.egg] * 2)} }}; // egg")
            if self.arch == Arch.x86:
                print(
                    "  unsigned char replace[] = { 0x0f, 0x34, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // sysenter; nop; "
                    "nop; ret; nop; int3; int3")
            else:
                print(
                    "  unsigned char replace[] = { 0x0f, 0x05, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // syscall; nop; "
                    "nop; ret; nop; int3; int3 ")
            print()

    def generate(self, function_names: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        elif any([f not in self.prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Write C file.
        with open(os.path.join(base_directory, 'data', 'base.c'), 'rb') as base_source:
            with open(f'{basename}.c', 'wb') as output_source:
                base_source_contents = base_source.read().decode()
                base_source_contents = base_source_contents.replace('<BASENAME>', os.path.basename(basename), 1)
                if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                    base_source_contents = base_source_contents.replace("// JUMPER", "#define JUMPER")

                if self.arch == Arch.x86:
                    base_source_contents = base_source_contents.replace(
                        '// <X86>',
                        f"#include <intrin.h>\n"
                        f"#define x32\n\n"
                        f"#pragma intrinsic(__readfsdword)\n"
                        f"extern unsigned long __readfsdword(unsigned long);\n\n"
                        f"EXTERN_C void* internal_cleancall_wow64_gate(){{\n\treturn (void*)__readfsdword(0xC0);\n}}\n\n"
                        # f"EXTERN_C void internal_cleancall_wow64_gate(){{\n\t((void(*)(void))__readfsdword(0xC0))();\n}}\n\n"
                        f"__declspec(naked) BOOL local_is_wow64(void)\n{{\n\t__asm {{\n\t\tmov eax, fs:[0xc0]\n\t\ttest eax, eax\n\t\tjne wow64\n\t\tmov eax, 0\n\t\tret\n\t\twow64:\n\t\tmov eax, 1\n\t\tret\n\t}}\n}}\n\n"
                    )
                    base_source_contents = base_source_contents.replace('<PEB>', '__readfsdword(0x30)')

                else:
                    base_source_contents = base_source_contents.replace('<PEB>', '__readgsqword(0x60)')
                output_source.write(base_source_contents.encode())

        # Write ASM file
        basename_suffix = ''
        basename_suffix = basename_suffix.capitalize() if os.path.basename(basename).istitle() else basename_suffix
        basename_suffix = f'_{basename_suffix}' if '_' in basename else basename_suffix
        with open(f'{basename}{basename_suffix}.asm', 'wb') as output_asm:
            if self.arch == Arch.x86:
                output_asm.write(b".686\n.XMM\n.MODEL flat, c\nASSUME fs:_DATA\n\n")

            output_asm.write(b'.code\n\nEXTERN SW2_GetSyscallNumber: PROC\n\n')
            if self.recovery == SyscallRecoveryType.JUMPER:
                # We perform a direct jump to the syscall instruction inside ntdll.dll
                output_asm.write(b'EXTERN SW2_GetSyscallOffset: PROC\n\n')

            elif self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                # We perform a direct jump to a syscall instruction of another API
                output_asm.write(b'EXTERN SW2_GetRandomSyscallOffset: PROC\n\n')

            if self.arch == Arch.x86 and self.wow64:
                output_asm.write(b'EXTERN internal_cleancall_wow64_gate: PROC\n\n')

            # Thanks to @S4ntiago_P and nanodump
            # https://github.com/helpsystems/nanodump/blob/main/source/syscalls-asm.asm
            output_asm.write(b'SyscallNotFound PROC\n\tmov eax, 0C0000225h\n\tret\nSyscallNotFound ENDP\n\n')
            if self.arch == Arch.x64:
                # For x86, the function is defined with inline assembly
                # Forx x64, the function returns false
                output_asm.write(b'local_is_wow64 PROC\n\tmov rax, 0\n\tret\nlocal_is_wow64 ENDP\n\n')

            for function_name in function_names:
                output_asm.write((self._get_function_asm_code(function_name) + '\n').encode())

            output_asm.write(b'end')

        # Write header file.
        with open(os.path.join(base_directory, 'data', 'base.h'), 'rb') as base_header:
            with open(f'{basename}.h', 'wb') as output_header:
                # Replace <SEED_VALUE> with a random seed.
                base_header_contents = base_header.read().decode()
                base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.seed:08X}', 1)

                # Write the base header.
                output_header.write(base_header_contents.encode())

                # Write the typedefs.
                for typedef in self._get_typedefs(function_names):
                    output_header.write(typedef.encode() + b'\n\n')

                # Write the function prototypes.
                for function_name in function_names:
                    output_header.write((self._get_function_prototype(function_name) + '\n\n').encode())

                # Write the endif line.
                output_header.write('#endif\n'.encode())

        if self.verbose:
            print('Complete! Files written to:')
            print(f'\t{basename}.h')
            print(f'\t{basename}.c')
            print(f'\t{basename}{basename_suffix}.asm')
            input("Press a key to continue...")
        return f'{basename}{basename_suffix}.asm'

    def _get_typedefs(self, function_names: list) -> list:
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.typedefs[typedef_id]['dependencies']
            more_dependencies = list(set(more_dependencies))  # Remove duplicates.

            if more_dependencies:
                # Create new layer.
                i += 1
                typedef_layers[i] = _names_to_ids(more_dependencies)
            else:
                # Remove duplicates between layers.
                for k in range(len(typedef_layers) - 1):
                    typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
                break

        # Get code for each typedef.
        typedef_code = []
        for i in range(max(typedef_layers.keys()), -1, -1):
            for j in typedef_layers[i]:
                typedef_code.append(self.typedefs[j]['definition'])
        return typedef_code

    def _get_function_prototype(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{param["type"]} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature

    def _get_function_hash(self, function_name: str):
        hash = self.seed
        name = function_name.replace('Nt', 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)

        return hash

    def _get_function_asm_code(self, function_name: str) -> str:
        function_hash = self._get_function_hash(function_name)
        num_params = len(self.prototypes[function_name]['params'])
        code = ''
        code += f'{function_name} PROC\n'
        if self.debug:
            code += '\tint 3\n'

        if self.arch == Arch.x64:
            # Generate 64-bit ASM code.
            code += '\tmov [rsp +8], rcx          ; Save registers.\n'
            code += '\tmov [rsp+16], rdx\n'
            code += '\tmov [rsp+24], r8\n'
            code += '\tmov [rsp+32], r9\n'
            code += '\tsub rsp, 28h\n'
            code += f'\tmov ecx, 0{function_hash:08X}h        ; Load function hash into ECX.\n'
            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\tcall SW2_GetRandomSyscallOffset        ; Get a syscall offset from a different api.\n'
                else:
                    code += '\tcall SW2_GetSyscallOffset              ; Resolve function hash into syscall offset.\n'
                code += '\tmov r15, rax                           ; Save the address of the syscall\n'
                code += f'\tmov ecx, 0{function_hash:08X}h        ; Re-Load function hash into ECX (optional).\n'
            code += '\tcall SW2_GetSyscallNumber              ; Resolve function hash into syscall number.\n'
            code += '\tadd rsp, 28h\n'
            code += '\tmov rcx, [rsp+8]                      ; Restore registers.\n'
            code += '\tmov rdx, [rsp+16]\n'
            code += '\tmov r8, [rsp+24]\n'
            code += '\tmov r9, [rsp+32]\n'
            code += '\tmov r10, rcx\n'
            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                code += '\tjmp r15                                ; Jump to -> Invoke system call.\n'
            elif self.recovery == SyscallRecoveryType.EGG_HUNTER:
                for x in self.egg + self.egg:
                    code += f'\tDB {x[2:]}h                     ; "{chr(int(x, 16)) if int(x, 16) != 0 else str(0)}"\n'
                code += '\tret\n'
            elif self.recovery == SyscallRecoveryType.EMBEDDED:
                code += f'\t{self.syscall_instruction}                    ; Invoke system call.\n'
                code += '\tret\n'
        else:
            # x32 Prolog
            code += '\tpush ebp\n'
            code += '\tmov ebp, esp\n'
            code += f'\tpush 0{function_hash:08X}h                  ; Load function hash into ECX.\n'

            if self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                if self.recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    code += '\tcall SW2_GetRandomSyscallOffset        ; Get a syscall offset from a different api.\n'
                else:
                    code += '\tcall SW2_GetSyscallOffset              ; Resolve function hash into syscall offset.\n'
                code += '\tmov edi, eax                           ; Save the address of the syscall\n'
                code += f'\tpush 0{function_hash:08X}h        ; Re-Load function hash into ECX (optional).\n'
            code += '\tcall SW2_GetSyscallNumber\n'
            code += '\tlea esp, [esp+4]\n'
            code += f'\tmov ecx, {num_params}h\n'
            code += 'push_argument:\n'
            code += '\tdec ecx\n'
            code += '\tpush [ebp + 08h + ecx * 4]\n'
            code += '\tjnz push_argument\n'
            if self.debug:
                # 2nd SW breakpoint, to study the syscall instruction in detail
                code += '\tint 3\n'
            code += '\tmov ecx, eax\n'
            if self.wow64 and self.recovery in [SyscallRecoveryType.EMBEDDED, SyscallRecoveryType.EGG_HUNTER]:
               code += '\tcall internal_cleancall_wow64_gate ; eax = KiFastSystemCall\n'

            code += '\tpush ret_address_epilog                      ; return address\n'
            
            if self.wow64:
                # Note: Workaround for Wow64 call
                # ntdll!NtWriteFile+0xc:
                # 77ca2a1c c22400          ret     24h
                # In a standard call, we have two addresses before the arguments passed to the Nt function
                # In this case, as we need to return to the program, we can insert the return address twice
                code += '\tpush ret_address_epilog                      ; return address\n'
            if self.wow64 and self.recovery in [SyscallRecoveryType.EMBEDDED, SyscallRecoveryType.EGG_HUNTER]:
                code += '\txchg eax, ecx ; call KiFastSystemCall\n'
                code += '\tjmp ecx ; call KiFastSystemCall\n'
            elif self.wow64 and self.recovery not in [SyscallRecoveryType.EMBEDDED, SyscallRecoveryType.EGG_HUNTER]:
                # not implemented
                raise NotImplementedError
            else:
                code += '\tcall do_sysenter_interrupt ; call KiFastSystemCall\n'

            code += '\tlea esp, [esp+4]\n'
            code += 'ret_address_epilog:\n'
            code += '\tmov esp, ebp\n'
            code += '\tpop ebp\n'
            code += '\tret\n'

            if not self.wow64:
                code += 'do_sysenter_interrupt:\n'
                code += '\tmov edx, esp\n'
                if self.recovery == SyscallRecoveryType.EGG_HUNTER:
                    for x in self.egg + self.egg:
                        code += f'\tDB {x[2:]}h                     ; "{chr(int(x, 16)) if int(x, 16) != 0 else str(0)}"\n'
                elif self.recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                    code += '\tjmp edi\n'
                else:
                    code += '\tsysenter\n'
                code += '\tret\n'

        code += f'{function_name} ENDP\n'
        return code


if __name__ == '__main__':
    print(
        "                                                       \n"
        "                  .                         ,--.       \n"
        ",-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/       \n"
        "`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \\      \n"
        "`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''       \n"
        "     /|                     |  @Jackson_T              \n"
        "    `-'                     '  @modexpblog, 2021       \n\n"
        "                      Edits by @klezVirus,  2022       \n"
        "SysWhispers3: Why call the kernel when you can whisper?\n\n"
    )

    parser = argparse.ArgumentParser(description="SysWhispers3 - SysWhispers on steroids")
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-a', '--arch', default="x64", choices=["x86", "x64"], help='Architecture', required=False)
    parser.add_argument('-m', '--method', default="embedded",
                        choices=["embedded", "egg_hunter", "jumper", "jumper_randomized"],
                        help='Syscall recovery method', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    parser.add_argument('--int2eh', default=False, action='store_true',
                        help='Use the old `int 2eh` instruction in place of `syscall`', required=False)
    parser.add_argument('--wow64', default=False, action='store_true',
                        help='Use Wow64 to run x86 on x64 (only usable with x86 architecture)', required=False)
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
                        help='Enable debug output', required=False)
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                        help='Enable syscall debug (insert software breakpoint)', required=False)
    args = parser.parse_args()

    recovery = SyscallRecoveryType.from_name_or_default(args.method)
    arch = Arch.from_string(args.arch)

    sw = SysWhispers(
        arch=arch,
        syscall_instruction="syscall" if not args.int2eh else "int 2eh",
        recovery=recovery,
        wow64=args.wow64,
        verbose=args.verbose,
        debug=args.debug
    )

    if args.preset == 'all':
        print('All functions selected.\n')
        sw.generate(basename=args.out_file)

    elif args.preset == 'common':
        print('Common functions selected.\n')
        sw.generate(
            ['NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenProcessToken',
             'NtTestAlert',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'],
            basename=args.out_file)

    elif args.preset:
        print('ERROR: Invalid preset provided. Must be "all" or "common".')

    elif not args.functions:
        print('ERROR:   --preset XOR --functions switch must be specified.\n')
        print('EXAMPLE: ./syswhispers.py --preset common --out-file syscalls_common')
        print('EXAMPLE: ./syswhispers.py --functions NtTestAlert,NtGetCurrentProcessorNumber --out-file syscalls_test')

    else:
        functions = args.functions.split(',') if args.functions else []
        sw.generate(functions, args.out_file)
