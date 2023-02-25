# -*- coding:utf-8 -*-

import os
import json
import struct
import logging

from syswhispers3.abstracts.abstractFactory import AbstractFactory
from syswhispers3.utils import Arch, Compiler, SyscallRecoveryType

from syswhispers3.constants.sysWhispersConstants import SysWhispersConstants

class SyscallsGenerator(AbstractFactory):
    """Main class used to generate SysWhispers files in various format, or standalone header. SysWhispers allows you to evade AV/EDR by invoking syscalls in various manners so userland hooked DLL are unable to detect them.

    Args:
        AbstractFactory (_type_): _description_
    """
    def __init__(
            self,
            log_level:int=logging.INFO,
            arch:Arch=Arch.x64,
            compiler:Compiler=Compiler.All,
            recovery:SyscallRecoveryType=SyscallRecoveryType.EMBEDDED,
            syscall_instruction:str="syscall",
            wow64:bool=False) -> None:
        super().__init__(log_level)

        # Set output level
        self.__debug = self.logger.is_debug()

        # Init internal vars
        self.__arch = Arch.from_string(str(arch))
        self.__compiler = Compiler.from_string(str(compiler))
        self.__recovery = SyscallRecoveryType.from_name_or_default(recovery)
        self.__wow64 = wow64
        self.__syscall_instruction = syscall_instruction
        self.__egg = self.generate_random_egg()
        self.__seed = self.generate_random_seed()
        
        # Load type definitions
        with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, "typedefs.json")) as td:
            self.__typedefs:list = json.load(td)
        
        # Load prototypes
        with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, "prototypes.json")) as pr:
            self.__prototypes:dict = json.load(pr)
        
        self.logger.debug("Params used:")
        self.logger.debug(f"\tArch: {self.__arch}")
        self.logger.debug(f"\tCompiler: {self.__compiler}")
        self.logger.debug(f"\tRecovery: {self.__recovery}")
        self.logger.debug(f"\tSyscall_instruction: {self.__syscall_instruction}")

        # self.validate()

    def list_supported_functions(self) -> list:
        """Public method used to list all supported kernel calls handled by SysWhispers

        Returns:
            list: The kernel calls supported as a list of strings
        """
        return list(self.__prototypes.keys())
    
    def list_donut_functions(self) -> list:
        """Public method used to list all kernel calls used by Donut

        Returns:
            list: The kernel calls used by Donut as a list of strings
        """
        return SysWhispersConstants.DONUT_SYSCALLS
    
    def validate(self) -> bool:
        """Public method used to check if EGG-Hunter method is used while compiler is set to 'MINGW' which is incompatible by now

        Returns:
            bool: Flag set when everything run smoothly
        """
        if self.__recovery == SyscallRecoveryType.EGG_HUNTER:
            if self.__compiler in [Compiler.All, Compiler.MINGW]:
                # TODO: try to make the 'db' instruction work in MinGW
                self.logger.warning("Egg-Hunter not compatible with MinGW")

            self.logger.output("[*] With the egg-hunter, you need to use a search-replace functionality:")
            self.logger.output(f"  unsigned char egg[] = {{ {', '.join([hex(int(x, 16)) for x in self.__egg] * 2)} }}; // egg")
            replace_x86 = '  unsigned char replace[] = { 0x0f, 0x34, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // sysenter; nop; nop; ret; nop; int3; int3'
            replace_x64 = '  unsigned char replace[] = { 0x0f, 0x05, 0x90, 0x90, 0xC3, 0x90, 0xCC, 0xCC }; // syscall; nop; nop; ret; nop; int3; int3'
            if self.__arch == Arch.Any:
                self.logger.output(f"#ifdef _WIN64\n{replace_x64}\n#else\n{replace_x86}\n#endif")
            elif self.__arch == Arch.x86:
                self.logger.output(replace_x86)
            else:
                self.logger.output(replace_x64)

        return True
    
    def generate(self, function_names:list=SysWhispersConstants.COMMON_SYSCALLS, basename: str = 'syscalls', standalone:bool=False) -> bool:
        """Public method used to generate code files based on requested configuration

        Args:
            function_names (list, optional): The list of kernel calls to evade. Defaults to COMMON_SYSCALLS.
            basename (str, optional): The basename used for filename generation, will be prepend to extensions. Defaults to 'syscalls'.
            standalone (bool, optional): When set to True this will concatanate all code in a single header file for easier import in external project. Defaults to False.

        Raises:
            ValueError: Error raised when standalone option is set and the architecture is set to ALL which is incompatible at the moment
            ValueError: Error raised if you call this method with an empty array of kernel calls

        Returns:
            bool: Return True if all run smoothly
        """
        if standalone and self.__arch == Arch.Any:
            raise ValueError('You can not generate a standalone file for all architecture. Please specify `-a [x86 | x64]` in your parameters.')
        
        written = []

        if len(function_names) == 0:
            function_names = list(self.__prototypes.keys())
        elif any([f not in self.__prototypes.keys() for f in function_names]):
            raise ValueError('Prototypes are not available for one or more of the requested functions.')

        # Set flags
        self.__standalone = standalone
        self.__base_dir = os.path.dirname(basename)
        if self.__base_dir is None:
            self.__base_dir = os.path.curdir
        self.__base_name = os.path.basename(basename)
        
        # Generate code
        h_code = self.__generate_h_code(function_names)
        c_code = self.__generate_c_code(function_names)
        asm_x64_code = None
        asm_x86_code = None

        if self.__arch in [Arch.Any, Arch.x64]:
            asm_x64_code = self.__generate_asm_code(function_names, Arch.x64)
        
        if self.__arch in [Arch.Any, Arch.x86]:
            asm_x86_code = self.__generate_asm_code(function_names, Arch.x86)
        
        # Write code to files
        if self.__standalone:
            # Build complete file
            standalone_code = h_code
            standalone_code += c_code
            if asm_x64_code is not None:
                standalone_code += asm_x64_code
            if asm_x86_code is not None:
                standalone_code += asm_x86_code

            # Write header code file
            with open(os.path.join(self.__base_dir, f"{self.__base_name}.h"), 'w') as hc:
                self.logger.debug(f"Standalone Header Code:\n{standalone_code}")
                hc.write(standalone_code)
            written.append(os.path.join(self.__base_dir, f"{self.__base_name}.h"))

            self.logger.output('Complete! Standalone File written to:')
        else:
            # Write C code file
            c_file = os.path.join(self.__base_dir, f"{self.__base_name}.c")
            with open(c_file, 'w') as cc:
                self.logger.debug(f"C Code:\n{c_code}")
                cc.write(c_code)
            written.append(c_file)
            
            # Write header code file
            h_file = os.path.join(self.__base_dir, f"{self.__base_name}.h")
            with open(h_file, 'w') as hc:
                self.logger.debug(f"Header Code:\n{h_code}")
                hc.write(h_code)
            written.append(h_file)
            
            if asm_x64_code is not None:
                asm_file = os.path.join(self.__base_dir, f"{self.__base_name}-asm.x64.asm")
                # Write ASM code file
                with open(asm_file, 'w') as ac:
                    self.logger.debug(f"ASM x64 Code:\n{asm_x64_code}")
                    ac.write(asm_x64_code)
                written.append(asm_file)
            
            if asm_x86_code is not None:
                asm_file = os.path.join(self.__base_dir, f"{self.__base_name}-asm.x86.asm")
                # Write ASM code file
                with open(asm_file, 'w') as ac:
                    self.logger.debug(f"ASM x86 Code:\n{asm_x86_code}")
                    ac.write(asm_x86_code)
                written.append(asm_file)
            
            self.logger.output('Complete! Files written to:')
        
        # Display written files
        for f in written:
            self.logger.output(f"\t{f}")
        
        return True
    
    def __get_wow64_function(self) -> str:
        """Private method used to insert the WOW gate so you can run 32bits code on 64bits architecture. Mainly used when setting Architecture to ALL

        Returns:
            str: The WOW64 function code generated
        """
        msvc_wow64 = '__declspec(naked) BOOL local_is_wow64(void)\n{\n    __asm {\n        mov eax, fs:[0xc0]\n        test eax, eax\n        jne wow64\n        mov eax, 0\n        ret\n        wow64:\n        mov eax, 1\n        ret\n    }\n}\n'
        mingw_wow64 = '__declspec(naked) BOOL local_is_wow64(void)\n{\n    __asm(\n        "mov eax, fs:[0xc0] \\n"\n        "test eax, eax \\n"\n        "jne wow64 \\n"\n        "mov eax, 0 \\n"\n        "ret \\n"\n        "wow64: \\n"\n        "mov eax, 1 \\n"\n        "ret \\n"\n    );\n}'
        wow64_function = ''
        if self.__compiler == Compiler.All:
            wow64_function += '#if defined(_MSC_VER)\n\n'
            wow64_function += msvc_wow64
            wow64_function += '\n\n#elif defined(__GNUC__)\n\n'
            wow64_function += mingw_wow64
            wow64_function += '\n\n#endif'
        elif self.__compiler == Compiler.MSVC:
            wow64_function += msvc_wow64
        elif self.__compiler == Compiler.MINGW:
            wow64_function += mingw_wow64
        
        return wow64_function
    
    def __generate_asm_code(self, function_names:list, arch:str) -> str:
        """Private method used to generate ASM opcodes based on architecture and kernel calls list to evade

        Args:
            function_names (list): The kernel calls list to evade
            arch (str): The architecture chosen. Can be x64 | x86 | ALL

        Raises:
            NotImplementedError: Error raised when architecture is not in supported list

        Returns:
            str: The Intel format opcodes generated
        """
        output_asm = ''
        # ASM code is embedded in C file when using MINGW
        if self.__compiler in [Compiler.All, Compiler.MSVC]:
            # Declaration only needed when using external file
            if not self.__standalone:
                if arch in [Arch.Any, Arch.x64]:
                    output_asm += '.code\n\nEXTERN SW3_GetSyscallNumber: PROC\n'
                elif arch in [Arch.Any, Arch.x86]:
                    output_asm += ".686\n.XMM\n.MODEL flat, c\nASSUME fs:_DATA\n.code\n\n"
                    output_asm += '\nEXTERN SW3_GetSyscallNumber: PROC\nEXTERN local_is_wow64: PROC\nEXTERN internal_cleancall_wow64_gate: PROC\n'
                else:
                    raise NotImplementedError("Unsupported architecture")
                    
                if self.__recovery == SyscallRecoveryType.JUMPER:
                    # We perform a direct jump to the syscall instruction inside ntdll.dll
                    output_asm += 'EXTERN SW3_GetSyscallAddress: PROC\n'

                elif self.__recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                    # We perform a direct jump to a syscall instruction of another API
                    output_asm += 'EXTERN SW3_GetRandomSyscallAddress: PROC\n'

                output_asm += '\n'

            # Set template
            target_template = 'base-x64.asm' if arch == Arch.x64 else 'base-x86.asm'
            
            # Load template
            with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, target_template), 'r') as bs:
                template = bs.read()
            
            for function_name in function_names:
                function_code = self._get_function_asm_code(template, function_name, arch, embedded=self.__standalone)
                output_asm += f"{function_code}\n\n"

            if not self.__standalone:
                output_asm += '\nend'
        
        return output_asm

    def __generate_h_code(self, function_names:list) -> str:
        """Private method used to generate the C++ Header file based on data/base.h template.

        Args:
            function_names (list): The kernel calls list to evade

        Returns:
            str: The C++ code generated
        """
        # Load base content
        with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, 'base.h'), 'r') as bs:
            # Replace <SEED_VALUE> with a random seed.
            base_header_contents = bs.read()
            
            # Replace SEED
            base_header_contents = base_header_contents.replace('<SEED_VALUE>', f'0x{self.__seed:08X}', 1)

            # Write the typedefs.
            for typedef in self.__get_typedefs(function_names):
                base_header_contents += f"{typedef}\n\n"

            # Write the function prototypes.
            for function_name in function_names:
                function_code = self.__get_function_prototype(function_name)
                base_header_contents +=  f"{function_code}\n\n"

            # Write the endif line.
            base_header_contents += '#endif\n'

        return base_header_contents

    def __generate_c_code(self, function_names:list) -> str:
        """Private method used to generate the C++ source file based on data/base.c template

        Args:
            function_names (list): The kernel calls list to evade

        Returns:
            str: The C++ source code generated
        """
        # Load base content
        with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, 'base.c'), 'r') as bs:
            base_source_contents = bs.read()

            if self.__debug:
                base_source_contents = base_source_contents.replace('//#define DEBUG', '#define DEBUG')
            # Clean template
            else:
                base_source_contents = base_source_contents.replace('//#define DEBUG', '')

            # Add include when not in standalone file
            if self.__standalone:
                base_source_contents = base_source_contents.replace('// <INCLUDES>', '')
            else:
                base_source_contents = base_source_contents.replace('// <INCLUDES>', f"#include \"{self.__base_name}.h\"\n#include <stdio.h>\n", 1)
            # Set Jumper method
            if self.__recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
                base_source_contents = base_source_contents.replace("// JUMPER", "#define JUMPER")
            # Clean template
            else:
                base_source_contents = base_source_contents.replace("// JUMPER", '')

            if self.__wow64:
                base_source_contents = base_source_contents.replace('// JUMP_TO_WOW32Reserved',
                                                                    '        // if we are a WoW64 process, jump to WOW32Reserved\n        SyscallAddress = (PVOID)__readfsdword(0xc0);\n        return SyscallAddress;')
            else:
                base_source_contents = base_source_contents.replace('// JUMP_TO_WOW32Reserved',
                                                                    '        return NULL;')

            # Set WoW64 call
            base_source_contents = base_source_contents.replace('// LOCAL_IS_WOW64', self.__get_wow64_function())

            if self.__compiler in [Compiler.All, Compiler.MINGW]:
                base_source_contents += '\n#if defined(__GNUC__)\n'
                # Set Wow64 gate
                if self.__arch == Arch.x64:
                    base_source_contents += '\n#if defined(_WIN64)\n'
                
                base_source_contents += "\n"
                
                # Set template
                target_template = 'base-x64.asm' if self.__arch == Arch.x64 else 'base-x86.asm'
                
                # Load template
                with open(os.path.join(SysWhispersConstants.SYSWHISPERS_DATA_PATH, target_template), 'r') as bs:
                    template = bs.read()
                        
                for function_name in function_names:
                    if self.__arch in [Arch.Any, Arch.x64]:
                        function_code = self._get_function_asm_code(template, function_name, Arch.x64, embedded=True)
                    
                    if self.__arch in [Arch.Any, Arch.x86]:
                        function_code = self._get_function_asm_code(template, function_name, Arch.x86, embedded=True)
                
                    base_source_contents += f"{function_code}\n\n"
                base_source_contents += '\n#endif\n'
        
        return base_source_contents
    
    def __get_typedefs(self, function_names: list) -> list:
        """Private method used to retrieve definition types of kernel calls list to evade using the data/typedefs.json ressource file

        Args:
            function_names (list): The kernel calls list to evade

        Returns:
            list: The C++ code generated
        """
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.__typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.__prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.__typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.__typedefs[typedef_id]['dependencies']
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
                typedef_code.append(self.__typedefs[j]['definition'])
        
        return typedef_code
    
    def __get_function_prototype(self, function_name: str) -> str:
        """Private method used to retrieve prototypes of kernel calls list to evade using the data/prototypes.json ressource file

        Args:
            function_names (list): The kernel calls list to evade

        Returns:
            list: The C++ code generated
        """
        # Check if given function is in syscall map.
        if function_name not in self.__prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.__prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {function_name}('
        if num_params:
            for i in range(num_params):
                param = self.__prototypes[function_name]['params'][i]
                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{param["type"]} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature

    def __get_function_hash(self, function_name: str) -> str:
        """Private method used to hash kernel call to evade with random hex number in order to avoid static analysis detection. Used by _get_function_asm_code()

        Args:
            function_name (str): The kernel call to evade

        Returns:
            str: The kernel call randomized
        """
        func_hash = self.__seed
        name = function_name.replace('Nt', 'Zw', 1) + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            func_hash ^= partial_name_short + ror8(func_hash)

        return f'{func_hash:08X}'

    def _get_function_asm_code(self, template: str, function_name: str, arch:Arch, embedded:bool=False) -> str:
        """Private method used to generate ASM opcodes handling the syscall evasion of a kernel call. The result is embedded in the data/base-ARCH.asm template 

        Args:
            template (str): The template source code to use
            function_name (str): The kernel call to evade
            arch (Arch): The architecture to use for opcodes generation
            embedded (bool): Standalone flag used to modify the leading and trailing code: ASM and C++ headers are not using opcodes the same way ;)

        Returns:
            str: The ASM opcodes generated
        """
        # Set register
        register = 'r15' if arch == Arch.x64 else 'edi'
        target_register = 'rax' if arch == Arch.x64 else 'eax'

        function_hash = self.__get_function_hash(function_name)
        template = template.replace('#### FUNCTION HASH ####', function_hash)

        # Define function hash
        function_hash_addr = f'0x{function_hash}' if self.__compiler == Compiler.MINGW else f'0{function_hash}h'
        template = template.replace('#### FUNCTION HASH ADDR ####', function_hash_addr)

        # Set vars
        random_syscall_code = ''
        wow_gate_code = ''
        wow_gate_finish = ''
        
        # Set random syscall used
        if self.__recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
            random_syscall = []
            if self.__recovery == SyscallRecoveryType.JUMPER_RANDOMIZED:
                random_syscall.append('call SW3_GetRandomSyscallAddress        ; Get a syscall offset from a different api.')
            else:
                random_syscall.append('call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset')
            random_syscall.append(f'\tmov {register}, {target_register}                          ; Save the address of the syscall')
            if arch == Arch.x64:
                random_syscall.append(f'\tmov ecx, {function_hash_addr}                     ; Re-Load function hash into ECX (optional)')
            else:
                random_syscall.append(f'\tpush {function_hash_addr}                     ; Re-Load function hash into ECX (optional)')
            
            # Set SYSCALL in template
            random_syscall_code = "\n\t".join(random_syscall)
        
        # On x86 running on x64:
        elif self.__wow64:
            wow_gate = []
            # check if the process is WoW64 or native
            wow_gate.append(f'call _local_is_wow64')
            wow_gate.append(f'\ttest eax, eax')
            wow_gate.append(f'\tje is_native')

            # if is wow64
            wow_gate.append('\tcall internal_cleancall_wow64_gate')

            # Note: Workaround for Wow64 call
            # ntdll!NtWriteFile+0xc:
            # 77ca2a1c c22400          ret     24h
            # In a standard call, we have two addresses before the arguments passed to the Nt function
            # In this case, as we need to return to the program, we can insert the return address twice
            wow_gate.append(f'\tpush ret_address_epilog_{function_hash}\n')
            wow_gate.append(f'\tpush ret_address_epilog_{function_hash}\n')
            wow_gate.append('\txchg eax, ecx\n')
            wow_gate.append('\tjmp ecx\n')
            wow_gate.append('\tjmp finish\n')
            
            # if is native
            wow_gate.append('is_native:')
            
            # Set WOW Gate in template
            wow_gate_code = "\n\t".join(wow_gate)
            wow_gate_finish = 'finish:'

        template = template.replace('#### RANDOM SYSCALL ####', random_syscall_code)
        template = template.replace('#### WOW64 GATE ####', wow_gate_code)
        template = template.replace('#### WOW64 FINISH ####', wow_gate_finish)
        
        # Set debug steps
        if self.__debug:
            template = template.replace('#### DEBUG ####', 'int 3')
        else:
            template = template.replace('#### DEBUG ####', '')
        
        # Set Offset
        if arch == Arch.x86:
            offset_value = '0x5' if self.__compiler == Compiler.MINGW else '05h'
        else:
            offset_value = '0x28' if self.__compiler == Compiler.MINGW else '28h'
        template = template.replace('#### OFFSET ####', offset_value)
        
        # Set call
        syscall = []
        if self.__recovery in [SyscallRecoveryType.JUMPER, SyscallRecoveryType.JUMPER_RANDOMIZED]:
            syscall.append(f'jmp {register}                            ; Jump to -> Invoke system call.')
            if arch == Arch.x86:
                syscall.append('\tret')
        elif self.__recovery == SyscallRecoveryType.EGG_HUNTER:
            if self.__compiler == Compiler.MINGW:
                signature = ','.join([x for x in self.__egg + self.__egg])
            else:
                signature = ','.join([f'{x[2:]}h' for x in self.__egg + self.__egg])
            syscall.append(f'db {signature}')
            if arch == Arch.x64:
                syscall.append('ret')
            else:
                syscall.append('\tret')
        elif self.__recovery == SyscallRecoveryType.EMBEDDED:
            if arch == Arch.x64:
                syscall.append(self.__syscall_instruction)
                syscall.append('ret')
            else:
                syscall.append('sysenter')
                syscall.append('\tret')
        
        template = template.replace('#### SYSCALL ####', "\n\t".join(syscall))

        # Format output
        if arch == Arch.x64:
            opcodes = "".join([s.replace('\t\t', '\t') for s in template.strip().splitlines(True) if s.strip()])
        else:
            opcodes = "".join([s for s in template.strip().splitlines(True) if s.strip()])
        
        if embedded:
            cleaned = ''
            for line in opcodes.split('\n'):
                # Avoid dealing with tags
                if '####' in line:
                    cleaned += line.rstrip()
                    continue
                # Remove comments
                cleaned += self.__remove_comments(line)
            
            # Replace end of lines
            opcodes = cleaned.replace('\n',' \\n\\\n')
        
        if embedded:
            header = f"#define {function_name} {function_name}\n__asm__(\"{function_name}: \\n\\\n"
            footer = '\");'
        else:
            header = f"{function_name} PROC"
            footer = f"{function_name} ENDP"
        
        # Set appropriate header
        opcodes = opcodes.replace('#### HEADER ####', header)
        opcodes = opcodes.replace('#### FOOTER ####', footer)

        return opcodes

    def __remove_comments(self, line:str) -> str:
        """Private method used to remove comments from asm source file

        Args:
            line (str): The asm source code line to clean

        Returns:
            str: The ASM cleaned line
        """
        i = line.find(';')
        if i >= 0:
            line = line[:i]
        return f"{line.rstrip()}\n"
