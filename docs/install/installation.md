# Installation
Here are all the steps needed to install SysWhispers3 project. For more informations on how to use it see: [usage](index#usage)

## Install it as dependency
```bash
pip3 install syswhispers3
```

## Install it as tool
- On Linux, MacOS based systems
```
git clone https://github.com/x42en/SysWhispers3
cd SysWhispers3
python3 ./syswhispers.py -h
```

- On Windows based systems
```
C:\> git clone https://github.com/x42en/SysWhispers3.git
C:\> cd SysWhispers3
C:\> python .\syswhispers.py --help
```

## Importing into Visual Studio

1. Copy the generated H/C/ASM files into the project folder.
2. In Visual Studio, go to *Project* → *Build Customizations...* and enable MASM.
3. In the *Solution Explorer*, add the .h and .c/.asm files to the project as header and source files, respectively.
4. Go to the properties of the ASM file, and set the *Item Type* to *Microsoft Macro Assembler*.

## Compiling outside of Visual Studio

### Windows

Makefile for 64 bits:

`Makefile.msvc`
```
OPTIONS = -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS-
LIBS = libvcruntime.lib libcmt.lib ucrt.lib kernel32.lib

program:
  ML64 /c syscalls-asm.x64.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64
  cl.exe $(OPTIONS) syscalls.c  program.c
  link.exe /OUT:program.x64.exe -nologo $(LIBS) /MACHINE:X64 -subsystem:console -nodefaultlib syscalls-asm.x64.obj syscalls.obj program.obj
```

Makefile for 32 bits:

`Makefile.msvc`
```
OPTIONS = -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS-
LIBS = libvcruntime.lib libcmt.lib ucrt.lib kernel32.lib

program:
  ML /c syscalls-asm.x86.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X86
  cl.exe $(OPTIONS) syscalls.c  program.c
  link.exe /OUT:program.x86.exe -nologo $(LIBS) /MACHINE:X86 -subsystem:console -nodefaultlib syscalls-asm.x86.obj syscalls.obj program.obj
```

Compile with nmake:
```
nmake -f Makefile.msvc
```

### Linux

Makefile for both 64 and 32 bits:

`Makefile.mingw`
```
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
OPTIONS := -masm=intel -Wall

program:
  $(CC_x64) syscalls.c program.c -o program.x64.exe $(OPTIONS)
  $(CC_x86) syscalls.c program.c -o program.x86.exe $(OPTIONS)
```

Compile with make:
```
make -f Makefile.mingw
```

## Caveats and Limitations

- The Egg-Hunter functionality is not implemented within this tool, it is in [Inceptor][1].
- System calls from the graphical subsystem (`win32k.sys`) are not supported.
- Tested on Visual Studio 2019/2022 with Windows 10 SDK. 
- Support for NASM is not guaranteed.
- Support for GCC and MinGW is not guaranteed.

## Troubleshooting

#### From SysWhispers2
- Type redefinitions errors: a project may not compile if typedefs in `syscalls.h` have already been defined.
  - Ensure that only required functions are included (i.e. `--preset all` is rarely necessary).
  - If a typedef is already defined in another used header, then it could be removed from `syscalls.h`.

#### New
- With `--verbose`, it is possible to enable troubleshooting output during code generation.
- With `--debug`, the tool will insert a software breakpoint in the syscall stub, to ease the debugging in WinDbg.
- With `--standalone`, the tool will generate a single header file for easier integration in other projects.
- If you get a `error A2084:constant value too large` during compilation, regenerates the stubs.
