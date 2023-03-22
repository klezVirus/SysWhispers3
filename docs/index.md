# SysWhispers3

SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on SysWhispers3, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)

---

### Why on earth didn't I create a PR to SysWhispers2?

The reason for SysWhispers3 to be a standalone version are many, but the most important are:

* SysWhispers3 is the de-facto "fork" used by [Inceptor][1], and implements some utils class which are not relevant to the 
  original version of the tool.
* SysWhispers2 is moving towards supporting NASM compilation (for gcc/mingw), while this version is specifically designed and 
  tested to support MSVC (because [Inceptor][1] will stay a Windows-only framework for the near future).
* SysWhispers3 contains partially implemented features (such as egg-hunting) which would not be sensible to include
  in the original version of the tool.

## Differences with SysWhispers2

The usage is pretty similar to [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), with the following exceptions:

* It also supports x86/WoW64
* It supports syscalls instruction replacement with an EGG (to be dynamically replaced)
* It supports direct jumps to syscalls in x86/x64 mode (in WOW64 it's almost standard)
* It supports direct jumps to random syscalls (borrowing [@ElephantSeal's idea](https://twitter.com/ElephantSe4l/status/1488464546746540042))
* It supports standalone file (xxx.h) generation for use with external framework

A better explanation of these features are better outlined i the blog post [SysWhispers is dead, long live SysWhispers!][2]

## Introduction

Security products, such as AVs and EDRs, usually place hooks in user-mode API functions to analyse a program execution 
flow, in order to detect potentially malicious activities.

SysWhispers2 is a tool designed to generate header/ASM pairs for any system call in the core kernel image 
(`ntoskrnl.exe`), which can then be integrated and called directly from C/C++ code, evading user-lands hooks. 

The tool, however, generates some patters which can be included in signatures, or behaviour which can be detected 
at runtime.

SysWhispers3 is built on top of SysWhispers2, and integrates some helpful features to bypass these forms of detection.

## Main topics
- [Contribute](contribute/installation)
- [Installation](install/installation)
- [Documentation](documentation/)

## Usage and Examples

The help shows all the available commands and features of the tool:

```
C:\>python syswhispers.py -h
                                                       
                  .                         ,--.       
,-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/       
`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \      
`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''       
     /|                     |  @Jackson_T              
    `-'                     '  @modexpblog, 2021       

                      Edits by @klezVirus,  2022       
                      Edits by     @x42en,  2023       
SysWhispers3: Why call the kernel when you can whisper?


usage: syswhispers.py [-h] [-p PRESET] [-a {x86,x64,all}] [-c {msvc,mingw,all}] [-m {embedded,egg_hunter,jumper,jumper_randomized}] [-f FUNCTIONS] -o OUT_FILE [--int2eh] [--wow64] [-s] [-q | -v | -d]

SysWhispers3 - SysWhispers on steroids

options:
  -h, --help            show this help message and exit
  -p PRESET, --preset PRESET
                        Preset ("all", "common")
  -a {x86,x64,all}, --arch {x86,x64,all}
                        Architecture (default: x64)
  -c {msvc,mingw,all}, --compiler {msvc,mingw,all}
                        Compiler (default: msvc)
  -m {embedded,egg_hunter,jumper,jumper_randomized}, --method {embedded,egg_hunter,jumper,jumper_randomized}
                        Syscall recovery method (default: embedded)
  -f FUNCTIONS, --functions FUNCTIONS
                        Comma-separated functions
  -o OUT_FILE, --out-file OUT_FILE
                        Output basename (w/o extension)
  --int2eh              Use the old `int 2eh` instruction in place of `syscall`
  --wow64               Add support for WoW64, to run x86 on x64
  -s, --standalone      Generate a single header file
  -q, --quiet           Disable all output
  -v, --verbose         Enable debug output
  -d, --debug           Enable debug output and syscall debug (insert software breakpoint)
```

### Command Lines

#### Standard SysWhispers, embedded system calls (x64)

```powershell
# Export all functions with compatibility for all supported Windows versions (see example-output/).
py .\syswhispers.py --preset all -o syscalls_all

# Export just the common functions (see below for list).
py .\syswhispers.py --preset common -o syscalls_common

# Export NtProtectVirtualMemory and NtWriteVirtualMemory with compatibility for all versions.
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem

# Export NtProtectVirtualMemory and NtWriteVirtualMemory in a standalone file (syscalls_mem.h) with compatibility for all versions.
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem -s
```

#### SysWhispers3-only samples 

```powershell
# Normal SysWhispers, 32-bits mode
py .\syswhispers.py --preset all -o syscalls_all -m jumper --arch x86

# Normal SysWhispers, using WOW64 in 32-bits mode (only specific functions)
py .\syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory -o syscalls_mem --arch x86 --wow64

# Egg-Hunting SysWhispers, to bypass the "mark of the sycall" (common function)
py .\syswhispers.py --preset common -o syscalls_common -m egg_hunter

# Jumping/Jumping Randomized SysWhispers, to bypass dynamic RIP validation (all functions) using MinGW as the compiler
py .\syswhispers.py --preset all -o syscalls_all -m jumper -c mingw

# Jumping Randomized SysWhispers, to bypass dynamic RIP validation (common functions) using MinGW as the compiler and all in one standalone file (syscalls_common.h)
py .\syswhispers.py --preset common -o syscalls_common -m jumper_randomized -c mingw -s
```

### Script Output

```
PS C:\Projects\SysWhispers2> py .\syswhispers.py --preset common --out-file temp\syscalls_common -v 
                                                       
                  .                         ,--.       
,-. . . ,-. . , , |-. o ,-. ,-. ,-. ,-. ,-.  __/       
`-. | | `-. |/|/  | | | `-. | | |-' |   `-. .  \      
`-' `-| `-' ' '   ' ' ' `-' |-' `-' '   `-'  '''       
     /|                     |  @Jackson_T              
    `-'                     '  @modexpblog, 2021       

                      Edits by @klezVirus,  2022       
                      Edits by     @x42en,  2023       
SysWhispers3: Why call the kernel when you can whisper?


Common functions selected.

Complete! Files written to:
        temp\syscalls_common.h
        temp\syscalls_common.c
        temp\syscalls_common_.asm
Press a key to continue...

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
