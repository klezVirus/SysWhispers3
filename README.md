:triangular_flag_on_post: This is the public repository of SysWhispers3, for latest version and updates please consider supporting us through https://porchetta.industries/

# SysWhispers3

SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls.

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on SysWhispers3, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)

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
* Can be used as a python library `pip3 install syswhispers3`

A better explanation of these features are better outlined i the blog post [SysWhispers is dead, long live SysWhispers!][2]

## Introduction

Security products, such as AVs and EDRs, usually place hooks in user-mode API functions to analyse a program execution 
flow, in order to detect potentially malicious activities.

SysWhispers2 is a tool designed to generate header/ASM pairs for any system call in the core kernel image 
(`ntoskrnl.exe`), which can then be integrated and called directly from C/C++ code, evading user-lands hooks. 

The tool, however, generates some patters which can be included in signatures, or behaviour which can be detected 
at runtime.

SysWhispers3 is built on top of SysWhispers2, and integrates some helpful features to bypass these forms of detection.

## Documentation

Most of the questions you would ask are probably in the documentation. Please **[READ THE DOC](https://klezVirus.github.io/SysWhispers3/)**

## Install
In order to use it as a python module
```bash
pip3 install --save syswhispers3
```

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


## Credits

#### SysWhispers2

Developed by [@Jackson_T](https://twitter.com/Jackson_T) and [@modexpblog](https://twitter.com/modexpblog), 
but builds upon the work of many others:

- [@FoxHex0ne](https://twitter.com/FoxHex0ne) for cataloguing many function prototypes and typedefs in a machine-readable format.
- [@PetrBenes](https://twitter.com/PetrBenes), [NTInternals.net team](https://undocumented.ntinternals.net/), and [MSDN](https://docs.microsoft.com/en-us/windows/) for additional prototypes and typedefs.
- [@Cn33liz](https://twitter.com/Cneelis) for the initial [Dumpert](https://github.com/outflanknl/Dumpert) POC implementation.

#### SysWhispers2 (x86/WOW64)

- [@rooster](https://github.com/mai1zhi2) for creating a sample x86/WOW64 compatible fork.

#### Others

- [@ElephantSe4l](https://mobile.twitter.com/elephantse4l) for the idea about randomizing the jumps to the syscalls.
- [@S4ntiagoP](https://twitter.com/s4ntiago_p) for the incredible work on [nanodump](https://github.com/helpsystems/nanodump), which gave me tons of ideas.

## Licence

As the original, this project is also licensed under the Apache License 2.0.


[1]: https://github.com/klezVirus/inceptor
[2]: https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/
