#include "<BASENAME>.h"
#include <stdio.h>

#define DEBUG

// JUMPER

// <X86>

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif


DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
ULONG_PTR SC_Offset(ULONG_PTR SyscallAddress) {
    return (ULONG_PTR)0;
}
#else
ULONG_PTR SC_Offset(ULONG_PTR SyscallAddress) {

    return (ULONG_PTR)0;
    unsigned char SyscallOpcode = 0x01;
    DWORD SyscallOpcodeOffset = 0;
  #ifdef x32
    SIZE_T nBytesRead;
  #else
    size_t nBytesRead;
  #endif
    DWORD searchLimit = 512;
    int found = 0;


  #ifdef x32
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    int sys_call_or_enter = 0x34;

    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    // Thanks @S4ntiagoP and nanodump for the hint :D
    if (local_is_wow64())
    {
    #ifdef DEBUG
    printf("[+] Running 32-bit app on x64 (WOW64)\n");
    #endif

        // if we are a WoW64 process, jump to WOW32Reserved
        SyscallAddress = (PVOID)__readfsdword(0xc0);
        return SyscallAddress;
    }

  #else
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    int sys_call_or_enter = 0x05;
  #endif
    while (found != 1 && SyscallOpcodeOffset <= searchLimit){
        while (!(SyscallOpcode == 0x0f)){
            SyscallOpcodeOffset++;
            ReadProcessMemory((HANDLE)-1, SyscallAddress + SyscallOpcodeOffset, &SyscallOpcode, 1, &nBytesRead);
        }
        ReadProcessMemory((HANDLE)-1, SyscallAddress + SyscallOpcodeOffset + 1, &SyscallOpcode, 1, &nBytesRead);
        if (!(SyscallOpcode == sys_call_or_enter)) {
            continue;
        }
        ReadProcessMemory((HANDLE)-1, SyscallAddress + SyscallOpcodeOffset + 2, &SyscallOpcode, 1, &nBytesRead);
        if (!(SyscallOpcode == 0xc3)) {
            continue;
        }
        found = 1;
    }

  #ifdef DEBUG
    #ifndef x32
        printf("Found Syscall Opcodes at address 0x%016llx\n", SyscallAddress + SyscallOpcodeOffset);
    #else
        printf("Found Syscall Opcodes at address 0x%08lx\n", SyscallAddress + SyscallOpcodeOffset);
    #endif
  #endif
    return (ULONG_PTR)(SyscallAddress + SyscallOpcodeOffset);
}

#endif


BOOL SW2_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)<PEB>;
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallOffset = SC_Offset(SW2_RVA2VA(ULONG_PTR, DllBase, Entries[i].Address));

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallOffset = Entries[j].SyscallOffset;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallOffset = Entries[j + 1].SyscallOffset;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallOffset = TempEntry.SyscallOffset;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

#ifdef x32
EXTERN_C ULONG32 SW2_GetSyscallOffset(DWORD FunctionHash)
#else
EXTERN_C ULONG64 SW2_GetSyscallOffset(DWORD FunctionHash)
#endif
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
#ifdef x32
            return (ULONG32) SW2_SyscallList.Entries[i].SyscallOffset;
#else
            return (ULONG64) SW2_SyscallList.Entries[i].SyscallOffset;
#endif
        }
    }

    return -1;
}

#ifdef x32
EXTERN_C ULONG32 SW2_GetRandomSyscallOffset(DWORD FunctionHash)
#else
EXTERN_C ULONG64 SW2_GetRandomSyscallOffset(DWORD FunctionHash)
#endif
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    DWORD index = ((DWORD) rand()) % SW2_SyscallList.Count;

    while (FunctionHash == SW2_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW2_SyscallList.Count;
    }
#ifdef x32
    return (ULONG64) SW2_SyscallList.Entries[index].SyscallOffset;
#else
    return (ULONG32) SW2_SyscallList.Entries[index].SyscallOffset;
#endif
}
