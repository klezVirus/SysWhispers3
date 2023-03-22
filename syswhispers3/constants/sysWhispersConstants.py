# -*- coding:utf-8 -*-

from syswhispers3.utils import get_project_root


class SysWhispersConstants:
    """Simple class used to store SysWhispers constants"""

    SYSWHISPERS_KEY_LEN = 23
    DONUT_SYSCALLS = [
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtContinue",
        "NtClose",
        "NtWaitForSingleObject",
        "NtProtectVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtCreateFile",
        "NtGetContextThread",
        "NtFreeVirtualMemory",
        "NtQueryVirtualMemory",
        "NtCreateThreadEx",
        "NtFlushInstructionCache",
    ]
    COMMON_SYSCALLS = [
        "NtCreateProcess",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtOpenProcessToken",
        "NtTestAlert",
        "NtOpenThread",
        "NtSuspendProcess",
        "NtSuspendThread",
        "NtResumeProcess",
        "NtResumeThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtClose",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtQuerySystemInformation",
        "NtQueryDirectoryFile",
        "NtQueryInformationFile",
        "NtQueryInformationProcess",
        "NtQueryInformationThread",
        "NtCreateSection",
        "NtOpenSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtAdjustPrivilegesToken",
        "NtDeviceIoControlFile",
        "NtQueueApcThread",
        "NtWaitForSingleObject",
        "NtWaitForMultipleObjects",
    ]
    JUMPER_SYSCALL_RECOVERY = """
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}
"""
    JUMPER_RANDOMIZED_SYSCALL_RECOVERY = """
EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

    while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW3_SyscallList.Count;
    }
    return SW3_SyscallList.Entries[index].SyscallAddress;
}
"""
    EGG_HUNTER_SEARCH_REPLACE = """
#ifdef SEARCH_AND_REPLACE
EXTERN void SearchAndReplace(unsigned char egg[], unsigned char replace[]){
    return NULL;
};
#endif
"""