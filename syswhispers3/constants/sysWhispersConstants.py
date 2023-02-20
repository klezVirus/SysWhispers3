# -*- coding:utf-8 -*-

import os
from syswhispers3.utils import get_project_root

class SysWhispersConstants:
    """Simple class used to store SysWhispers constants
    """
    SYSWHISPERS_DATA_PATH = os.path.join("syswhispers3","data")
    COMMON_SYSCALLS = [
        'NtCreateProcess',
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
        'NtWaitForSingleObject',
        'NtWaitForMultipleObjects'
    ]