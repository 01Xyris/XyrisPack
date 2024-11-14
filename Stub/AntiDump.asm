
AntiDump PROTO

.CODE
AntiDump PROC
    LOCAL BaseAddress:DWORD
    LOCAL OldProtect:DWORD
    LOCAL PEHeader:DWORD
    LOCAL SizeOfHeaders:DWORD
     invoke lstrcmp, addr antidump_check, addr sz_antidump_check
	.if eax == -1
    	ret
	.endif

    invoke GetModuleHandle, NULL
    mov BaseAddress, eax
    mov eax, BaseAddress
    add eax, 3Ch        
    mov eax, [eax]
    add eax, BaseAddress
    mov PEHeader, eax
    
    mov eax, PEHeader
    add eax, 54h        
    mov eax, [eax]
    mov SizeOfHeaders, eax
    
    invoke VirtualProtect, BaseAddress, SizeOfHeaders, PAGE_READWRITE, addr OldProtect
    test eax, eax
    jz @exit
    
    mov eax, PEHeader
    add eax, 8
    mov dword ptr [eax], 0
    
    add eax, 20h
    mov dword ptr [eax], 0
    
    mov eax, PEHeader
    add eax, 74h
    mov dword ptr [eax], 0
    
    mov eax, PEHeader
    add eax, 0F8h       ;
    mov dword ptr [eax+24h], 0  
    

    mov eax, PEHeader
    add eax, 0A8h      
    mov dword ptr [eax], 0
    
    
    mov eax, PEHeader
    add eax, 78h        
    mov dword ptr [eax], 0
    
   
    invoke VirtualProtect, BaseAddress, SizeOfHeaders, [OldProtect], addr OldProtect
    
@exit:
    ret
AntiDump ENDP