
Decrypt PROTO section:DWORD, size_var:DWORD, outBuffer:DWORD

.CODE

Decrypt PROC uses eax esi edi ebx section:DWORD, size_var:DWORD, outBuffer:DWORD
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
Decrypt ENDP
