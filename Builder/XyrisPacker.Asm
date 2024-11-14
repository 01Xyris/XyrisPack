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

includelib kernel32.lib
includelib user32.lib
includelib Comctl32.lib
includelib shell32.lib
includelib comdlg32.lib
includelib shlwapi.lib

IDC_BTNPACK      equ 1004
IDC_EDITPATH     equ 1003
IDC_BTNOPEN      equ 1005

DlgProc PROTO :HWND, :UINT, :WPARAM, :LPARAM

.const
    IDD_DIALOG1    equ 101

.data
    szFilter       db "Executable Files (*.exe)", 0, "*.exe", 0, 0
    ofn            OPENFILENAME <>
    sfn            OPENFILENAME <>
    szFile         db 260 dup(0)
    szSaveFile     db 260 dup(0)
    szFileName     db 260 dup(0)
    szQuote        db '"', 0
    szExe          db ".exe", 0
    szCmdLine      db "XyrisPacker.CLI.exe --file ", 0
    szStub         db " --stub stub.bin", 0
    szOutput       db ' --output "', 0
    szStartup1     db " --startup 1", 0
    szStartup0     db " --startup 0", 0
    szUnhook1      db " --unhook 1", 0
    szUnhook0      db " --unhook 0", 0
    szDelay1       db " --delay 1", 0
    szDelay0       db " --delay 0", 0
    szAntiDump1    db " --antidump 1", 0
    szAntiDump0    db " --antidump 0", 0
    szQuoteEnd     db '"', 0
    szCommand      db 2048 dup(0)
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

.data?
    hInstance      dd ?
    hWnd           dd ?

.code
start:
    invoke GetModuleHandle, NULL
    mov hInstance, eax
    invoke InitCommonControls
    invoke DialogBoxParam, hInstance, IDD_DIALOG1, NULL, addr DlgProc, NULL
    invoke ExitProcess, 0

DlgProc proc hWin:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    LOCAL wID:WORD
    
    mov eax, uMsg
    .if eax == WM_INITDIALOG
        push hWin
        pop hWnd
        
    .elseif eax == WM_COMMAND
        mov eax, wParam
        mov wID, ax
        
        .if wID == IDC_BTNOPEN
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
                    invoke GetCurrentDirectory, 260, addr szCurrentDir
                    
                    invoke lstrcpy, addr szCommand, addr szCmdLine
                    invoke lstrcat, addr szCommand, addr szQuote
                    invoke lstrcat, addr szCommand, addr szFile
                    invoke lstrcat, addr szCommand, addr szQuote
                    invoke lstrcat, addr szCommand, addr szStub
                    
                
                    invoke IsDlgButtonChecked, hWin, 1007  
                    .if eax == BST_CHECKED
                        invoke lstrcat, addr szCommand, addr szStartup1
                    .else
                        invoke lstrcat, addr szCommand, addr szStartup0
                    .endif
                    
                  
                    invoke IsDlgButtonChecked, hWin, 1008  
                    .if eax == BST_CHECKED
                        invoke lstrcat, addr szCommand, addr szUnhook1
                    .else
                        invoke lstrcat, addr szCommand, addr szUnhook0
                    .endif
                    
                  
                    invoke IsDlgButtonChecked, hWin, 1009  
                    .if eax == BST_CHECKED
                        invoke lstrcat, addr szCommand, addr szDelay1
                    .else
                        invoke lstrcat, addr szCommand, addr szDelay0
                    .endif
                    
                   
                    invoke IsDlgButtonChecked, hWin, 1010  
                    .if eax == BST_CHECKED
                        invoke lstrcat, addr szCommand, addr szAntiDump1
                    .else
                        invoke lstrcat, addr szCommand, addr szAntiDump0
                    .endif
                    
                    invoke lstrcat, addr szCommand, addr szOutput
                    invoke lstrcat, addr szCommand, addr szSaveFile
                    invoke lstrcat, addr szCommand, addr szQuoteEnd
                    
                    invoke RtlZeroMemory, addr startInfo, sizeof STARTUPINFO
                    mov startInfo.cb, sizeof STARTUPINFO
                    
                    invoke GetModuleFileName, NULL, addr szWorkingDir, 260
                    invoke PathRemoveFileSpec, addr szWorkingDir
                    
                    invoke CreateProcess, NULL, addr szCommand, NULL, NULL, FALSE, NULL, NULL, addr szWorkingDir, addr startInfo, addr procInfo
                    
                    invoke CloseHandle, procInfo.hProcess
                    invoke CloseHandle, procInfo.hThread
                    invoke SetCurrentDirectory, addr szCurrentDir
                    
                    invoke lstrcpy, addr szSuccessMsg, addr szSuccess
                    invoke lstrcat, addr szSuccessMsg, addr szSaveFile
                    invoke MessageBox, hWin, addr szSuccessMsg, addr szSuccessCaption, MB_ICONINFORMATION
                .endif
            .endif
        .endif
        
    .elseif eax == WM_CLOSE
        invoke EndDialog, hWin, 0
    .else
        mov eax, FALSE
        ret
    .endif
    mov eax, TRUE
    ret
DlgProc endp
end start
