// pe_utils.h
#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <windows.h>

// Function declarations for PE file operations
DWORD align_to(DWORD value, DWORD alignment);
BOOL find_and_replace(HANDLE hFile, const char* key, BOOL startup, BOOL unhook, BOOL antidump, BOOL delay);
int add_section_to_pe(const char* stub_path, const char* section_name, const unsigned char* data, size_t data_len);

#endif // PE_UTILS_H