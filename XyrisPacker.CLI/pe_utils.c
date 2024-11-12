#define _CRT_SECURE_NO_WARNINGS
#include "pe_utils.h"
#include <stdio.h>

DWORD align_to(DWORD value, DWORD alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

BOOL find_and_replace(HANDLE hFile, const char* key) {
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) return FALSE;

    LPVOID fileData = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!fileData) {
        CloseHandle(hMapping);
        return FALSE;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    BOOL found = FALSE;

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".data", 5) == 0) {
            BYTE* sectionData = (BYTE*)fileData + section[i].PointerToRawData;
            DWORD sectionSize = section[i].SizeOfRawData;

            printf("Searching .data section at offset 0x%08X, size: %d bytes\n",
                section[i].PointerToRawData, sectionSize);

            for (DWORD j = 0; j < sectionSize - 6; j++) {
                if (memcmp(sectionData + j, "SECRET", 6) == 0) {
                    printf("Found SECRET in .data at offset: 0x%08X\n",
                        section[i].PointerToRawData + j);
                    memcpy(sectionData + j, key, 6);
                    found = TRUE;
                    break;
                }
            }
            break;
        }
    }

    FlushViewOfFile(fileData, 0);
    UnmapViewOfFile(fileData);
    CloseHandle(hMapping);
    return found;
}

int add_section(const char* stub_path, const char* section_name, const unsigned char* data, size_t data_len) {
    HANDLE hFile = CreateFileA(stub_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return -1;
    }

    LPVOID fileData = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!fileData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -1;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER lastSection = &sections[ntHeaders->FileHeader.NumberOfSections - 1];

    DWORD alignedDataSize = align_to((DWORD)data_len, ntHeaders->OptionalHeader.FileAlignment);
    DWORD alignedVirtualSize = align_to((DWORD)data_len, ntHeaders->OptionalHeader.SectionAlignment);

    IMAGE_SECTION_HEADER newSection = { 0 };
    strncpy((char*)newSection.Name, section_name, IMAGE_SIZEOF_SHORT_NAME);
    newSection.Misc.VirtualSize = data_len;
    newSection.VirtualAddress = align_to(lastSection->VirtualAddress + lastSection->Misc.VirtualSize,
        ntHeaders->OptionalHeader.SectionAlignment);
    newSection.SizeOfRawData = alignedDataSize;
    newSection.PointerToRawData = align_to(lastSection->PointerToRawData + lastSection->SizeOfRawData,
        ntHeaders->OptionalHeader.FileAlignment);
    newSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    ntHeaders->FileHeader.NumberOfSections++;
    ntHeaders->OptionalHeader.SizeOfImage = align_to(newSection.VirtualAddress + alignedVirtualSize,
        ntHeaders->OptionalHeader.SectionAlignment);

    memcpy(&sections[ntHeaders->FileHeader.NumberOfSections - 1], &newSection, sizeof(IMAGE_SECTION_HEADER));

    UnmapViewOfFile(fileData);
    CloseHandle(hMapping);

    SetFilePointer(hFile, newSection.PointerToRawData + alignedDataSize, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);

    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return -1;
    }

    fileData = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (!fileData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return -1;
    }

    memcpy((BYTE*)fileData + newSection.PointerToRawData, data, data_len);

    if (alignedDataSize > data_len) {
        ZeroMemory((BYTE*)fileData + newSection.PointerToRawData + data_len,
            alignedDataSize - data_len);
    }

    FlushViewOfFile(fileData, 0);
    UnmapViewOfFile(fileData);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}