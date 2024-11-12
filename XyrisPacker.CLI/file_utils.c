#define _CRT_SECURE_NO_WARNINGS
#include "file_utils.h"
#include "pe_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stddef.h> 

char* create_stub_key(const char* original_path, const char* key) {
    const char* suffix = "_keyed.exe";
    char* new_path = (char*)malloc(strlen(original_path) + strlen(suffix) + 1);
    if (!new_path) return NULL;

    strcpy(new_path, original_path);
    char* dot = strrchr(new_path, '.');
    if (dot) *dot = '\0';
    strcat(new_path, suffix);

    printf("Creating keyed copy: %s\n", new_path);
    printf("Key to insert: %s\n", key);

    if (!CopyFileA(original_path, new_path, FALSE)) {
        printf("Failed to create file copy: %lu\n", GetLastError());
        free(new_path);
        return NULL;
    }

    HANDLE hFile = CreateFileA(new_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open keyed copy for modification\n");
        free(new_path);
        return NULL;
    }

    if (!find_and_replace(hFile, key)) {
        printf("Failed to find SECRET in .data section\n");
        CloseHandle(hFile);
        DeleteFileA(new_path);
        free(new_path);
        return NULL;
    }

    CloseHandle(hFile);
    return new_path;
}

char* create_final(const char* keyed_exe_path, const char* section_name,
    const unsigned char* data, size_t data_len) {
    size_t base_len = strlen(keyed_exe_path) - strlen("_keyed.exe");
    char* final_path = (char*)malloc(base_len + strlen("_packed.exe") + 1);
    if (!final_path) return NULL;

    strncpy(final_path, keyed_exe_path, base_len);
    final_path[base_len] = '\0';
    strcat(final_path, "_packed.exe");

    printf("\nCreating final copy: %s\n", final_path);
    printf("Source file: %s\n", keyed_exe_path);

    if (!CopyFileA(keyed_exe_path, final_path, FALSE)) {
        printf("Failed to create final copy: %lu\n", GetLastError());
        free(final_path);
        return NULL;
    }

    if (add_section(final_path, section_name, data, data_len) != 0) {
        printf("Failed to add section\n");
        DeleteFileA(final_path);
        free(final_path);
        return NULL;
    }

    return final_path;
}