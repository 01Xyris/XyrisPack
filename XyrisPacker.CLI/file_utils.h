#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <stddef.h> 

char* create_stub_key(const char* original_path, const char* key);
char* create_final(const char* keyed_exe_path, const char* section_name,
    const unsigned char* data, size_t data_len);

#endif 