#include "utils.h"

bool is_file_exists(const char* path) {
    DWORD attrs = GetFileAttributes(path);
    
    return (attrs != INVALID_FILE_ATTRIBUTES) && 
           !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool is_directory_exists(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

time_t filetime_to_unix_timestamp(FILETIME ft) {
    ULARGE_INTEGER ull;

    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        ull.QuadPart accurates to 10 ^ -7 seconds.
    */
    return (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
}