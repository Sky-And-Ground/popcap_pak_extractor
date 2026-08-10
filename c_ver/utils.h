#ifndef __UTILS_H__
#define __UTILS_H__

#include <windows.h>
#include <stdbool.h>
#include <time.h>

bool is_file_exists(const char* path);
bool is_directory_exists(const char* path);

/* convert windows platform's FILETIME structure to a unix timestamp. */
time_t filetime_to_unix_timestamp(FILETIME ft);

#endif