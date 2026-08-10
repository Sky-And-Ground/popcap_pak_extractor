#ifndef __PAK_UTILS_H__
#define __PAK_UTILS_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

std::string format_windows_filetime(const FILETIME& ft);

#endif