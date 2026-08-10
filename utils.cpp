#include "utils.h"
#include <ctime>

std::string format_windows_filetime(const FILETIME& ft) {
    char buf[32];
    ULARGE_INTEGER ull;
    
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    
    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 1000'0000ULL) - 116'4447'3600ULL);
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", timeinfo);
    return std::string{ buf };
}