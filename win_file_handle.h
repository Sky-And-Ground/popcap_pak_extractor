#ifndef __PAK_WIN_FILE_HANDLE_H__
#define __PAK_WIN_FILE_HANDLE_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <system_error>

class WinFile {
    HANDLE handle = INVALID_HANDLE_VALUE;
public:
    WinFile() = default;
    
    WinFile(const std::string& filePath, DWORD desiredAccess, DWORD creationDisposition) {
        handle = CreateFileA(filePath.data(), desiredAccess, 0, nullptr, creationDisposition, FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (handle == INVALID_HANDLE_VALUE) {
            std::error_code ec{ (int)GetLastError(), std::system_category() };
            throw std::system_error{ ec, "CreateFileA failed" };
        }
    }
    
    ~WinFile() {
        clear();
    }
    
    WinFile(const WinFile&) = delete;
    WinFile& operator=(const WinFile&) = delete;
    
    WinFile(WinFile&& other) noexcept : handle{ other.handle } {
        other.handle = INVALID_HANDLE_VALUE;
    }
    
    WinFile& operator=(WinFile&& other) noexcept {
        if (this != &other) {
            clear();
            handle = other.handle;
            other.handle = INVALID_HANDLE_VALUE;
        }
        
        return *this;
    }
    
    void clear() noexcept {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }

    DWORD read(char* buf, DWORD numOfBytesToRead) {
        DWORD numOfBytesRead;

        if (!ReadFile(handle, (LPVOID)buf, numOfBytesToRead, &numOfBytesRead, nullptr)) {
            std::error_code ec{ (int)GetLastError(), std::system_category() };
            throw std::system_error{ ec, "ReadFile failed" };
        }

        return numOfBytesRead;
    }
    
    void write(const char* buf, DWORD numOfBytesToWrite) {
        if (!WriteFile(handle, buf, numOfBytesToWrite, nullptr, nullptr)) {
            std::error_code ec{ (int)GetLastError(), std::system_category() };
            throw std::system_error{ ec, "WriteFile failed" };
        }
    }
    
    void set_file_time(const FILETIME& ft) {
        if (!SetFileTime(handle, nullptr, nullptr, &ft)) {
            std::error_code ec{ (int)GetLastError(), std::system_category() };
            throw std::system_error{ ec, "SetFileTime failed" };
        }
    }
    
    DWORD get_file_size() {
        DWORD fileSize = GetFileSize(handle, nullptr);
        
        if (fileSize == INVALID_FILE_SIZE) {
            std::error_code ec{ (int)GetLastError(), std::system_category() };
            throw std::system_error{ ec, "GetFileSize failed" };
        }

        return fileSize;
    }
};

#endif