/**
 * @author yuan
 * @brief PopCap's .pak file extractor, written in C++17, only works for windows platform.
 * 
 * a very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs for giving 
 * the popcap .pak file's format:
 * 
 * Header 
 *   4 bytes - Magic (Should be [0xc0, 0x4a, 0xc0, 0xba])
 *   4 bytes - Version (Should be all 0) 
 *   loop 
 *       1 byte  - Record Flag (exit loop if 0x80)
 *       1 byte  - File name length (N) 
 *       N bytes - Filename 
 *       4 bytes - Filesize (u32)
 *       4 bytes - Last write time (Microsoft FILETIME struct)
 *   end
 *
 * Body
 *   for each record
 *       record.filesize bytes - File data
 *   end
 * 
*/
#ifndef _WIN32
#error "this program only works for windows platform"
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <system_error>
#include <filesystem>
#include <string>
#include <memory>
#include <vector>
#include <array>
#include <utility>
#include <cstdint>
#include <ctime>

namespace fs = std::filesystem;

namespace parser {
    class ParserError : public std::runtime_error {
    public:
        ParserError(const std::string& msg) : std::runtime_error{ msg } {}
    };

    class FileNotFoundException : public ParserError {
    public:
        FileNotFoundException(const std::string& filePath) : ParserError{ filePath + " not found" } {}
    };

    class InvalidMagicException : public ParserError {
    public:
        InvalidMagicException() : ParserError{ "invalid magic field" } {}
    };

    class InvalidVersionException : public ParserError {
    public:
        InvalidVersionException() : ParserError{ "invalid version field" } {}
    };

    class UnexpectedEndOfFileException : public ParserError {
    public:
        UnexpectedEndOfFileException() : ParserError{ "file maybe broken" } {}
    };

    class WinFile {
        HANDLE handle;
    public:
        WinFile() : handle{ INVALID_HANDLE_VALUE } {}

        WinFile(const std::string& filePath, DWORD desiredAccess, DWORD creationDisposition) {
            handle = CreateFileA(filePath.data(), desiredAccess, 0, nullptr, creationDisposition, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (handle == INVALID_HANDLE_VALUE) {
                std::error_code ec{ (int)GetLastError(), std::system_category() };
                throw std::system_error{ ec, "CreateFileA failed on " + filePath };
            }
        }

        ~WinFile() {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }

        WinFile(const WinFile&) = delete;
        WinFile& operator=(const WinFile&) = delete;

        WinFile(WinFile&& other) : handle{ other.handle } {
            other.handle = INVALID_HANDLE_VALUE;
        }

        WinFile& operator=(WinFile&& other) {
            if (this != &other) {
                if (handle != INVALID_HANDLE_VALUE) {
                    CloseHandle(handle);
                }

                handle = other.handle;
                other.handle = INVALID_HANDLE_VALUE;
            }

            return *this;
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

    struct FileAttr {
        std::unique_ptr<char[]> fileName;
        DWORD fileSize;
        FILETIME lastWriteTime;
    };

    class Parser {
        std::vector<FileAttr> fileAttrs;
        WinFile pak;
        DWORD pakSize;

        std::unique_ptr<char[]> create_buffer(size_t size) {
            return std::make_unique<char[]>(size);
        }

        void read_from_pak(char* buf, DWORD bytesToRead) {
            if (pakSize < bytesToRead) {
                throw UnexpectedEndOfFileException{};
            }

            DWORD total = bytesToRead;

            while (total > 0) {
                DWORD read = pak.read(buf, total);

                buf += read;
                total -= read;
            }

            // decode them.
            for (DWORD i = 0; i < bytesToRead; ++i) {
                buf[i] = ((unsigned char)buf[i]) ^ 0xf7;
            }

            pakSize -= bytesToRead;
        }

        bool reach_header_end() {
            UCHAR c;

            read_from_pak((char*)(&c), sizeof(c));
            return c == 0x80;
        }

        void parse_magic() {
            std::array<UCHAR, 4> magic;

            read_from_pak((char*)magic.data(), magic.size());

            bool check_magic = magic[0] == 0xC0 
                            && magic[1] == 0x4A 
                            && magic[2] == 0xC0 
                            && magic[3] == 0xBA;

            if (!check_magic) {
                throw InvalidMagicException{};
            }
        }

        void parse_version() {
            std::array<UCHAR, 4> version;

            read_from_pak((char*)version.data(), version.size());

            bool check_version = version[0] == 0x00 
                            && version[1] == 0x00 
                            && version[2] == 0x00 
                            && version[3] == 0x00;

            if (!check_version) {
                throw InvalidVersionException{};
            }
        }

        void parse_file_name(FileAttr& attr) {
            char c;

            read_from_pak(&c, sizeof(char));

            // get the length of the file name.
            uint32_t fileNameLen = (uint32_t)c;
            attr.fileName = create_buffer(fileNameLen + 1);

            // get file name.
            read_from_pak(attr.fileName.get(), fileNameLen);
            attr.fileName[fileNameLen] = '\0';
        }

        void parse_file_size(FileAttr& attr) {
            read_from_pak((char*)(&(attr.fileSize)), sizeof(attr.fileSize));
        }

        void parse_file_last_write_time(FileAttr& attr) {
            read_from_pak((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
        }

        void save_single_file(const FileAttr& attr, char* buf, size_t buffer_size, const fs::path& p) {
            DWORD fileSize = attr.fileSize;
            DWORD needLen = 0;
            
            WinFile tmpFile { p.string(), GENERIC_WRITE, CREATE_NEW };

            while (fileSize > 0) {
                needLen = (fileSize < buffer_size ? fileSize : buffer_size);

                read_from_pak(buf, needLen);
                tmpFile.write(buf, needLen);

                fileSize -= needLen;
            }

            tmpFile.set_file_time(attr.lastWriteTime);
        }
    public:
        Parser(const std::string& filePath) 
            : fileAttrs{}, pak{ filePath, GENERIC_READ, OPEN_EXISTING }, pakSize{ INVALID_FILE_SIZE } 
        {
            pakSize = pak.get_file_size();
        }

        const std::vector<FileAttr>& get_file_attrs() const noexcept {
            return fileAttrs;
        }

        // this function would throw ParseError or std::system_error.
        void parse_header() {
            parse_magic();
            parse_version();

            while (true) {
                if (reach_header_end()) {
                    return;
                }

                FileAttr attr;

                parse_file_name(attr);
                parse_file_size(attr);
                parse_file_last_write_time(attr);
                
                fileAttrs.emplace_back(std::move(attr));
            }
        }

        // this function would throw ParseError or std::system_error.
        void save_body(const std::string& toDir) {
            const size_t buffer_size = 65536;
            std::unique_ptr<char[]> buf = create_buffer(buffer_size);

            for (const FileAttr& attr : fileAttrs) {
                fs::path p{ toDir };
                p.append(attr.fileName.get());

                fs::path parentDir = p.parent_path();
                if (!fs::exists(parentDir)) {
                    fs::create_directories(parentDir);
                }

                save_single_file(attr, buf.get(), buffer_size, p);
            }
        }
    };
};

const char* format_windows_filetime(const FILETIME& ft, char* buf, size_t buf_size) {
    ULARGE_INTEGER ull;
    
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attrs(const std::vector<parser::FileAttr>& attrs, const std::string& savFile) {
    std::ofstream out{ savFile };
    char buf[32];

    for (const parser::FileAttr& attr : attrs) {
        out << format_windows_filetime(attr.lastWriteTime, buf, std::size(buf)) << "  " << std::setw(10) << attr.fileSize << " bytes  " << attr.fileName.get() << "\n";
    }

    out.close();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <.pak> <sav_dir>\n";
        return 1;
    }

    if (fs::is_directory(argv[2])) {
        std::cerr << "dir: " << argv[2] << " is already existed.\n";
        return 1;
    }

    parser::Parser pakParser{ argv[1] };
    
    pakParser.parse_header();
    pakParser.save_body(argv[2]);
    std::cout << "file body saved -> " << argv[2] << "\n";

    save_file_attrs(pakParser.get_file_attrs(), "file_attrs.txt");
    std::cout << "file attributes saved -> file_attrs.txt\n";
    return 0;
}
