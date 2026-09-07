/**
 * @author yuan
 * @brief PopCap's .pak file extractor, written in C++20, only works for windows platform.
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
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <fstream>
#include <string>
#include <memory>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <utility>
#include <vector>
#include <array>
#include <cstdint>

namespace fs = std::filesystem;

using namespace std::chrono;
using namespace std::string_literals;

template <typename T>
concept CharType = std::is_same_v<T, char> || std::is_same_v<T, unsigned char>;

struct FileAttr {
    std::unique_ptr<char[]> fileName;
    DWORD fileSize;
    FILETIME lastWriteTime;
};

struct Header {
    std::array<UCHAR, 4> magic;
    std::array<UCHAR, 4> version;
    std::vector<FileAttr> fileAttrList;
};

class PakFile {
    HANDLE hFile;
    DWORD size;
public:
    PakFile(const std::string& path) {
        hFile = CreateFileA(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            throw std::system_error(err, std::system_category(), "sys call CreateFileA failed");
        }

        size = GetFileSize(hFile, nullptr);
        if (size == INVALID_FILE_SIZE) {
            DWORD err = GetLastError();
            CloseHandle(hFile);
            throw std::system_error(err, std::system_category(), "sys call GetFileSize failed");
        }
    }

    ~PakFile() {
        CloseHandle(hFile);
    }

    template<CharType type>
    DWORD read(type* buf, DWORD numOfBytesToRead) {
        if (size < numOfBytesToRead) {
            throw std::runtime_error{ "cannot read the require number of bytes: " + std::to_string(numOfBytesToRead) };
        }

        DWORD numOfBytesRead;
        if (!ReadFile(hFile, (LPVOID)buf, numOfBytesToRead, &numOfBytesRead, nullptr)) {
            DWORD err = GetLastError();
            throw std::system_error(err, std::system_category(), "sys call ReadFile failed");
        }

        size -= numOfBytesRead;
        return numOfBytesRead;
    }
};

class PakExtractor {
    Header header;

    template<CharType type>
    UCHAR decode_one_byte(type c) noexcept {
        // using 0xf7 to decode the data in .pak file.
        return static_cast<UCHAR>(c ^ 0xf7);
    }

    template<CharType type>
    void decode_bytes(type* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            data[i] = decode_one_byte(data[i]);
        }
    }

    bool reach_header_end(PakFile& pakFile) {
        char c;
        pakFile.read(&c, 1);
        return decode_one_byte(c) == 0x80;
    }

    bool check_magic() noexcept {
        return header.magic[0] == 0xC0 
            && header.magic[1] == 0x4A 
            && header.magic[2] == 0xC0 
            && header.magic[3] == 0xBA;
    }

    bool check_version() noexcept {
        return header.version[0] == 0x00 
            && header.version[1] == 0x00 
            && header.version[2] == 0x00 
            && header.version[3] == 0x00;
    }

    void parse_magic(PakFile& pakFile) {
        pakFile.read(header.magic.data(), header.magic.size());
        decode_bytes(header.magic.data(), header.magic.size());
    }

    void parse_version(PakFile& pakFile) {
        pakFile.read(header.version.data(), header.version.size());
        decode_bytes(header.version.data(), header.version.size());
    }

    std::unique_ptr<char[]> init_file_name(size_t size) {
        return std::unique_ptr<char[]>(new char[size]);
    }

    void parse_file_name(FileAttr& attr, PakFile& pakFile) {
        char c;
        pakFile.read(&c, 1);

        // get the length of the file name.
        uint32_t fileNameLen = (uint32_t)decode_one_byte(c);
        attr.fileName = init_file_name(fileNameLen + 1);
        attr.fileName[fileNameLen] = '\0';

        // get file name.
        pakFile.read(attr.fileName.get(), fileNameLen);
        decode_bytes(attr.fileName.get(), fileNameLen);
    }

    void parse_file_size(FileAttr& attr, PakFile& pakFile) {    
        constexpr uint32_t FILE_SIZE_BYTES = 4;

        pakFile.read((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
        decode_bytes((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
    }

    void parse_file_last_write_time(FileAttr& attr, PakFile& pakFile) {
        pakFile.read((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
        decode_bytes((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
    }

    void parse_header(PakFile& pakFile) {
        std::cout << "parse magic.\n";
        parse_magic(pakFile);

        if (!check_magic()) {
            throw std::runtime_error{ "parse header failed, invalid magic" };
        }

        std::cout << "parse version.\n";
        parse_version(pakFile);

        if (!check_version()) {
            throw std::runtime_error{ "parse header failed, invalid version" };
        }

        std::cout << "parse all file attributes.\n";

        while (true) {
            if (reach_header_end(pakFile)) {
                break;
            }

            FileAttr attr;
            parse_file_name(attr, pakFile);
            parse_file_size(attr, pakFile);
            parse_file_last_write_time(attr, pakFile);

            header.fileAttrList.emplace_back(std::move(attr));
        }
    }

    system_clock::time_point convert_filetime_to_system_clock_time_point(const FILETIME& ft) {
        ULARGE_INTEGER uli;
    
        uli.HighPart = ft.dwHighDateTime;
        uli.LowPart = ft.dwLowDateTime;
    
        /* 
            windows file time begins from 1601/01/01, but unix timestamp 
            begins from 1970/01/01, so we have to minus this duration, 
            that's where 11644473600LL seconds come from.
            
            uli.QuadPart accurates to 10 ^ -7 seconds.
        */
        seconds sec{ uli.QuadPart / 10000000 - 11644473600ULL };
        system_clock::duration dur{ sec };
        system_clock::time_point tp{ dur };
        return tp;
    }

    decltype(auto) write_win_filetime(const FILETIME& ft) {
        auto tp = convert_filetime_to_system_clock_time_point(ft);
        time_t seconds = system_clock::to_time_t(tp);
        tm* localTime = std::localtime(&seconds);
    
        return std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    }

    void save_file_attributes() {
        std::cout << "save file attributes.\n";

        constexpr const char* savPath = "pak_file_attributes.txt";
        std::ofstream out{ savPath };
        if (!out.is_open()) {
            std::cerr << "cannot save file attributes to \"" << savPath << "\".\n";
            return;
        }

        for (const FileAttr& attr : header.fileAttrList) {
            out << write_win_filetime(attr.lastWriteTime) << ", " << std::setw(10) << attr.fileSize << " bytes, " << attr.fileName.get() << "\n";
        }

        out.close();
        std::cout << "save file attributes to file \"" << savPath << "\" success.\n";
    }

    /*
        Before writing this function, I have tried the answer from:
        https://stackoverflow.com/questions/72030923/how-to-convert-a-windows-filetime-to-a-stdchronotime-pointstdchronofile

        be cautions that, this solution only works for vc++, but it would get a really different result on other compilers, 
        such as my winlibs-x86_64-posix-seh-gcc-14.1.0-mingw-w64msvcrt-11.0.1-r1 g++ compiler and my Msys2 mingw compiler.
        so I consider to create the system_clock first, then convert it to file_clock. 

        if using visual C++, the conversion could be easily replaced by using file_clock::duration and file_clock::time_point.
    */
    file_clock::time_point convert_win_FILETIME_to_file_clock(const FILETIME& ft) {
        auto tp = convert_filetime_to_system_clock_time_point(ft);

        /*
            accroding to the microsoft's document: https://learn.microsoft.com/en-us/cpp/standard-library/file-clock-class?view=msvc-170
            whether std::chrono::file_clock provide from_utc, to_utc, from_sys, to_sys is actually defined by vendor, so it is safe to use 
            clock_cast here.
        */
        return clock_cast<file_clock>(tp);
    }

    template<size_t N>
    void save_single_file_data(const FileAttr& attr, PakFile& pakFile, std::array<char, N>& buf, const fs::path& p) {
        DWORD fileSize = attr.fileSize;
        DWORD readLen = 0;
        DWORD needLen;
        std::ofstream out{ p.string(), std::ios::binary };

        while (fileSize > 0) {
            needLen = (fileSize < buf.size() ? fileSize : buf.size());
            readLen = pakFile.read(buf.data(), needLen);
            decode_bytes(buf.data(), readLen);

            out.write(buf.data(), readLen);
            fileSize -= readLen;
        }

        /*
            be cautions here,
            you Must do this close() first before calling std::filesystem::last_write_time(),
            otherwise, you may find your file's last write time is the current time, this is
            really a silly mistake, and it's really easy to be made.

            The same question can be found at:
            https://stackoverflow.com/questions/38158037/why-cant-i-change-the-last-write-time-of-my-newly-created-files
        */
        out.close();
        auto fc = convert_win_FILETIME_to_file_clock(attr.lastWriteTime);
        fs::last_write_time(p, fc);
    }

    void extract_inner_files(PakFile& pakFile, const std::string& rootPath) {
        std::array<char, 8192> buf;

        for (const FileAttr& attr : header.fileAttrList) {
            fs::path p{ rootPath };
            p.append(attr.fileName.get());

            fs::path parentDir = p.parent_path();
            if (!fs::exists(parentDir)) {
                fs::create_directories(parentDir);
            }

            save_single_file_data(attr, pakFile, buf, p);
        }
    }
public:
    void start_parse(PakFile& pakFile, const std::string& rootPath) {
        parse_header(pakFile);
        std::cout << "parse header success, the number of the file attributes is " << header.fileAttrList.size() << ".\n";

        save_file_attributes();

        std::cout << "extract inner files.\n";
        extract_inner_files(pakFile, rootPath);
        std::cout << "extract inner files to dir \"" << rootPath << "\" success.\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <.pak> <sav_dir>.\n";
        return 1;
    }

    if (fs::is_directory(argv[2])) {
        std::cerr << "dir: " << argv[2] << " is already exists.\n";
        return 1;
    }

    PakFile pakFile{ argv[1] };
    PakExtractor pe;

    try {
        pe.start_parse(pakFile, argv[2]);
    }
    catch(const std::system_error& se) {
        std::cerr << "system error, " << se.code() << ", "<< se.what() << "\n";
    }
    catch(const std::runtime_error& re) {
        std::cerr << "runtime error, " << re.what() << "\n";
    }
    catch(const std::exception& e) {
        std::cerr << "exception, " << e.what() << "\n";
    }
    catch(...) {
        std::cerr << "unknown error\n";
    }

    return 0;
}