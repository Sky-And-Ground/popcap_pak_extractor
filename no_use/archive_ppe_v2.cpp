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

#include <windows.h>
#include <iostream>
#include <fstream>
#include <iomanip>
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
    enum class ParseError {
        file_not_found,
        invalid_magic,
        invalid_version,
        file_broken
    };

    class ParseErrorCategory : public ::std::error_category {
    public:
        virtual const char* name() const noexcept override {
            return "parse error";
        }

        virtual std::string message(int err) const override {
            switch(static_cast<ParseError>(err)) {
                case ParseError::file_not_found:
                    return "file not found";
                case ParseError::invalid_magic:
                    return "invalid magic field";
                case ParseError::invalid_version:
                    return "invalid version field";
                case ParseError::file_broken:
                    return "file broken";
                default:
                    return "unknown parse error";
            }
        }
    };

    const std::error_category& parse_error_category() {
        static ParseErrorCategory category;
        return category;
    }

    std::error_code make_error_code(ParseError code) {
        return std::error_code(static_cast<int>(code), parse_error_category());
    }

    struct FileAttr {
        std::unique_ptr<char[]> fileName;
        DWORD fileSize;
        FILETIME lastWriteTime;
    };

    class Parser {
        std::array<UCHAR, 4> magic;
        std::array<UCHAR, 4> version;
        std::vector<FileAttr> fileAttrs;
        HANDLE hFile;
        DWORD pakFileSize;

        template<typename CharType>
        DWORD read_pak(CharType* buf, DWORD numOfBytesToRead, std::error_code& ec) {
            if (pakFileSize < numOfBytesToRead) {
                ec = make_error_code(ParseError::file_broken);
                return 0;
            }

            DWORD numOfBytesRead;
            if (!ReadFile(hFile, (LPVOID)buf, numOfBytesToRead, &numOfBytesRead, nullptr)) {
                ec.assign(GetLastError(), std::system_category());
                return 0;
            }

            ec.clear();
            pakFileSize -= numOfBytesRead;
            return numOfBytesRead;
        }

        template<typename CharType>
        UCHAR decode_one_byte(CharType c) noexcept {
            // using 0xf7 to decode the data in .pak file.
            return static_cast<UCHAR>(c ^ 0xf7);
        }

        template<typename CharType>
        void decode_bytes(CharType* data, size_t len) noexcept {
            for (size_t i = 0; i < len; ++i) {
                data[i] = decode_one_byte(data[i]);
            }
        }

        bool reach_header_end(std::error_code& ec) {
            char c;
            read_pak(&c, 1, ec);

            if (ec) {
                return false;
            }
            else {
                return decode_one_byte(c) == 0x80;
            }
        }

        bool check_magic() noexcept {
            return magic[0] == 0xC0 
                && magic[1] == 0x4A 
                && magic[2] == 0xC0 
                && magic[3] == 0xBA;
        }

        bool check_version() noexcept {
            return version[0] == 0x00 
                && version[1] == 0x00 
                && version[2] == 0x00 
                && version[3] == 0x00;
        }

        void parse_magic(std::error_code& ec) {
            read_pak(magic.data(), magic.size(), ec);

            if (!ec) {
                decode_bytes(magic.data(), magic.size());

                if (!check_magic()) {
                    ec = make_error_code(ParseError::invalid_magic);
                }
            }
        }

        void parse_version(std::error_code& ec) {
            read_pak(version.data(), version.size(), ec);

            if (!ec) {
                decode_bytes(version.data(), version.size());

                if (!check_version()) {
                    ec = make_error_code(ParseError::invalid_version);
                }
            }
        }

        std::unique_ptr<char[]> init_file_name(size_t size) {
            return std::unique_ptr<char[]>(new char[size]);
        }

        void parse_file_name(FileAttr& attr, std::error_code& ec) {
            char c;
            read_pak(&c, 1, ec);
            if (ec) {
                return;
            }

            // get the length of the file name.
            uint32_t fileNameLen = (uint32_t)decode_one_byte(c);
            attr.fileName = init_file_name(fileNameLen + 1);
            attr.fileName[fileNameLen] = '\0';

            // get file name.
            read_pak(attr.fileName.get(), fileNameLen, ec);
            
            if (!ec) {
                decode_bytes(attr.fileName.get(), fileNameLen);
            }
        }

        void parse_file_size(FileAttr& attr, std::error_code& ec) {    
            constexpr uint32_t FILE_SIZE_BYTES = 4;
            read_pak((char*)(&(attr.fileSize)), FILE_SIZE_BYTES, ec);

            if (!ec) {
                decode_bytes((char*)(&(attr.fileSize)), FILE_SIZE_BYTES);
            }
        }

        void parse_file_last_write_time(FileAttr& attr, std::error_code& ec) {
            read_pak((char*)(&(attr.lastWriteTime)), sizeof(FILETIME), ec);

            if (!ec) {
                decode_bytes((char*)(&(attr.lastWriteTime)), sizeof(FILETIME));
            }
        }

        template<size_t N>
        void save_single_file(const FileAttr& attr, std::array<char, N>& buf, const fs::path& p, std::error_code& ec) {
            DWORD fileSize = attr.fileSize;
            DWORD readLen = 0;
            DWORD needLen = 0;
            
            HANDLE tempFileHandle = CreateFile(p.string().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (tempFileHandle == INVALID_HANDLE_VALUE) {
                ec.assign(GetLastError(), std::system_category());
                return;
            }

            while (fileSize > 0) {
                needLen = (fileSize < buf.size() ? fileSize : buf.size());
                
                readLen = read_pak(buf.data(), needLen, ec);
                if (ec) {
                    CloseHandle(tempFileHandle);
                    return;
                }

                decode_bytes(buf.data(), buf.size());

                if (!WriteFile(tempFileHandle, buf.data(), readLen, nullptr, nullptr)) {
                    ec.assign(GetLastError(), std::system_category());
                    CloseHandle(tempFileHandle);
                    return;
                }

                fileSize -= readLen;
            }

            if (!SetFileTime(tempFileHandle, nullptr, nullptr, &(attr.lastWriteTime))) {
                ec.assign(GetLastError(), std::system_category());
                CloseHandle(tempFileHandle);
                return;
            }

            CloseHandle(tempFileHandle);
        }
    public:
        Parser() : hFile{ INVALID_HANDLE_VALUE } {}

        ~Parser() {
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
            }
        }

        const std::vector<FileAttr>& get_file_attrs() const noexcept {
            return fileAttrs;
        }

        void open(const std::string& filePath, std::error_code& ec) {
            hFile = CreateFileA(filePath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                ec.assign(GetLastError(), std::system_category());
                return;
            }

            pakFileSize = GetFileSize(hFile, nullptr);
            if (pakFileSize == INVALID_FILE_SIZE) {
                ec.assign(GetLastError(), std::system_category());
                return;
            }

            ec.clear();
        }

        void parse_header(std::error_code& ec) {
            parse_magic(ec);
            if (ec) {
                return;
            }

            parse_version(ec);
            if (ec) {
                return;
            }

            while (true) {
                bool reached = reach_header_end(ec);
                if (ec || reached) {
                    return;
                }

                FileAttr attr;
                
                parse_file_name(attr, ec);
                if (ec) {
                    return;
                }

                parse_file_size(attr, ec);
                if (ec) {
                    return;
                }

                parse_file_last_write_time(attr, ec);
                if (ec) {
                    return;
                }

                fileAttrs.emplace_back(std::move(attr));
            }
        }

        void save_body(const std::string& toDir, std::error_code& ec) {
            std::array<char, 8192> buf;

            for (const FileAttr& attr : fileAttrs) {
                fs::path p{ toDir };
                p.append(attr.fileName.get());

                fs::path parentDir = p.parent_path();
                if (!fs::exists(parentDir)) {
                    fs::create_directories(parentDir);
                }

                save_single_file(attr, buf, p, ec);
            }
        }
    };
}

namespace std {
    template<>
    struct is_error_code_enum<parser::ParseError> : std::true_type {};
}

// not thread safe.
const char* format_windows_filetime(const FILETIME& ft) {
    static char buf[32];
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
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attrs(const std::vector<parser::FileAttr>& attrs, const std::string& savFile) {
    std::ofstream out{ savFile };

    for (const parser::FileAttr& attr : attrs) {
        out << format_windows_filetime(attr.lastWriteTime) << ", " << std::setw(10) << attr.fileSize << " bytes, " << attr.fileName.get() << "\n";
    }

    out.close();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <.pak> <sav_dir>\n";
        return 1;
    }

    if (fs::is_directory(argv[2])) {
        std::cerr << "dir: " << argv[2] << " is not empty.\n";
        return 1;
    }

    parser::Parser pakParser;
    std::error_code ec;

    pakParser.open(argv[1], ec);
    if (ec) {
        std::cerr << "open file failed, " << ec.message() << "\n";
        return 1;
    }

    pakParser.parse_header(ec);
    if (ec) {
        std::cerr << "parse header failed, " << ec.message() << "\n";
        return 1;
    }

    pakParser.save_body(argv[2], ec);
    if (ec) {
        std::cerr << "save body failed, " << ec.message() << "\n";
        return 1;
    }

    save_file_attrs(pakParser.get_file_attrs(), "file_attrs.txt");
    std::cout << "parse success, file attributes has been wriiten to `file_attrs.txt`\n";
    return 0;
}
