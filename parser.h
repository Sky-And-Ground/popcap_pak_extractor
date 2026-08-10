#ifndef __PAK_PARSER_H__
#define __PAK_PARSER_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <memory>
#include <vector>
#include <filesystem>
#include <cstdint>
#include "win_file_handle.h"

namespace fs = std::filesystem;

// we could extract these information from the .pak header.
struct FileAttr {
    std::unique_ptr<char[]> name;
    DWORD size;
    FILETIME last_write_time;
};

class Parser {
private:
    static constexpr int32_t BUFFER_SIZE = 65536;

    std::unique_ptr<char[]> buf;
    std::vector<FileAttr> file_attr_list;
    WinFile pak;
    DWORD pak_size;
private:
    void read_from_pak(char* buf, DWORD wanted_bytes);

    bool reach_header_end();
    void parse_magic();
    void parse_version();
    void parse_file_name(FileAttr& attr);
    void parse_file_size(FileAttr& attr);
    void parse_file_last_write_time(FileAttr& attr);

    void save_single_file(const FileAttr& attr, const fs::path& p);
public:
    Parser(const std::string& pak_path);

    void parse_header();
    void save_file_attr_list(const std::string& path);
    void save_body(const std::string& to_dir);
};

#endif