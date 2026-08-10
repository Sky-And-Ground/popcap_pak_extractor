#include "parser.h"
#include "utils.h"
#include "custom_exception.h"
#include <fstream>
#include <iomanip>

void Parser::read_from_pak(char* buf, DWORD wanted_bytes) {
    if (pak_size < wanted_bytes) {
        THROW_PARSE_ERROR("unexpected end of file");
    }
    
    DWORD total = wanted_bytes;
    char* ptr = buf;

    while (total > 0) {
        DWORD read = pak.read(ptr, total);

        ptr += read;
        total -= read;
    }
    
    // decode them.
    for (DWORD i = 0; i < wanted_bytes; ++i) {
        buf[i] = ((unsigned char)buf[i]) ^ 0xf7;
    }
    
    pak_size -= wanted_bytes;
}

bool Parser::reach_header_end() {
    UCHAR c;
    read_from_pak((char*)(&c), sizeof(c));
    return c == 0x80;
}

void Parser::parse_magic() {
    UCHAR magic[4];
    read_from_pak((char*)magic, sizeof(magic));

    bool ret = magic[0] == 0xC0 
            && magic[1] == 0x4A 
            && magic[2] == 0xC0 
            && magic[3] == 0xBA;

    if (!ret) {
        THROW_PARSE_ERROR("invalid magic");
    }
}

void Parser::parse_version() {
    UCHAR version[4];
    read_from_pak((char*)version, sizeof(version));

    bool ret = version[0] == 0x00 
            && version[1] == 0x00 
            && version[2] == 0x00 
            && version[3] == 0x00;

    if (!ret) {
        THROW_PARSE_ERROR("invalid version");
    }
}

void Parser::parse_file_name(FileAttr& attr) {
    char c;
    read_from_pak(&c, sizeof(char));
    
    uint32_t fileNameLen = (uint32_t)c;

    attr.name = std::make_unique<char[]>(fileNameLen + 1);
    read_from_pak(attr.name.get(), fileNameLen);
    attr.name[fileNameLen] = '\0';
}

void Parser::parse_file_size(FileAttr& attr) {
    read_from_pak((char*)(&(attr.size)), sizeof(attr.size));
}

void Parser::parse_file_last_write_time(FileAttr& attr) {
    read_from_pak((char*)(&(attr.last_write_time)), sizeof(FILETIME));
}

void Parser::save_single_file(const FileAttr& attr, const fs::path& p) {
    DWORD fileSize = attr.size;
    DWORD needLen = 0;
    
    WinFile tmpFile{ p.string(), GENERIC_WRITE, CREATE_NEW };
    
    while (fileSize > 0) {
        needLen = (fileSize < BUFFER_SIZE ? fileSize : BUFFER_SIZE);

        read_from_pak(buf.get(), needLen);
        tmpFile.write(buf.get(), needLen);

        fileSize -= needLen;
    }
    
    tmpFile.set_file_time(attr.last_write_time);
}

Parser::Parser(const std::string& pak_path) 
    : buf{ std::make_unique<char[]>(BUFFER_SIZE) }, 
    file_attr_list{}, 
    pak{ pak_path, GENERIC_READ, OPEN_EXISTING }, 
    pak_size{ INVALID_FILE_SIZE }
{
    pak_size = pak.get_file_size();
}

void Parser::parse_header() {
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
        
        file_attr_list.emplace_back(std::move(attr));
    }
}

void Parser::save_file_attr_list(const std::string& path) {
    std::ofstream out{ path };
    
    for (const FileAttr& attr : file_attr_list) {
        out << format_windows_filetime(attr.last_write_time) 
            << "  " 
            << std::setw(10) << attr.size << " bytes  " 
            << attr.name.get() 
            << "\n";
    }
    
    out.close();
}

void Parser::save_body(const std::string& to_dir) {
    for (const FileAttr& attr : file_attr_list) {
        fs::path p{ to_dir };
        p.append(attr.name.get());
        
        fs::path parentDir = p.parent_path();
        if (!fs::exists(parentDir)) {
            fs::create_directories(parentDir);
        }
        
        save_single_file(attr, p);
    }
}
