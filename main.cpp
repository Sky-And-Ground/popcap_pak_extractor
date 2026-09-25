#include "parser.h"
#include <iostream>
#include <string>
#include <system_error>
#include <filesystem>
#include <stdexcept>

namespace fs = std::filesystem;

void parse(const std::string& pak_path, const std::string& pak_header_save_path, const std::string& pak_body_save_path) {
    Parser parser{ pak_path };

    parser.parse_header();
    
    parser.save_file_attr_list(pak_header_save_path);
    std::cout << "parse header part success\n";

    parser.save_body(pak_body_save_path);
    std::cout << "save body part success\n";
}

void when_extract_failed(const std::string& pak_body_save_path) {
    try{
        fs::remove_all(pak_body_save_path);
    }
    catch(const fs::filesystem_error& e) {
        std::cerr << "remove dir failed: " << pak_body_save_path << "\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <.pak> <sav_dir>\n";
        return -1;
    }

    try {
        parse(argv[1], "header_info.txt", argv[2]);
    }
    catch(const std::system_error& e) {
        std::cerr << "system error, " << e.code().value() << ", " << e.code().message() << "\n";
        when_extract_failed(argv[2]);
        return -1;
    }
    catch(const std::exception& e) {
        std::cerr << "error, " << e.what() << "\n";
        when_extract_failed(argv[2]);
        return -1;
    }

    return 0;
}