#include "parser.h"
#include <iostream>
#include <string>
#include <system_error>
#include <stdexcept>

void parse(const std::string& pak_path, const std::string& pak_header_save_path, const std::string& pak_body_save_path) {
    Parser parser{ pak_path };

    parser.parse_header();
    
    parser.save_file_attr_list(pak_header_save_path);
    std::cout << "parse header part success\n";

    parser.save_body(pak_body_save_path);
    std::cout << "save body part success\n";
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
        return -1;
    }
    catch(const std::exception& e) {
        std::cerr << "error, " << e.what() << "\n";
        return -1;
    }

    return 0;
}