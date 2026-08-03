#include "extractor.h"
#include "arena_allocator.h"
#include "utils.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <.pak> <dir>\n", argv[0]);
        return -1;
    }

    if (!is_file_exists(argv[1])) {
        fprintf(stderr, "%s does not exist\n", argv[1]);
        return -1;
    }

    if (is_directory_exists(argv[2])) {
        fprintf(stderr, "given dir: %s is already existed\n", argv[2]);
        return -1;
    }

    PakContext ctx;

    init_arena(65536);
    init_pak_context(&ctx, argv[1]);

    parse_header(&ctx);
    save_header(&ctx, "attr.txt");
    parse_body(&ctx, argv[2]);

    destroy_pak_context(&ctx);
    destroy_arena();
    return 0;
}
