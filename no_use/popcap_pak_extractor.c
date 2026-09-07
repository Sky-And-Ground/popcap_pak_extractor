/*
    @author yuan
    @brief popcap's .pak file extractor written in C, no 3rd parties, only works for windows platform.
    
    a very big thanks to https://github.com/nathaniel-daniel/popcap-pak-rs for giving 
    the popcap .pak file's format:
    
        Header 
        4 bytes - Magic (Should be [0xc0, 0x4a, 0xc0, 0xba])
        4 bytes - Version (Should be all 0) 
        loop 
            1 byte  - Record Flag (exit loop if 0x80)
            1 byte  - File name length (N) 
            N bytes - Filename 
            4 bytes - Filesize (u32)
            4 bytes - Last write time (Microsoft FILETIME struct)
        end
        
        Body
        for each record
            record.filesize bytes - File data
        end
*/
#ifndef _WIN32
#error  "This program only works for windows platform"
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

typedef INT32 i32;
typedef UINT32 u32;
typedef UCHAR uchar;

#define XOR_VALUE     0xf7
#define HEADER_END    0x80
#define MAGIC_FLAG    0xbac04ac0   /* little endian. */
#define VERSION_FLAG  0X0

#define FILE_ATTR_LIST_SAVE_PATH   "attr.txt"

typedef struct TileAllocNode {
    size_t total;
    size_t used;

    struct TileAllocNode* next;
} TileAllocNode;

typedef struct {
    TileAllocNode head;
    TileAllocNode* tail;

    size_t tile_capacity;
    size_t tile_num;
} TileAllocator;

typedef struct FileAttribute {
    char* name;
    i32 size;
    FILETIME last_write_time;

    struct FileAttribute* next;
} FileAttribute;

typedef struct {
    FileAttribute head;
    FileAttribute* tail;

    i32 length;
} FileAttributeList;

typedef struct {
    HANDLE file_handle;
    DWORD file_size;
    FileAttributeList attr_list;
    TileAllocator allocator;
} PakContext;

#define decode_one_byte(ch) \
    (uchar)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
    i32 i; \
    for (i = 0; i < (length); ++i) { \
        toBuf[i] = decode_one_byte(fromBuf[i]); \
    } \
} while(0)

void tile_alloc_init(TileAllocator* allocator, size_t tile_capacity) {
    allocator->tile_num = 0;
    allocator->tile_capacity = tile_capacity;

    /* 
        set the head used and total both to 0, then the first call to tile_alloc() would
        allocate a new tail node.
    */
    allocator->head.used = 0;
    allocator->head.total = 0;
    allocator->head.next = NULL;
    allocator->tail = &(allocator->head);
}

void tile_alloc_destroy(TileAllocator* allocator) {
    TileAllocNode* cursor = allocator->head.next;
    TileAllocNode* tmp;

    while (cursor) {
        tmp = cursor;
        cursor = cursor->next;

        free(tmp);
    }
}

void* tile_alloc(TileAllocator* allocator, size_t need_bytes) {
    TileAllocNode* tail = allocator->tail;
    char* ptr = NULL;

    if (tail->total - tail->used < need_bytes) {   /* allocate new tile. */
        size_t need = need_bytes > allocator->tile_capacity ? need_bytes : allocator->tile_capacity;
        TileAllocNode* new_node = (TileAllocNode*)malloc(sizeof(TileAllocNode) + need);

        if (!new_node) {
            return NULL;
        }

        new_node->total = need;
        new_node->used = 0;
        new_node->next = NULL;

        allocator->tail->next = new_node;
        allocator->tail = allocator->tail->next;

        allocator->tile_num += 1;
    }
    
    tail = allocator->tail;   /* tail maybe updated. */
    ptr = ((char*)tail) + sizeof(TileAllocNode) + tail->used;
    tail->used += need_bytes;

    return (void*)ptr;
}

const char* win_str_err(DWORD err) {
    static char winErrMsg[1024];
    
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
    return success ? winErrMsg : "";
}

void file_attr_init(FileAttribute* attr) {
    attr->name = NULL;
    attr->next = NULL;
}

void file_attr_list_add(FileAttributeList* list, FileAttribute* attr) {
    list->tail->next = attr;
    list->tail = list->tail->next;

    list->length += 1;
}

bool pak_context_init(PakContext* ctx, const char* path) {
    ctx->file_handle = INVALID_HANDLE_VALUE;
    ctx->file_size = INVALID_FILE_SIZE;

    ctx->attr_list.length = 0;
    ctx->attr_list.head.next = NULL;

    ctx->attr_list.tail = &(ctx->attr_list.head);

    tile_alloc_init(&(ctx->allocator), 2 << 16);

    ctx->file_handle = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, ".pak file init failed, cannot open file: %s, %s\n", path, win_str_err(GetLastError()));
        return false;
    }
    
    ctx->file_size = GetFileSize(ctx->file_handle, NULL);
    if (ctx->file_size == INVALID_FILE_SIZE) {
        fprintf(stderr, ".pak file init failed, cannot get file size: %s, %s\n", path, win_str_err(GetLastError()));
        return false;
    }
    
    return true;
}

void pak_context_destroy(PakContext* ctx) {
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
    }

    tile_alloc_destroy(&(ctx->allocator));
}

bool pak_read(PakContext* ctx, char* buf, DWORD num_of_bytes_to_read, DWORD* read_bytes) {
    DWORD tmp;
    
    if (ctx->file_size < num_of_bytes_to_read) {   /* then this file must be broken. */
        return false;
    }

    if (!ReadFile(ctx->file_handle, (LPVOID)buf, num_of_bytes_to_read, &tmp, NULL)) {
        fprintf(stderr, "sys call ReadFile failed, %s\n", win_str_err(GetLastError()));
        return false;
    }
    
    if (num_of_bytes_to_read != tmp) {
        return false;
    }

    decode_bytes(buf, buf, (i32)tmp);
    ctx->file_size -= tmp;

    if (read_bytes) {
        *read_bytes = tmp;
    }

    return true;
}

void* pak_alloc(PakContext* ctx, size_t need) {
    return tile_alloc(&(ctx->allocator), need);
}

bool pak_parse_magic(PakContext* ctx) {
    u32 magic;

    if (!pak_read(ctx, (char*)&magic, sizeof(magic), NULL)) {
        return false;
    }

    return magic == MAGIC_FLAG;
}

bool pak_parse_version(PakContext* ctx) {
    u32 version;

    if (!pak_read(ctx, (char*)&version, sizeof(version), NULL)) {
        return false;
    }

    return version == VERSION_FLAG;
}

bool pak_parse_file_name(PakContext* ctx, FileAttribute* attr) {
    uchar byte;
    i32 file_name_len = 0;
    char* name;

    /* the length of the file name is contained in the file. */
    if (!pak_read(ctx, (char*)&byte, sizeof(byte), NULL)) {
        return false;
    }

    file_name_len = (i32)byte;
    name = (char*)pak_alloc(ctx, (file_name_len + 1) * sizeof(char));

    if (name == NULL) {
        fprintf(stderr, "parse file name failed, no memory\n");
        return false;
    }

    if (!pak_read(ctx, name, file_name_len, NULL)) {
        return false;
    }

    name[file_name_len] = '\0';
    attr->name = name;
    return true;
}

bool pak_parse_file_size(PakContext* ctx, FileAttribute* attr) {
    return pak_read(ctx, (char*)(&(attr->size)), sizeof(attr->size), NULL);
}

bool pak_parse_file_last_write_time(PakContext* ctx, FileAttribute* attr) {
    return pak_read(ctx, (char*)(&(attr->last_write_time)), sizeof(attr->last_write_time), NULL);
}

bool pak_parse_file_attributes(PakContext* ctx) {
    uchar end_flag;
    FileAttribute* attr;

    while (true) {
        if (!pak_read(ctx, (char*)&end_flag, sizeof(end_flag), NULL)) {
            return false;
        }

        if (end_flag == HEADER_END) {
            return true;
        }

        attr = (FileAttribute*)pak_alloc(ctx, sizeof(FileAttribute));

        if (attr == NULL) {
            fprintf(stderr, "parse file attributes failed, no memory\n");
            return false;
        }

        file_attr_init(attr);

        if (!pak_parse_file_name(ctx, attr)) {
            return false;
        }

        if (!pak_parse_file_size(ctx, attr)) {
            return false;
        }

        if (!pak_parse_file_last_write_time(ctx, attr)) {
            return false;
        }

        file_attr_list_add(&(ctx->attr_list), attr);
    }
}

bool pak_parse_header(PakContext* ctx) {
    if (!pak_parse_magic(ctx)) {
        fprintf(stderr, "parse magic part failed\n");
        return false;
    }

    if (!pak_parse_version(ctx)) {
        fprintf(stderr, "parse version part failed\n");
        return false;
    }

    if (!pak_parse_file_attributes(ctx)) {
        fprintf(stderr, "parse file attributes failed\n");
        return false;
    }

    return true;
}

const char* format_windows_filetime(FILETIME* ft) {
    static char buf[32];
    
    ULARGE_INTEGER ull;
    time_t timestamp;
    struct tm* timeinfo;

    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

bool file_attr_list_save_to_file(PakContext* ctx, const char* path) {
    FILE* f = fopen(path, "w");

    if (!f) {
        fprintf(stderr, "cannot open %s to save file attributes\n", path);
        return false;
    }
    else {
        FileAttribute* cursor = ctx->attr_list.head.next;

        while (cursor) {
            const char* file_last_write_time = format_windows_filetime(&(cursor->last_write_time));
            fprintf(f, "%s, %10d bytes, %s\n", file_last_write_time, cursor->size, cursor->name);
            cursor = cursor->next;
        }
        
        fclose(f);
        return true;
    }
}

void build_complete_path(char* buf, const char* extractPath, const char* fileName) {    
    while (*extractPath != '\0') {
        *buf = *extractPath;

        ++buf;
        ++extractPath;
    }

    --extractPath;
    if (*extractPath != '\\') {
        *buf = '\\';
        ++buf;
    }

    while (*fileName != '\0') {
        *buf = *fileName;

        ++buf;
        ++fileName;
    }

    *buf = '\0';
}

bool is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    fprintf(stderr, "cannot create directory: %s, %s\n", path, win_str_err(GetLastError()));
                    return false;
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
    
    return true;
}

bool pak_save_one_file(PakContext* ctx, FileAttribute* attr, const char* path, char* buf, i32 buf_len) {
    HANDLE handle;
    i32 file_size;
    i32 need_len;
    i32 read_len;
    DWORD tmp;
    bool flag = true;
    
    handle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "save %s failed, cannot create it, %s\n", path, win_str_err(GetLastError()));
        return false;
    }

    file_size = attr->size;

    while (file_size > 0) {
        need_len = file_size < buf_len ? file_size : buf_len;

        if (!pak_read(ctx, buf, need_len * sizeof(char), &tmp)) {
            fprintf(stderr, "save %s failed, bad read from the pak file\n", path);
            flag = false;
            break;
        }

        read_len = (i32)tmp;
        if (!WriteFile(handle, buf, read_len, NULL, NULL)) {
            fprintf(stderr, "save %s failed, sys call WriteFile, %s\n", path, win_str_err(GetLastError()));
            flag = false;
            break;
        }
        
        file_size -= read_len;
    }

    if (!SetFileTime(handle, NULL, NULL, &(attr->last_write_time))) {
        fprintf(stderr, "save %s failed, sys call SetFileTime, %s\n", path, win_str_err(GetLastError()));
        flag = false;
    }

    CloseHandle(handle);
    return flag;
}

bool pak_save_body(PakContext* ctx, const char* to_dir) {
    const i32 buffer_size = 65536;

    char path[MAX_PATH];
    char* buf;
    FileAttribute* cursor;
    bool flag = true;

    buf = (char*)pak_alloc(ctx, buffer_size * sizeof(char));
    if (buf == NULL) {
        fprintf(stderr, "no memory to hold buf, cannot save body data\n");
        return false;
    }

    cursor = ctx->attr_list.head.next;

    while (cursor) {
        build_complete_path(path, to_dir, cursor->name);

        if (!recursive_create_parent_dirs(path)) {
            flag = false;
            break;
        }

        if (!pak_save_one_file(ctx, cursor, path, buf, buffer_size)) {
            flag = false;
            break;
        }

        cursor = cursor->next;
    }

    return flag;
}

int main(int argc, char* argv[]) {
    PakContext ctx;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <.pak> <dir>\n", argv[0]);
        return -1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: %s is already existed\n", argv[2]);
        return -1;
    }

    if (!pak_context_init(&ctx, argv[1])) {
        goto finally;
    }

    if (!pak_parse_header(&ctx)) {
        goto finally;
    }

    if (file_attr_list_save_to_file(&ctx, FILE_ATTR_LIST_SAVE_PATH)) {
        printf("file attibutes has been saved to file: %s\n", FILE_ATTR_LIST_SAVE_PATH);
    }

    if (pak_save_body(&ctx, argv[2])) {
        printf("file body has been saved to dir: %s\n", argv[2]);
    }

finally:
    pak_context_destroy(&ctx);
    return 0;
}
