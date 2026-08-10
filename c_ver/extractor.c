#include "extractor.h"
#include "arena_allocator.h"
#include "utils.h"
#include "die.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* windows is little-endian. */
#define MAGIC_FLAG    0xbac04ac0

#define VERSION_FLAG  0X0

#define HEADER_END_FLAG  0x80

#define decode_one_byte(ch) \
    (UCHAR)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
    INT32 i; \
    for (i = 0; i < (length); ++i) { \
        toBuf[i] = decode_one_byte(fromBuf[i]); \
    } \
} while(0)

static void file_attr_init(FileAttribute* attr) {
    attr->name = NULL;
    attr->next = NULL;
}

static void file_attr_list_add(FileAttributeList* list, FileAttribute* attr) {
    list->tail->next = attr;
    list->tail = list->tail->next;

    list->length += 1;
}

void init_pak_context(PakContext* ctx, const char* pak_path) {
    ctx->file_handle = INVALID_HANDLE_VALUE;
    ctx->file_size = INVALID_FILE_SIZE;

    ctx->attr_list.length = 0;
    ctx->attr_list.head.next = NULL;

    ctx->attr_list.tail = &(ctx->attr_list.head);

    ctx->file_handle = CreateFile(pak_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        die("sys call CreateFile failed, code: %d", GetLastError());
    }
    
    ctx->file_size = GetFileSize(ctx->file_handle, NULL);
    if (ctx->file_size == INVALID_FILE_SIZE) {
        die("sys call GetFileSize failed, code: %d", GetLastError());
    }
}

void destroy_pak_context(PakContext* ctx) {
    if (ctx->file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->file_handle);
    }
}

static void pak_read(PakContext* ctx, char* buf, DWORD num_of_bytes_to_read) {
    if (ctx->file_size < num_of_bytes_to_read) {
        die("file maybe broken");
    }

    DWORD total = num_of_bytes_to_read;
    char* ptr = buf;

    while (total > 0) {
        DWORD read;

        if (!ReadFile(ctx->file_handle, (LPVOID)ptr, total, &read, NULL)) {
            die("sys call ReadFile failed, code: %d", GetLastError());
        }

        ptr += read;
        total -= read;
    }

    decode_bytes(buf, buf, (INT32)num_of_bytes_to_read);
    ctx->file_size -= num_of_bytes_to_read;
}

static inline
bool pak_parse_magic(PakContext* ctx) {
    UINT32 magic;
    pak_read(ctx, (char*)&magic, sizeof(magic));

    return magic == MAGIC_FLAG;   /* windows is little-endian. */
}

static inline
bool pak_parse_version(PakContext* ctx) {
    UINT32 version;
    pak_read(ctx, (char*)&version, sizeof(version));

    return version == VERSION_FLAG;
}

void pak_parse_file_name(PakContext* ctx, FileAttribute* attr) {
    /* the length of the file name is contained in the file. */
    UCHAR byte;
    pak_read(ctx, (char*)&byte, sizeof(byte));

    INT32 file_name_len = (INT32)byte;
    char* name = (char*)arena_alloc((file_name_len + 1) * sizeof(char));

    pak_read(ctx, name, file_name_len);
    name[file_name_len] = '\0';
    attr->name = name;
}

static inline
void pak_parse_file_size(PakContext* ctx, FileAttribute* attr) {
    pak_read(ctx, (char*)(&(attr->size)), sizeof(attr->size));
}

static inline
void pak_parse_file_last_write_time(PakContext* ctx, FileAttribute* attr) {
    pak_read(ctx, (char*)(&(attr->last_write_time)), sizeof(attr->last_write_time));
}

void pak_parse_file_attributes(PakContext* ctx) {
    while (true) {
        UCHAR end_flag;
        pak_read(ctx, (char*)&end_flag, sizeof(end_flag));

        if (end_flag == HEADER_END_FLAG) {
            return;
        }

        FileAttribute* attr = (FileAttribute*)arena_alloc(sizeof(FileAttribute));
        file_attr_init(attr);

        pak_parse_file_name(ctx, attr);
        pak_parse_file_size(ctx, attr);
        pak_parse_file_last_write_time(ctx, attr);

        file_attr_list_add(&(ctx->attr_list), attr);
    }
}

void parse_header(PakContext* ctx) {
    if (!pak_parse_magic(ctx)) {
        die("invalid magic part");
    }

    if (!pak_parse_version(ctx)) {
        die("invalid version part");
    }

    pak_parse_file_attributes(ctx);
}

static void build_complete_path(char* buf, const char* basePath, const char* fileName) {
    while (*basePath != '\0') {
        *buf = *basePath;

        ++buf;
        ++basePath;
    }

    --basePath;
    if (*basePath != '\\') {
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

/*
    create directories if not exists. this function would also create sub directories.
    if failed, just log and die.
*/
static void recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_directory_exists(path)) {
                if (!CreateDirectory(path, NULL)) {
                    die("sys call CreateDirectory failed, code: %d", GetLastError());
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

void parse_one_file_data(PakContext* ctx, FileAttribute* attr, const char* path) {
    char buf[8192];

    HANDLE handle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        die("sys call CreateFile failed, code: %d", GetLastError());
    }

    INT32 file_size = attr->size;

    while (file_size > 0) {
        INT32 need_len = file_size < (INT32)sizeof(buf) ? file_size : (INT32)sizeof(buf);
        pak_read(ctx, buf, need_len * sizeof(char));

        if (!WriteFile(handle, buf, need_len, NULL, NULL)) {
            die("sys call WriteFile failed, code: %d", GetLastError());
        }
        
        file_size -= need_len;
    }

    if (!SetFileTime(handle, NULL, NULL, &(attr->last_write_time))) {
        die("sys call SetFileTime failed, code: %d", GetLastError());
    }

    CloseHandle(handle);
}

void parse_body(PakContext* ctx, const char* save_dir) {
    char path[MAX_PATH];
    FileAttribute* cursor = ctx->attr_list.head.next;

    while (cursor) {
        build_complete_path(path, save_dir, cursor->name);
        recursive_create_parent_dirs(path);
        parse_one_file_data(ctx, cursor, path);

        cursor = cursor->next;
    }
}

void save_header(PakContext* ctx, const char* save_file) {
    FILE* f = fopen(save_file, "w");

    if (!f) {
        fprintf(stderr, "cannot open %s to save file attributes\n", save_file);
        return;
    }

    FileAttribute* cursor = ctx->attr_list.head.next;
    char buf[32];

    while (cursor) {
        time_t timestamp = filetime_to_unix_timestamp(cursor->last_write_time);
        struct tm* timeinfo = localtime(&timestamp);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", timeinfo);

        fprintf(f, "%s, %10d bytes, %s\n", buf, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(f);
}