/*
    @author yuan
    @brief popcap's .pak file extractor written in C99, no 3rd parties, only works for windows platform.
    
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
#error "This program only works for windows platform"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

typedef INT32 i32;
typedef UCHAR uchar;

#define BYTES_OF_MAGIC      4
#define BYTES_OF_VERSION    4
#define BYTES_OF_FILE_SIZE  4
#define BYTES_OF_FILE_TIME  ((i32)sizeof(FILETIME))

#define XOR_VALUE  0xf7

#define decode_one_byte(ch) \
    (uchar)((ch) ^ XOR_VALUE)

#define decode_bytes(from_buf, to_buf, length) do { \
    i32 i; \
    for (i = 0; i < (length); ++i) { \
        to_buf[i] = decode_one_byte(from_buf[i]); \
    } \
} while(0)

typedef struct FileAttr {
    char* name;
    i32 size;
    FILETIME last_write_time;

    struct FileAttr* next;
} FileAttr;

typedef struct {
    FileAttr* head;
    FileAttr* tail;
    i32 length;
} FileAttrList;

typedef struct {
    HANDLE handle;
    DWORD file_size;
} WinFile;

static WinFile* pak_file = NULL;
static FileAttrList* file_attr_list = NULL;
static char* buffer = NULL;

const char* win_strerr(DWORD errCode) {
    static char winErrMsg[1024];
    
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
    return success == 0 ? "" : winErrMsg;
}

bool is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool init_resources(const char* pak_path) {
    /* win file. */
    pak_file = (WinFile*)malloc(sizeof(WinFile));

    if (pak_file == NULL) {
        fprintf(stderr, "out of memory, cannot init pak_file\n");
        return false;
    }
    
    pak_file->handle = CreateFile(pak_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (pak_file->handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "cannot create handle for %s, %s\n", pak_path, win_strerr(GetLastError()));
        return false;
    }

    pak_file->file_size = GetFileSize(pak_file->handle, NULL);

    if (pak_file->file_size == INVALID_FILE_SIZE) {
        fprintf(stderr, "cannot get file size of %s, %s\n", pak_path, win_strerr(GetLastError()));
        return false;
    }

    /* file attribute list. */
    file_attr_list = (FileAttrList*)malloc(sizeof(FileAttrList));

    if (file_attr_list == NULL) {
        fprintf(stderr, "out of memory, cannot init file_attr_list\n");
        return false;
    }

    file_attr_list->head = (FileAttr*)malloc(sizeof(FileAttr));

    if (file_attr_list->head == NULL) {
        fprintf(stderr, "out of memory, cannot init file_attr_list head\n");
        return false;
    }

    file_attr_list->head->next = NULL;
    file_attr_list->tail = file_attr_list->head;

    file_attr_list->length = 0;
    return true;
}

void destroy_resources(void) {
    if (pak_file) {
        if (pak_file->handle != INVALID_HANDLE_VALUE) {
            CloseHandle(pak_file->handle);
        }

        free(pak_file);
    }

    if (file_attr_list) {
        if (file_attr_list->head) {
            FileAttr* cursor = file_attr_list->head->next;
            FileAttr* tmp;

            while (cursor) {
                tmp = cursor;
                cursor = cursor->next;

                if (tmp->name) {
                    free(tmp->name);
                }

                free(tmp);
            }

            free(file_attr_list->head);
        }

        free(file_attr_list);
    }

    if (buffer) {
        free(buffer);
    }
}

void log_error_exit(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    destroy_resources();
    exit(EXIT_FAILURE);
}

FileAttr* add_new_file_attr(void) {
    FileAttr* attr = (FileAttr*)malloc(sizeof(FileAttr));

    if (attr == NULL) {
        log_error_exit("out of memory, cannot create a FileAttr object\n");
    }

    attr->name = NULL;
    attr->next = NULL;

    file_attr_list->tail->next = attr;
    file_attr_list->tail = file_attr_list->tail->next;

    file_attr_list->length += 1;
    return attr;
}

DWORD read_from_pak(char* buf, DWORD num_of_bytes_to_read) {
    DWORD read_len;

    if (pak_file->file_size < num_of_bytes_to_read) {
        log_error_exit(".pak file maybe broken, parse stop\n");
    }

    if (!ReadFile(pak_file->handle, (LPVOID)buf, num_of_bytes_to_read, &read_len, NULL)) {
        log_error_exit("read from the .pak failed, parse stop, %s\n", win_strerr(GetLastError()));
    }

    pak_file->file_size -= read_len;
    return read_len;
}

void parse_magic(void) {
    uchar magic[BYTES_OF_MAGIC];

    read_from_pak((char*)magic, BYTES_OF_MAGIC);
    decode_bytes(magic, magic, BYTES_OF_MAGIC);

    bool valid = magic[0] == 0xc0 && 
                magic[1] == 0x4a && 
                magic[2] == 0xc0 && 
                magic[3] == 0xba;
    
    if (!valid) {
        log_error_exit("invalid magic, parse stop\n");
    }
}

void parse_version(void) {
    uchar version[BYTES_OF_VERSION];

    read_from_pak((char*)version, BYTES_OF_VERSION);
    decode_bytes(version, version, BYTES_OF_VERSION);

    bool valid = version[0] == 0x00 && 
                version[1] == 0x00 && 
                version[2] == 0x00 && 
                version[3] == 0x00;
    
    if (!valid) {
        log_error_exit("invalid version, parse stop\n");
    }
}

bool is_the_end_of_pak_header(void) {
    uchar flag;
    read_from_pak((char*)&flag, sizeof(flag));

    return decode_one_byte(flag) == 0x80;
}

void parse_file_name(FileAttr* attr) {
    uchar byte;
    i32 file_name_len;

    read_from_pak((char*)&byte, sizeof(byte));
    file_name_len = (i32)decode_one_byte(byte);

    attr->name = (char*)malloc((file_name_len + 1) * sizeof(char));
    if (attr->name == NULL) {
        log_error_exit("out of memory, cannot store name, parse stop\n");
    }

    attr->name[file_name_len] = '\0';

    read_from_pak(attr->name, file_name_len);
    decode_bytes(attr->name, attr->name, file_name_len);
}

void parse_file_size(FileAttr* attr) {
    char* buf = (char*)(&(attr->size));

    read_from_pak(buf, sizeof(attr->size));
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void parse_file_last_write_time(FileAttr* attr) {
    char* buf = (char*)(&(attr->last_write_time));

    read_from_pak(buf, sizeof(attr->last_write_time));
    decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
}

void parse_pak_header_part(void) {
    parse_magic();
    parse_version();

    while (true) {
        if (is_the_end_of_pak_header()) {
            break;
        }

        FileAttr* attr = add_new_file_attr();

        parse_file_name(attr);
        parse_file_size(attr);
        parse_file_last_write_time(attr);
    }
}

const char* format_windows_filetime(FILETIME* ft) {
    static char buf[32];
    
    ULARGE_INTEGER ull;
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    struct tm *timeinfo = localtime(&timestamp);
    strftime(buf, sizeof(buf) / sizeof(char), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attr_list(const char* savPath) {
    FILE* savFile = fopen(savPath, "w");

    if (savFile == NULL) {
        fprintf(stderr, "save file attribute list failed, cannot open %s\n", savPath);
        return;
    }

    FileAttr* cursor = file_attr_list->head->next;

    while (cursor) {
        const char* last_write_time = format_windows_filetime(&(cursor->last_write_time));
        fprintf(savFile, "%s, %10d bytes, %s\n", last_write_time, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(savFile);
}

void build_complete_path(char* buf, const char* to_dir, const char* fileName) {
    while (*to_dir != '\0') {
        *buf = *to_dir;

        ++buf;
        ++to_dir;
    }

    --to_dir;
    if (*to_dir != '\\') {
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

void recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    log_error_exit("cannot create parent directories for %s, %s\n", path, win_strerr(GetLastError()));
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

bool save_single_file_body(HANDLE handle, FileAttr* attr, i32 write_buffer_size, const char* path) {
    i32 file_size = attr->size;
    i32 need_len;
    i32 read_len;

    while (file_size > 0) {
        need_len = (file_size < write_buffer_size ? file_size : write_buffer_size);
        read_len = (i32)read_from_pak(buffer, need_len);
        decode_bytes(buffer, buffer, read_len);

        if (!WriteFile(handle, buffer, read_len, NULL, NULL)) {
            fprintf(stderr, "cannot write body data to %s, %s\n", attr->name, win_strerr(GetLastError()));
            return false;
        }

        file_size -= read_len;
    }

    if (!SetFileTime(handle, NULL, NULL, &(attr->last_write_time))) {
        fprintf(stderr, "cannot set file time to %s, %s\n", attr->name, win_strerr(GetLastError()));
        return false;
    }

    return true;
}

void save_pak_body(const char* to_dir) {
    const i32 write_buffer_size = 2 << 16;

    buffer = (char*)malloc(write_buffer_size * sizeof(char));
    if (buffer == NULL) {
        log_error_exit("out of memory, cannot create buffer, save pak body failed\n");
    }

    char path[MAX_PATH];
    FileAttr* cursor = file_attr_list->head->next;

    while (cursor) {
        build_complete_path(path, to_dir, cursor->name);
        recursive_create_parent_dirs(path);

        HANDLE handle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

        if (handle == INVALID_HANDLE_VALUE) {
            log_error_exit("cannot create file handle to save body of %s, %s\n", cursor->name, win_strerr(GetLastError()));
        }

        if (!save_single_file_body(handle, cursor, write_buffer_size, to_dir)) {
            CloseHandle(handle);
            log_error_exit("save body of %s failed\n", cursor->name);
        }

        CloseHandle(handle);
        cursor = cursor->next;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "popcap pak extractor: usage: %s <.pak> <sav_dir>\n", argv[0]);
        return 1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: \"%s\" is already existed\n", argv[2]);
        return 1;
    }

    if (!init_resources(argv[1])) {
        destroy_resources();
        return 1;
    }

    const char* file_attr_list_save_path = "file_attr_list.txt";

    parse_pak_header_part();
    printf("header part parse success\n");

    save_file_attr_list(file_attr_list_save_path);
    printf("save file attribute list --> %s\n", file_attr_list_save_path);

    save_pak_body(argv[2]);
    printf("save pak body --> %s\n", argv[2]);

    destroy_resources();
    return 0;
}
