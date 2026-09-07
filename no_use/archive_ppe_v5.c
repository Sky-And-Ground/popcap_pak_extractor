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
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef INT32 i32;
typedef UCHAR uchar;

#define BYTES_OF_MAGIC      4
#define BYTES_OF_VERSION    4
#define BYTES_OF_FILE_SIZE  4
#define BYTES_OF_FILE_TIME  ((i32)sizeof(FILETIME))

#define XOR_VALUE  0xf7

#define WRITE_BUFFER_SIZE   65536

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

/* if malloc failed, just abort. */
void* malloc_or_die(size_t bytes) {
    void* memory = malloc(bytes);

    if (!memory) {
        fprintf(stderr, "malloc failed for %lld bytes\n", bytes);
        abort();
    }

    return memory;
}

/* is this directory exist ? */
int is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/* format windows error code to readable message, not thread safe. */
const char* win_strerr(DWORD errCode) {
    static char winErrMsg[1024];
    
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
    return success == 0 ? "" : winErrMsg;
}

/* init WinFile object with given path. */
void init_win_file(WinFile* wf, const char* path) {
    DWORD err;

    wf->handle = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (wf->handle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        fprintf(stderr, "cannot init windows file with path: %s, %ld, %s\n", path, err, win_strerr(err));
        exit(EXIT_FAILURE);
    }

    wf->file_size = GetFileSize(wf->handle, NULL);
    if (wf->file_size == INVALID_FILE_SIZE) {
        err = GetLastError();
        fprintf(stderr, "cannot get windows file size with path: %s, %ld, %s\n", path, err, win_strerr(err));
        exit(EXIT_FAILURE);
    }
}

/* destroy the WinFile object. */
void destroy_win_file(WinFile* wf) {
    if (wf) {
        CloseHandle(wf->handle);
    }
}

/* init the FileAttr object. */
void init_file_attr(FileAttr* attr) {
    attr->name = NULL;
    attr->next = NULL;
    attr->size = INVALID_FILE_SIZE;
}

/* init the FileAttrList object. */
void init_file_attr_list(FileAttrList* list) {
    list->head = (FileAttr*)malloc_or_die(sizeof(FileAttr));
    
    list->head->next = NULL;
    list->tail = list->head;
    list->length = 0;
}

/* destroy the FileAttrList object. */
void destroy_file_attr_list(FileAttrList* list) {
    if (list) {
        FileAttr* cursor = list->head->next;
        FileAttr* tmp;

        while (cursor) {
            tmp = cursor;
            cursor = cursor->next;

            if (tmp->name) {
                free(tmp->name);
            }

            free(tmp);
        }

        free(list->head);
    }
}

/* add one FileAttr object to the list. */
void file_attr_list_add(FileAttrList* list, FileAttr* attr) {
    list->tail->next = attr;
    list->tail = list->tail->next;
    list->length += 1;
}

/* read the require bytes from the .pak file. */
DWORD read_from_pak(WinFile* pak, char* buf, DWORD num_of_bytes_to_read) {
    DWORD read_len, err;

    if (pak->file_size < num_of_bytes_to_read) {
        fprintf(stderr, ".pak file broken\n");
        exit(EXIT_FAILURE);
    }

    if (!ReadFile(pak->handle, (LPVOID)buf, num_of_bytes_to_read, &read_len, NULL)) {
        err = GetLastError();
        fprintf(stderr, "cannot read from the .pak, %ld, %s\n", err, win_strerr(err));
        exit(EXIT_FAILURE);
    }

    pak->file_size -= read_len;
    return read_len;
}

/* parse the magic part. */
void parse_magic(WinFile* pak) {
    uchar magic[BYTES_OF_MAGIC];

    read_from_pak(pak, (char*)magic, BYTES_OF_MAGIC);
    decode_bytes(magic, magic, BYTES_OF_MAGIC);

    int valid = magic[0] == 0xc0 && 
                magic[1] == 0x4a && 
                magic[2] == 0xc0 && 
                magic[3] == 0xba;
    
    if (!valid) {
        fprintf(stderr, "invalid magic\n");
        exit(EXIT_FAILURE);
    }
}

/* parse the version part. */
void parse_version(WinFile* pak) {
    uchar version[BYTES_OF_VERSION];

    read_from_pak(pak, (char*)version, BYTES_OF_VERSION);
    decode_bytes(version, version, BYTES_OF_VERSION);

    int valid = version[0] == 0x00 && 
                version[1] == 0x00 && 
                version[2] == 0x00 && 
                version[3] == 0x00;
    
    if (!valid) {
        fprintf(stderr, "invalid version\n");
        exit(EXIT_FAILURE);
    }
}

/* do we reach the end of the header part. */
int is_the_end_of_pak_header(WinFile* pak) {
    uchar flag;

    read_from_pak(pak, (char*)&flag, sizeof(flag));
    flag = decode_one_byte(flag);

    return flag == 0x80;
}

/* parse the file name. */
void parse_file_name(WinFile* pak, FileAttr* attr) {
    uchar byte;
    i32 file_name_len;

    read_from_pak(pak, (char*)&byte, sizeof(byte));
    file_name_len = (i32)decode_one_byte(byte);

    attr->name = (char*)malloc_or_die((file_name_len + 1) * sizeof(char));
    attr->name[file_name_len] = '\0';

    read_from_pak(pak, attr->name, file_name_len);
    decode_bytes(attr->name, attr->name, file_name_len);
}

/* parse the file size. */
void parse_file_size(WinFile* pak, FileAttr* attr) {
    char* buf = (char*)(&(attr->size));

    read_from_pak(pak, buf, sizeof(attr->size));
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

/* parse the file last write time. */
void parse_file_last_write_time(WinFile* pak, FileAttr* attr) {
    char* buf = (char*)(&(attr->last_write_time));

    read_from_pak(pak, buf, sizeof(attr->last_write_time));
    decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
}

/* parse the whole header. */
FileAttrList* parse_pak_header(WinFile* pak) {
    FileAttrList* list = (FileAttrList*)malloc_or_die(sizeof(FileAttrList));
    init_file_attr_list(list);

    parse_magic(pak);
    parse_version(pak);

    while (1) {
        if (is_the_end_of_pak_header(pak)) {
            break;
        }

        FileAttr* attr = (FileAttr*)malloc_or_die(sizeof(FileAttr));
        init_file_attr(attr);

        parse_file_name(pak, attr);
        parse_file_size(pak, attr);
        parse_file_last_write_time(pak, attr);

        file_attr_list_add(list, attr);
    }

    return list;
}

/* format windows filetime to year-month-day hour:minute:second, not thread safe. */
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

/* save file attribute list to file. */
void save_file_attr_list(FileAttrList* list, const char* savPath) {
    FILE* savFile = fopen(savPath, "w");

    if (savFile == NULL) {
        fprintf(stderr, "save file attribute list failed, cannot open %s\n", savPath);
        return;
    }

    FileAttr* cursor = list->head->next;
    while (cursor) {
        const char* last_write_time = format_windows_filetime(&(cursor->last_write_time));
        fprintf(savFile, "%s, %10d bytes, %s\n", last_write_time, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(savFile);
}

/* concatenate path. */
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

/* create parent directories recursively. */
void recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    DWORD err = GetLastError();
                    fprintf(stderr, "cannot create parent directories of %s, %ld, %s\n", path, err, win_strerr(err));
                    exit(EXIT_FAILURE);
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

/* save one file data. */
void save_single_file_body(WinFile* pak, FileAttr* attr, const char* to_dir) {
    static char path[MAX_PATH];
    static char buf[WRITE_BUFFER_SIZE];

    i32 file_size = attr->size;
    i32 need_len;
    i32 read_len;
    DWORD err;

    build_complete_path(path, to_dir, attr->name);
    recursive_create_parent_dirs(path);

    HANDLE handle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        fprintf(stderr, "cannot create file handle to save body of %s, %ld, %s\n", attr->name, err, win_strerr(err));
        exit(EXIT_FAILURE);
    }

    while (file_size > 0) {
        need_len = (file_size < WRITE_BUFFER_SIZE ? file_size : WRITE_BUFFER_SIZE);
        read_len = (i32)read_from_pak(pak, buf, need_len);
        decode_bytes(buf, buf, read_len);

        if (!WriteFile(handle, buf, read_len, NULL, NULL)) {
            err = GetLastError();
            fprintf(stderr, "cannot write body data to %s, %ld, %s\n", attr->name, err, win_strerr(err));
            exit(EXIT_FAILURE);
        }

        file_size -= read_len;
    }

    if (!SetFileTime(handle, NULL, NULL, &(attr->last_write_time))) {
        err = GetLastError();
        fprintf(stderr, "cannot set file time to %s, %ld, %s\n", attr->name, err, win_strerr(err));
        exit(EXIT_FAILURE);
    }

    CloseHandle(handle);
}

/* save the whole .pak body data. */
void save_pak_body(WinFile* pak, FileAttrList* list, const char* to_dir) {
    FileAttr* cursor = list->head->next;

    while (cursor) {
        save_single_file_body(pak, cursor, to_dir);
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

    const char* fileAttrListSavePath = "file_attr_list.txt";

    WinFile wf;
    init_win_file(&wf, argv[1]);

    FileAttrList* list = parse_pak_header(&wf);

    save_file_attr_list(list, fileAttrListSavePath);
    printf("save file attribute list -> %s\n", fileAttrListSavePath);

    save_pak_body(&wf, list, argv[2]);
    printf("save file body -> %s\n", argv[2]);

    destroy_file_attr_list(list);
    destroy_win_file(&wf);
    return 0;
}
