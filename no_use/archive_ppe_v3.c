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
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>

#define BYTES_OF_MAGIC       4
#define BYTES_OF_VERSION     4
#define BYTES_OF_FILE_SIZE   4
#define BYTES_OF_FILE_TIME   ((int32_t)sizeof(FILETIME))
#define WRITE_BUF_SIZE       65536

struct FileAttr {
    char* name;
    int32_t size;
    FILETIME lastWriteTime;

    struct FileAttr* next;
};

struct FileAttrList {
    struct FileAttr* head;
    struct FileAttr* tail;
    int32_t length;
};

struct ExtractorContext {
    UCHAR magic[BYTES_OF_MAGIC];
    UCHAR version[BYTES_OF_VERSION];
    struct FileAttrList* attrList;
    HANDLE pakHandle;
    DWORD pakFileSize;
    HANDLE tempFileHandle;
    char writeBuf[WRITE_BUF_SIZE];
};

static struct ExtractorContext* context = NULL;

#define decode_one_byte(ch) \
    (UCHAR)((ch) ^ 0xf7)

#define decode_bytes(fromBuf, toBuf, length) do { \
    int32_t i; \
    for (i = 0; i < (length); ++i) { \
        toBuf[i] = decode_one_byte(fromBuf[i]); \
    } \
} while(0)

void create_context(const char* pakPath);
void destroy_context(void);
void log_error_quit(const char* fmt, ...);
void* allocate_memory(size_t size);
const char* win_strerr(DWORD errCode);
const char* format_windows_filetime(FILETIME* ft);
void build_complete_path(char* buf, const char* extractPath, const char* fileName);
void recursive_create_parent_dirs(char* path);
int is_dir_exist(const char* path);
struct FileAttr* create_file_attr(void);
struct FileAttrList* create_file_attr_list(void);
void destroy_file_attr(struct FileAttr* attr);
void destroy_file_attr_list(struct FileAttrList* list);
void file_attr_list_add(struct FileAttrList* list, struct FileAttr* attr);
DWORD pak_read(char* buf, DWORD numOfBytesToRead);
int is_magic_valid(void);
int is_version_valid(void);
int is_the_end_of_header(void);
void pak_parse_magic(void);
void pak_parse_version(void);
void pak_parse_file_name(struct FileAttr* attr);
void pak_parse_file_size(struct FileAttr* attr);
void pak_parse_file_last_write_time(struct FileAttr* attr);
void pak_parse_all_file_attrs(void);
void pak_parse_header(void);
void pak_parse_single_file_body(struct FileAttr* attr, const char* extractDir);
void pak_parse_body(const char* extractDir);
void save_file_attr_list(void);

void create_context(const char* pakPath) {
    DWORD err;
    struct ExtractorContext* temp;

    context->attrList = NULL;
    context->pakHandle = INVALID_HANDLE_VALUE;
    context->tempFileHandle = INVALID_HANDLE_VALUE;
    
    temp = (struct ExtractorContext*)allocate_memory(sizeof(struct ExtractorContext));

    temp->pakHandle = CreateFile(pakPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp->pakHandle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        log_error_quit("%s: sys call CreateFile failed on \"%s\", %ld, %s\n", __func__, pakPath, err, win_strerr(err));
    }

    temp->pakFileSize = GetFileSize(temp->pakHandle, NULL);
    if (temp->pakFileSize == INVALID_FILE_SIZE) {
        err = GetLastError();
        log_error_quit("%s: sys call GetFileSize failed on \"%s\", %ld, %s\n", __func__, pakPath, err, win_strerr(err));
    }

    temp->attrList = create_file_attr_list();
    context = temp;
}

void destroy_context(void) {
    if (context) {
        if (context->attrList) {
            destroy_file_attr_list(context->attrList);
        }

        if (context->pakHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(context->pakHandle);
        }

        if (context->tempFileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(context->tempFileHandle);
        }

        free(context);
    }
}

void log_error_quit(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fflush(stderr);
    destroy_context();
    exit(EXIT_FAILURE);
}

void* allocate_memory(size_t size) {
    void* memory = malloc(size);

    if (!memory) {
        log_error_quit("%s: malloc failed for %lld bytes\n", __func__, size);
    }

    return memory;
}

const char* win_strerr(DWORD errCode) {
    static char winErrMsg[1024];
    
    DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                             NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)winErrMsg, sizeof(winErrMsg) / sizeof(char), NULL);
    return success == 0 ? "" : winErrMsg;
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

int is_dir_exist(const char* path) {
    DWORD dwAttrib = GetFileAttributes(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES 
        && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void recursive_create_parent_dirs(char* path) {
    DWORD err;
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    err = GetLastError();
                    log_error_quit("%s: sys call CreateDirectory failed on \"%s\", %ld, %s\n", __func__, path, err, win_strerr(err));
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

struct FileAttr* create_file_attr(void) {
    struct FileAttr* attr = (struct FileAttr*)allocate_memory(sizeof(struct FileAttr));
    attr->name = NULL;
    attr->next = NULL;
    return attr;
}

struct FileAttrList* create_file_attr_list(void) {
    struct FileAttrList* list = (struct FileAttrList*)allocate_memory(sizeof(struct FileAttrList));
    
    list->head = (struct FileAttr*)allocate_memory(sizeof(struct FileAttr));
    list->head->next = NULL;
    list->tail = list->head;
    list->length = 0;
    return list;
}

void destroy_file_attr(struct FileAttr* attr) {
    if (attr) {
        if (attr->name) {
            free(attr->name);
        }

        free(attr);
    }
}

void destroy_file_attr_list(struct FileAttrList* list) {
    if (list) {
        struct FileAttr* cursor = list->head->next;
        struct FileAttr* temp;

        while (cursor != NULL) {
            temp = cursor;
            cursor = cursor->next;

            destroy_file_attr(temp);
        }

        free(list->head);
        free(list);
    }
}

void file_attr_list_add(struct FileAttrList* list, struct FileAttr* attr) {
    attr->next = NULL;
    
    list->tail->next = attr;
    list->tail = list->tail->next;
    list->length += 1;
}

DWORD pak_read(char* buf, DWORD numOfBytesToRead) {
    DWORD readLen, err;
    
    if (context->pakFileSize < numOfBytesToRead) {
        log_error_quit("%s: remained file size is less than required, file maybe broken\n", __func__);
    }

    if (!ReadFile(context->pakHandle, (LPVOID)buf, numOfBytesToRead, &readLen, NULL)) {
        err = GetLastError();
        log_error_quit("%s: sys call ReadFile failed, %ld, %s\n", __func__, err, win_strerr(err));
    }

    context->pakFileSize -= readLen;
    return readLen;
}

int is_magic_valid(void) {
    return (context->magic[0] == 0xc0)
        && (context->magic[1] == 0x4a)
        && (context->magic[2] == 0xc0)
        && (context->magic[3] == 0xba);
}

int is_version_valid(void) {
    return (context->version[0] == 0x00)
        && (context->version[1] == 0x00)
        && (context->version[2] == 0x00)
        && (context->version[3] == 0x00);
}

int is_the_end_of_header(void) {
    UCHAR flag;
    pak_read((char*)&flag, sizeof(flag));
    flag = decode_one_byte(flag);
    return flag == 0x80;
}

void pak_parse_magic(void) {
    pak_read((char*)context->magic, sizeof(context->magic));
    decode_bytes(context->magic, context->magic, BYTES_OF_MAGIC);
}

void pak_parse_version(void) {
    pak_read((char*)context->version, sizeof(context->version));
    decode_bytes(context->version, context->version, BYTES_OF_VERSION);
}

void pak_parse_file_name(struct FileAttr* attr) {
    UCHAR byte;
    int32_t fileNameLen;

    pak_read((char*)&byte, sizeof(byte));
    fileNameLen = (int32_t)decode_one_byte(byte);

    attr->name = (char*)allocate_memory((fileNameLen + 1) * sizeof(char));
    attr->name[fileNameLen] = '\0';
    pak_read(attr->name, fileNameLen * sizeof(char));
    decode_bytes(attr->name, attr->name, fileNameLen);
}

void pak_parse_file_size(struct FileAttr* attr) {
    char* buf = (char*)(&(attr->size));
    pak_read(buf, sizeof(attr->size));
    decode_bytes(buf, buf, BYTES_OF_FILE_SIZE);
}

void pak_parse_file_last_write_time(struct FileAttr* attr) {
    char* buf = (char*)(&(attr->lastWriteTime));
    pak_read(buf, sizeof(attr->lastWriteTime));
    decode_bytes(buf, buf, BYTES_OF_FILE_TIME);
}

void pak_parse_all_file_attrs(void) {
    struct FileAttr* attr;

    while (1) {
        if (is_the_end_of_header()) {
            break;
        }

        attr = create_file_attr();
        
        pak_parse_file_name(attr);
        pak_parse_file_size(attr);
        pak_parse_file_last_write_time(attr);

        file_attr_list_add(context->attrList, attr);
    }
}

void pak_parse_header(void) {
    pak_parse_magic();

    if (!is_magic_valid()) {
        log_error_quit("%s: magic is not valid\n", __func__);
    }

    pak_parse_version();

    if (!is_version_valid()) {
        log_error_quit("%s: version is not valid\n", __func__);
    }

    pak_parse_all_file_attrs();
    
    printf("%s: success\n", __func__);
}

void pak_parse_single_file_body(struct FileAttr* attr, const char* extractDir) {
    char path[MAX_PATH];
    int32_t fileSize = attr->size;
    int32_t needLen;
    int32_t readLen;
    DWORD err;

    build_complete_path(path, extractDir, attr->name);
    recursive_create_parent_dirs(path);

    context->tempFileHandle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (context->tempFileHandle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        log_error_quit("%s: sys call CreateFile failed on %s, %ld, %s\n", __func__, attr->name, err, win_strerr(err));
    }

    while (fileSize > 0) {
        needLen = (fileSize < WRITE_BUF_SIZE ? fileSize : WRITE_BUF_SIZE);
        readLen = (int32_t)pak_read(context->writeBuf, needLen);
        decode_bytes(context->writeBuf, context->writeBuf, readLen);

        if (!WriteFile(context->tempFileHandle, context->writeBuf, readLen, NULL, NULL)) {
            err = GetLastError();
            log_error_quit("%s: sys call WriteFile failed, %ld, %s\n", __func__, err, win_strerr(err));
        }

        fileSize -= readLen;
    }

    if (!SetFileTime(context->tempFileHandle, NULL, NULL, &(attr->lastWriteTime))) {
        err = GetLastError();
        log_error_quit("%s: sys call SetFileTime failed, %ld, %s\n", __func__, err, win_strerr(err));
    }

    CloseHandle(context->tempFileHandle);
    context->tempFileHandle = INVALID_HANDLE_VALUE;
}

void pak_parse_body(const char* extractDir) {
    struct FileAttr* cursor = context->attrList->head->next;

    while (cursor) {
        pak_parse_single_file_body(cursor, extractDir);
        cursor = cursor->next;
    }

    printf("%s: success\n", __func__);
}

void save_file_attr_list(void) {
    struct FileAttr* cursor;
    const char* lastWriteTime;
    const char* savPath = "pak_file_attributes.txt";
    FILE* savFile = fopen(savPath, "w");

    if (savFile == NULL) {
        fprintf(stderr, "%s: fopen failed on %s\n", __func__, savPath);
        return;
    }

    cursor = context->attrList->head->next;
    while (cursor) {
        lastWriteTime = format_windows_filetime(&(cursor->lastWriteTime));
        fprintf(savFile, "%s, %10d bytes, %s\n", lastWriteTime, cursor->size, cursor->name);
        cursor = cursor->next;
    }

    fclose(savFile);
    printf("%s: write file info to %s success\n", __func__, savPath);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "popcap pak extractor: usage: %s <name.pak> <sav_dir>\n", argv[0]);
        return 1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "popcap pak extractor: given dir: \"%s\" is already exists\n", argv[2]);
        return 1;
    }

    create_context(argv[1]);

    pak_parse_header();
    save_file_attr_list();
    pak_parse_body(argv[2]);

    destroy_context();
    return 0;
}
