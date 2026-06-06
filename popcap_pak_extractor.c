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
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

/* target .pak file. */
typedef struct {
    HANDLE handle;
    DWORD size;
} PakFile;

/* file attribute in the .pak header. */
typedef struct {
    char* name;
    DWORD size;
    FILETIME last_write_time;
} FileAttr;

typedef struct {
    FileAttr* data;
    size_t capacity;
    size_t length;
} FileAttrList;

#define LOGGER(...)  \
	logger(__FILE__, __func__, __LINE__, __VA_ARGS__)

#define LOGGER_SYS_ERROR(...)  \
	logger(__FILE__, __func__, __LINE__, __VA_ARGS__)

void logger(const char* file_name, const char* func_name, int line_no, const char* fmt, ...) {
	fprintf(stderr, "%s %s(%d) ", file_name, func_name, line_no);
	
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	
	fflush(stderr);
}

void logger_sys_error(const char* file_name, const char* func_name, int line_no, const char* fmt, ...) {
	char buf[1024];
	DWORD err = GetLastError();
	
	DWORD success = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)buf, sizeof(buf), NULL);
	
	if (!success) {
		buf[0] = '\0';
	}
	
	fprintf(stderr, "%s %s(%d) sys call failed, code: %d, msg: %s, ", file_name, func_name, line_no, err, buf);
	
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	
	fflush(stderr);
}

void init_pak_file(PakFile* pak, const char* file) {
    HANDLE handle = CreateFileA(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
		LOGGER_SYS_ERROR("CreateFileA\n");
        exit(EXIT_FAILURE);
    }

    DWORD size = GetFileSize(handle, NULL);
    if (size == INVALID_FILE_SIZE) {
        LOGGER_SYS_ERROR("GetFileSize\n");
        exit(EXIT_FAILURE);
    }

    pak->handle = handle;
    pak->size = size;
}

void destroy_pak_file(PakFile* pak) {
    if (pak->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(pak->handle);
    }
}

void read_from_pak(PakFile* pak, char* buf, DWORD to_read) {
    if (pak->size < to_read) {
		LOGGER("unexpected end of file\n");
        exit(EXIT_FAILURE);
    }

    DWORD total = to_read;
	char* ptr = buf;
    
    while (total > 0) {
        DWORD readLen = 0;

        if (!ReadFile(pak->handle, (LPVOID)ptr, total, &readLen, NULL)) {
            LOGGER_SYS_ERROR("ReadFile\n");
            exit(EXIT_FAILURE);
        }

		ptr += readLen;
        total -= readLen;
    }
	
    DWORD i;
    for (i = 0; i < to_read; ++i) {
        buf[i] = (UCHAR)buf[i] ^ 0xf7;
    }

    pak->size -= to_read;
}

void init_file_attr_list(FileAttrList* list, size_t capacity) {
    list->capacity = capacity;
    list->length = 0;
    list->data = (FileAttr*)malloc(capacity * sizeof(FileAttr));

    if (list->data == NULL) {
        LOGGER("no memory\n");
        abort();
    }
}

void destroy_file_attr_list(FileAttrList* list) {
    if (list->data) {
        size_t i;

        for (i = 0; i < list->length; ++i) {
            if (list->data[i].name) {
                free(list->data[i].name);
            }
        }

        free(list->data);
    }
}

FileAttr* file_attr_list_add(FileAttrList* list) {
    if (list->length == list->capacity) {
        size_t new_capacity = 2 * list->capacity;
        FileAttr* tmp = (FileAttr*)malloc(new_capacity * sizeof(FileAttr));

        if (!tmp) {
            LOGGER("no memory\n");
            abort();
        }

        memcpy(tmp, list->data, list->length * sizeof(FileAttr));
        free(list->data);

        list->data = tmp;
        list->capacity = new_capacity;
    }

    FileAttr* ptr = list->data + list->length;
    ptr->name = NULL;
    ptr->size = INVALID_FILE_SIZE;

    list->length += 1;
    return ptr;
}

bool parse_magic(PakFile* pak) {
    UCHAR buf[4];
    read_from_pak(pak, (char*)buf, sizeof(buf));
	
    return buf[0] == 0xC0 && buf[1] == 0x4A && buf[2] == 0xC0 && buf[3] == 0xBA;
}

bool parse_version(PakFile* pak) {
    UCHAR buf[4];
    read_from_pak(pak, (char*)buf, sizeof(buf));

    return buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00;
}

void parse_file_name(PakFile* pak, FileAttr* attr) {
    UCHAR c;
    read_from_pak(pak, (char*)&c, sizeof(c));

    uint32_t file_name_length = (uint32_t)c;
    char* name = (char*)malloc((file_name_length + 1) * sizeof(char));

    if (name == NULL) {
        LOGGER("no memory\n");
        abort();
    }

    read_from_pak(pak, name, file_name_length);
    name[file_name_length] = '\0';
    attr->name = name;
}

void parse_file_size(PakFile* pak, FileAttr* attr) {
    read_from_pak(pak, (char*)(&attr->size), sizeof(attr->size));
}

void parse_file_last_write_time(PakFile* pak, FileAttr* attr) {
    read_from_pak(pak, (char*)(&attr->last_write_time), sizeof(attr->last_write_time));
}

void parse_file_attributes(PakFile* pak, FileAttrList* list) {
    UCHAR end_flag;

    while (true) {
        read_from_pak(pak, (char*)&end_flag, sizeof(end_flag));
        if (end_flag == 0x80) {
            return;
        }

        FileAttr* attr = file_attr_list_add(list);
        parse_file_name(pak, attr);
        parse_file_size(pak, attr);
        parse_file_last_write_time(pak, attr);
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

void recursive_create_parent_dirs(char* path) {
    char* cursor = path;

    while (*cursor != '\0') {
        if (*cursor == '\\') {
            /* split a substr here, just make it ends with '\0'. */
            *cursor = '\0';

            if (!is_dir_exist(path)) {
                if (!CreateDirectory(path, NULL)) {
                    LOGGER_SYS_ERROR("CreateDirectory failed on %s\n", path);
                    exit(EXIT_FAILURE);
                }
            }

            /* setting back. */
            *cursor = '\\';
        }

        ++cursor;
    }
}

void parse_single_file_body(PakFile* pak, FileAttr* attr, const char* path, char* buf, size_t buf_size) {
    HANDLE handle = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
		LOGGER_SYS_ERROR("CreateFile failed on %s\n", path);
        exit(EXIT_FAILURE);
    }

    int32_t file_size = attr->size;

    while (file_size > 0) {
        int32_t need_len = file_size < buf_size ? file_size : buf_size;
        read_from_pak(pak, buf, need_len);

        if (!WriteFile(handle, buf, need_len, NULL, NULL)) {
            LOGGER_SYS_ERROR("WriteFile failed on %s\n", path);
			exit(EXIT_FAILURE);
        }
        
        file_size -= need_len;
    }

    if (!SetFileTime(handle, NULL, NULL, &(attr->last_write_time))) {
        LOGGER_SYS_ERROR("SetFileTime failed on %s\n", path);
		exit(EXIT_FAILURE);
    }

    CloseHandle(handle);
}

void parse_pak_header(PakFile* pak, FileAttrList* list) {
    if (!parse_magic(pak)) {
        LOGGER("parse MAGIC failed\n");
        exit(EXIT_FAILURE);
    }

    if (!parse_version(pak)) {
        LOGGER("parse VERSION failed\n");
        exit(EXIT_FAILURE);
    }

    parse_file_attributes(pak, list);
}

void parse_pak_body(PakFile* pak, FileAttrList* list, const char* save_to_dir) {
    char buf[2 << 16];
    char path[MAX_PATH];

    size_t i;
    for (i = 0; i < list->length; ++i) {
        FileAttr* attr = &(list->data[i]);

        build_complete_path(path, save_to_dir, attr->name);
        recursive_create_parent_dirs(path);
        parse_single_file_body(pak, attr, path, buf, sizeof(buf));
    }
}

const char* str_filetime(FILETIME ft, char* buf, size_t len) {
    ULARGE_INTEGER ull;
    
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    /* 
        windows file time begins from 1601/01/01, but unix timestamp 
        begins from 1970/01/01, so we have to minus this duration, 
        that's where 11644473600LL seconds come from.
        
        uli.QuadPart accurates to 10 ^ -7 seconds.
    */
    time_t timestamp = (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
    struct tm* timeinfo = localtime(&timestamp);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buf;
}

void save_file_attributes(FileAttrList* list, const char* path) {
    FILE* f = fopen(path, "w");

    if (f) {
        char buf[32];
        size_t i;

        for (i = 0; i < list->length; ++i) {
            FileAttr* attr = &(list->data[i]);
            fprintf(f, "%s, %10d bytes, %s\n", str_filetime(attr->last_write_time, buf, sizeof(buf)), attr->size, attr->name);
        }

        fclose(f);
        printf("pak header info saved -> %s success\n", path);
    }
}

void do_extractor_routine(const char* pak_path, const char* to_dir, const char* file_attr_list_save_path) {
    PakFile pak;
    FileAttrList list;

    init_pak_file(&pak, pak_path);
    init_file_attr_list(&list, 2 << 14);

    parse_pak_header(&pak, &list);
    parse_pak_body(&pak, &list, to_dir);
    save_file_attributes(&list, file_attr_list_save_path);

    destroy_file_attr_list(&list);
    destroy_pak_file(&pak);

    printf("pak body data saved -> %s success\n", to_dir);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <.pak> <dir>\n", argv[0]);
        return -1;
    }

    if (is_dir_exist(argv[2])) {
        fprintf(stderr, "given dir: %s is already existed\n", argv[2]);
        return -1;
    }

    do_extractor_routine(argv[1], argv[2], "attrs.txt");
    return 0;
}
