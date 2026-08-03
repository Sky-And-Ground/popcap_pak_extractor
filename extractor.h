#ifndef __EXTRACTOR_H__
#define __EXTRACTOR_H__

#include <windows.h>

typedef struct FileAttribute {
    char* name;
    INT32 size;
    FILETIME last_write_time;

    struct FileAttribute* next;
} FileAttribute;

typedef struct {
    FileAttribute head;
    FileAttribute* tail;

    INT32 length;
} FileAttributeList;

typedef struct {
    HANDLE file_handle;
    DWORD file_size;
    FileAttributeList attr_list;
} PakContext;

/* 
    init the context with the given .pak file path. 
    if failed, just log and die.
*/
void init_pak_context(PakContext* ctx, const char* pak_path);

void destroy_pak_context(PakContext* ctx);

/*
    parse the header part.
    if failed, just log and die.
*/
void parse_header(PakContext* ctx);

/*
    parse the body part and save each file into the given directory.
    if any one failed, just log and die.
*/
void parse_body(PakContext* ctx, const char* save_dir);

/*
    the .pak header part contains all file attibutes, this function
    would save them into the given file.

    if open the save_file failed, just log and do nothing.
*/
void save_header(PakContext* ctx, const char* save_file);

#endif