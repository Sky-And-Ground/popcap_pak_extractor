#ifndef __PAK_CUSTOM_EXCEPTION_H__
#define __PAK_CUSTOM_EXCEPTION_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdexcept>
#include <system_error>
#include <string>

#define THROW_PARSE_ERROR(msg) \
    throw ParseError{ __FILE__, __func__, __LINE__, msg }

#define THROW_SYSTEM_ERROR(errCode, msg) \
    throw SystemError{ __FILE__, __func__, __LINE__, errCode, msg }

class ParseError : public std::runtime_error {
public:
    const char* file;
    const char* func;
    int line;

    ParseError(const char* _file, const char* _func, int _line, const std::string& msg)
        : std::runtime_error{ msg }, file{ _file }, func{ _func }, line{ _line }
    {}
};

class SystemError : public ParseError {
public:
    std::error_code ec;

    SystemError(const char* file, const char* func, int line, int errCode, const std::string& msg)
        : ParseError{ file, func, line, msg }, ec{ errCode, std::system_category() }
    {}
};

#endif