#include "die.h"
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

void die(const char* fmt, ...) {
    char buf[2048];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    fprintf(stderr, "%s\n", buf);
    exit(EXIT_FAILURE);
}