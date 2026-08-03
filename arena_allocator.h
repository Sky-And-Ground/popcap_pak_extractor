#ifndef __ARENA_ALLOCATOR_H__
#define __ARENA_ALLOCATOR_H__

#include <stddef.h>

/* init the global arena allocator. if default_capacity is 0, then it will be set to 4096. */
void init_arena(size_t default_capacity);

/* destroy the global arena allocator. */
void destroy_arena(void);

/* allocate memory. if there are no memory, just die. */
void* arena_alloc(size_t need);

#endif