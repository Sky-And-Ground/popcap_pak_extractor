#include "arena_allocator.h"
#include "die.h"
#include <stdlib.h>

typedef struct ArenaNode {
    size_t total;
    size_t used;

    struct ArenaNode* next;
} ArenaNode;

typedef struct Arena {
    ArenaNode head;
    ArenaNode* tail;

    size_t node_num;
} Arena;

static size_t node_default_capacity = 4096;
static Arena global_arena_allocator;

void init_arena(size_t default_capacity) {
    if (default_capacity > 0) {
        node_default_capacity = default_capacity;
    }

    global_arena_allocator.node_num = 0;

    global_arena_allocator.head.used = 0;
    global_arena_allocator.head.total = 0;
    global_arena_allocator.head.next = NULL;

    global_arena_allocator.tail = &(global_arena_allocator.head);
}

void destroy_arena(void) {
    ArenaNode* cursor = global_arena_allocator.head.next;
    ArenaNode* tmp;

    while (cursor) {
        tmp = cursor;
        cursor = cursor->next;

        free(tmp);
    }
}

void* arena_alloc(size_t bytes) {
    ArenaNode* tail = global_arena_allocator.tail;

    if (tail->total - tail->used < bytes) {
        size_t want = bytes > node_default_capacity ? bytes : node_default_capacity;

        ArenaNode* new_node = (ArenaNode*)malloc(sizeof(ArenaNode) + want);

        if (!new_node) {
            new_node = (ArenaNode*)malloc(sizeof(ArenaNode) + want);

            if (!new_node) {
                die("no memory to allocate, can't run anymore\n");
            }
        }

        new_node->total = want;
        new_node->used = 0;
        new_node->next = NULL;

        global_arena_allocator.tail->next = new_node;
        global_arena_allocator.tail = global_arena_allocator.tail->next;

        global_arena_allocator.node_num += 1;
    }

    tail = global_arena_allocator.tail;
    char* ptr = (char*)tail + sizeof(ArenaNode) + tail->used;
    tail->used += bytes;

    return (void*)ptr;
}
