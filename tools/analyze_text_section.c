#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_LINE 1024
#define MAX_FUNC 2048

typedef struct {
    char name[256];
    uint64_t start_addr;
    uint64_t end_addr;
    bool is_hacl;
} FunctionInfo;

bool is_hacl_function(const char* name) {
    return (strstr(name, "Hacl_") || strstr(name, "EverCrypt_"));
}

void write_json(const char* out_file, FunctionInfo* funcs, int count) {
    FILE* out = fopen(out_file, "w");
    if (!out) {
        perror("fopen output");
        return;
    }

    fprintf(out, "[\n");
    for (int i = 0; i < count; ++i) {
        uint64_t size_bytes = funcs[i].end_addr - funcs[i].start_addr;
        fprintf(out,
                "  {\n"
                "    \"name\": \"%s\",\n"
                "    \"is_hacl\": %s,\n"
                "    \"size_bytes\": %lu\n"
                "  }%s\n",
                funcs[i].name,
                funcs[i].is_hacl ? "true" : "false",
                size_bytes,
                i == count - 1 ? "" : ",");
    }
    fprintf(out, "]\n");

    fclose(out);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <objdump_output.txt> <output.json>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "r");
    if (!f) {
        perror("fopen input");
        return 1;
    }

    FunctionInfo funcs[MAX_FUNC];
    int func_count = 0;

    char line[MAX_LINE];
    FunctionInfo* current = NULL;

    while (fgets(line, sizeof(line), f)) {
        uint64_t addr;
        char name[256];

        // Detect function header like: 0000000000001230 <func_name>:
        if (sscanf(line, "%lx <%[^>]>:", &addr, name) == 2) {
            if (current != NULL) {
                current->end_addr = addr; // End previous func at this address
            }

            if (func_count >= MAX_FUNC) {
                fprintf(stderr, "Too many functions\n");
                break;
            }

            current = &funcs[func_count++];
            strncpy(current->name, name, sizeof(current->name));
            current->start_addr = addr;
            current->end_addr = addr; // temporarily
            current->is_hacl = is_hacl_function(name);
        }
    }

    // If last function was found, end at last address seen (guess)
    if (current && current->end_addr == current->start_addr) {
        current->end_addr = current->start_addr + 1; // fallback to 1 byte
    }

    fclose(f);

    write_json(argv[2], funcs, func_count);
    printf("Wrote %d functions to %s\n", func_count, argv[2]);

    return 0;
}
