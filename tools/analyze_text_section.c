#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_LINE 1024
#define MAX_FUNC 2048
#define MAX_HACL_FUNCS 2048

typedef struct {
    char name[256];
    uint64_t start_addr;
    uint64_t end_addr;
    bool is_hacl;
    bool is_edger8r;  // NEW
} FunctionInfo;


char* hacl_func_list[MAX_HACL_FUNCS];
int hacl_func_count = 0;

bool load_hacl_function_list(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen hacl_function_names.txt");
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Strip trailing newline
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        if (hacl_func_count >= MAX_HACL_FUNCS) {
            fprintf(stderr, "Too many HACL functions\n");
            break;
        }
        hacl_func_list[hacl_func_count++] = strdup(line);
    }

    fclose(f);
    return true;
}


bool is_label_symbol(const char* name) {
    if (name[0] != 'L') return false;
    for (int i = 1; name[i]; ++i) {
        if (!isdigit((unsigned char)name[i])) return false;
    }
    return true;
}


bool is_hacl_function(const char* name) {
    if (name[0] == 'L' && isdigit(name[1])) return false;
    for (int i = 0; i < hacl_func_count; ++i) {
        if (strcmp(name, hacl_func_list[i]) == 0) {
            return true;
        }
    }
    return false;
}

bool is_edger8r_function(const char* name) {
    return strncmp(name, "sgx_", 4) == 0;
}


void write_json(const char* out_file, FunctionInfo* funcs, int count) {
    FILE* out = fopen(out_file, "w");
    if (!out) {
        perror("fopen output");
        return;
    }

    fprintf(out, "[\n");
    for (int i = 0; i < count; ++i) {
        uint64_t size_bytes = funcs[i].end_addr > funcs[i].start_addr
            ? funcs[i].end_addr - funcs[i].start_addr
            : 0;
            fprintf(out,
                "  {\n"
                "    \"name\": \"%s\",\n"
                "    \"is_hacl\": %s,\n"
                "    \"is_edger8r\": %s,\n"
                "    \"size_bytes\": %lu\n"
                "  }%s\n",
                funcs[i].name,
                funcs[i].is_hacl ? "true" : "false",
                funcs[i].is_edger8r ? "true" : "false",
                size_bytes,
                i == count - 1 ? "" : ",");
    }
    fprintf(out, "]\n");
    fclose(out);
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <objdump.txt> <output.json> <hacl_function_names.txt>\n", argv[0]);
        return 1;
    }

    const char* objdump_path = argv[1];
    const char* output_path = argv[2];
    const char* hacl_list_path = argv[3];

    if (!load_hacl_function_list(hacl_list_path)) {
        return 1;
    }

    FILE* f = fopen(objdump_path, "r");
    if (!f) {
        perror("fopen objdump input");
        return 1;
    }

    FunctionInfo funcs[MAX_FUNC];
    int func_count = 0;

    char line[MAX_LINE];
    FunctionInfo* current = NULL;
    uint64_t last_valid_addr = 0;

    bool in_text_section = false;

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "Disassembly of section ") != NULL) {
            if (strstr(line, ".text") != NULL || strstr(line, ".nipx") != NULL) {
                in_text_section = true;
                printf("[info] Entering code section: %s", line);  // optional
            } else {
                in_text_section = false;
            }
            continue;
        }

        if (strstr(line, "Disassembly of section ") != NULL) {
            in_text_section = false;
            continue;
        }

        if (!in_text_section) {
            continue; // skip functions outside .text
        }
        uint64_t addr;
        char name[256];

        // Match function header: 00000000000f3fa0 <func_name>:
        if (sscanf(line, "%lx <%[^>]>:", &addr, name) == 2) {
            if (is_label_symbol(name)) {
                continue;  // Skip local label like L0, L42, etc.
            }

            if (current != NULL) {
                current->end_addr = addr;
            }

            if (func_count >= MAX_FUNC) {
                fprintf(stderr, "Too many functions\n");
                break;
            }

            current = &funcs[func_count++];
            strncpy(current->name, name, sizeof(current->name));
            current->start_addr = addr;
            current->end_addr = 0;
            current->is_hacl = is_hacl_function(name);
            current->is_edger8r = is_edger8r_function(name); 
        }

        // Track last valid instruction address
        if (sscanf(line, "%lx:", &addr) == 1) {
            if (addr > last_valid_addr) {
                last_valid_addr = addr;
            }
        }
    }

    // Fix final function size
    if (current != NULL && current->end_addr == 0) {
        current->end_addr = last_valid_addr + 16;
    }

    fclose(f);
    write_json(output_path, funcs, func_count);

    // Cleanup
    for (int i = 0; i < hacl_func_count; ++i) {
        free(hacl_func_list[i]);
    }

    printf("Wrote %d functions to %s\n", func_count, output_path);
    return 0;
}
