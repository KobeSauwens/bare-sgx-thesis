#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_LINE 1024
#define MAX_RIPS 8192
#define MAX_INSTR 65536

typedef struct {
    unsigned int rip;
    char instr[MAX_LINE];
    char func[MAX_LINE];
} Instr;

Instr disasm[MAX_INSTR];
int disasm_count = 0;

unsigned int rips[MAX_RIPS];
int rip_count = 0;

void load_disasm(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open disassembly");
        exit(1);
    }

    char line[MAX_LINE];
    char current_func[MAX_LINE] = "unknown";

    while (fgets(line, sizeof(line), f)) {
        unsigned int addr;
        if (sscanf(line, "%x <%[^>]>:", &addr, current_func) == 2) {
            continue;  // It's a function label
        }

        char *colon = strchr(line, ':');
        if (!colon || colon - line < 1) continue;

        *colon = '\0';
        addr = (unsigned int)strtoul(line, NULL, 16);
        char *instr_ptr = colon + 1;

        disasm[disasm_count].rip = addr;
        strncpy(disasm[disasm_count].instr, instr_ptr, MAX_LINE - 1);
        strncpy(disasm[disasm_count].func, current_func, MAX_LINE - 1);
        disasm_count++;
    }

    fclose(f);
}

void load_rips(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open debug log");
        exit(1);
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        unsigned int rip;
        if (sscanf(line, " [main.c] ^^ enclave RIP=0x%x", &rip) == 1) {
            rips[rip_count++] = rip;
        }
    }

    fclose(f);
}

Instr *lookup_instr(unsigned int rip) {
    for (int i = 0; i < disasm_count; i++) {
        if (disasm[i].rip == rip) {
            return &disasm[i];
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <debug_log> <enclave_dump>\n", argv[0]);
        return 1;
    }

    load_disasm(argv[2]);
    load_rips(argv[1]);

    printf("%-10s  %-30s  %s\n", "RIP", "Function", "Instruction");
    printf("----------  ------------------------------  -------------------------\n");

    char last_func[MAX_LINE] = "";
    for (int i = 0; i < rip_count; i++) {
        Instr *instr = lookup_instr(rips[i]);
        if (!instr) {
            printf("0x%04x     %-30s  %s\n", rips[i], "(unknown)", "UNKNOWN");
            continue;
        }

        if (strcmp(last_func, instr->func) != 0) {
            printf("\n== Entering function: %s ==\n\n", instr->func);
            strncpy(last_func, instr->func, MAX_LINE);
        }

        printf("0x%04x     %-30s  %s", rips[i], instr->func, instr->instr);
    }

    return 0;
}
