#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 1024
#define MAX_RIPS 8192
#define MAX_INSTR 65536

typedef struct {
    unsigned int rip;
    char line[MAX_LINE];
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
    while (fgets(line, sizeof(line), f)) {
        unsigned int addr;
        char *instr_ptr = strchr(line, ':');
        if (!instr_ptr || instr_ptr - line < 4) continue;

        line[instr_ptr - line] = '\0';
        addr = (unsigned int)strtoul(line, NULL, 16);
        instr_ptr++; // skip space after colon

        disasm[disasm_count].rip = addr;
        strncpy(disasm[disasm_count].line, instr_ptr, MAX_LINE - 1);
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

const char *lookup_instr(unsigned int rip) {
    for (int i = 0; i < disasm_count; i++) {
        if (disasm[i].rip == rip) {
            return disasm[i].line;
        }
    }
    return "UNKNOWN";
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <debug_log> <enclave_dump>\n", argv[0]);
        return 1;
    }

    load_disasm(argv[2]);
    load_rips(argv[1]);

    printf("%-10s  %s", "RIP", "Instruction");
    printf("\n-----------  ------------------------\n");

    for (int i = 0; i < rip_count; i++) {
        printf("0x%04x     %s", rips[i], lookup_instr(rips[i]));
    }

    return 0;
}
