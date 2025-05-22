#!/bin/bash

# Check for enclave ELF argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <enclave.elf>"
    exit 1
fi

ENCLAVE_ELF="$1"

# Step 1: Compile the map_rips tool from ../tools/
echo "[+] Compiling map_rips from ../../tools/"
gcc -o map_rips ../../tools/map_rips.c || { echo "[-] Compilation failed"; exit 1; }

# Step 2: Run the SGX app and capture debug output
echo "[+] Running app and capturing output to debug_info.txt"
sudo ./app > debug_info.txt || { echo "[-] Failed to run ./app"; exit 1; }

# Step 3: Disassemble enclave ELF
echo "[+] Disassembling $ENCLAVE_ELF to enclave_dump.txt"
objdump -D "$ENCLAVE_ELF" > enclave_dump.txt || { echo "[-] objdump failed"; exit 1; }

# Step 4: Execute map_rips tool
echo "[+] Running map_rips to analyze RIP trace"
./map_rips debug_info.txt enclave_dump.txt