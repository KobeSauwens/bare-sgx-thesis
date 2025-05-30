#!/bin/bash

# --- Configurable filenames ---
#../app/bare-crypto-app/enclave/encl.elf 
#BINARY=../app/bare-crypto-app/enclave/encl.elf
#ARCHIVE=../app/bare-crypto-app/enclave/dist/portable-gcc-compatible/libevercrypt.a
#BINARY=../app/sdk-crypto-app/Enclave/encl.so
#ARCHIVE=../app/sdk-crypto-app/Enclave/dist/portable-gcc-compatible/libevercrypt.a
BINARY=../app/oe-crypto-app/enclave/enclave.signed
ARCHIVE=../app/oe-crypto-app/enclave/dist/portable-gcc-compatible/libevercrypt.a

OBJDUMP_OUT=sdk_enclave_dump.txt
HACL_LIST=hacl_function_names.txt
#OUTPUT_JSON=bare_functions.json
#OUTPUT_JSON=sdk_functions.json
OUTPUT_JSON=oe_functions.json
ANALYZER=./analyze_text_section

# --- Step 1: Disassemble binary with demangling ---
echo "[1] Running objdump on $BINARY ..."
objdump -D -C "$BINARY" > "$OBJDUMP_OUT"

# --- Step 2: Extract all HACL function names from the .a archive ---
echo "[2] Extracting function names from $ARCHIVE ..."
nm -a -C --defined-only "$ARCHIVE" | grep ' [TtR] ' | awk '{print $3}' | sort -u > "$HACL_LIST"

echo "[2.1] HACL symbol count: $(wc -l < "$HACL_LIST")"
head -n 5 "$HACL_LIST"

# --- Step 3: Run analyzer ---
echo "[3] Running $ANALYZER to generate $OUTPUT_JSON ..."
"$ANALYZER" "$OBJDUMP_OUT" "$OUTPUT_JSON" "$HACL_LIST"

echo "Done: wrote functions to $OUTPUT_JSON"
