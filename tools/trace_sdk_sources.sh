#!/bin/bash

# Path to SGX SDK source
SGX_SDK_SRC="$HOME/linux-sgx"

# Path to where the .a libraries are stored
LIB_DIR="/opt/intel/sgxsdk/lib64"

# Hardcoded list of archive files (relative to LIB_DIR)
ARCHIVES=(
  libsgx_tcrypto.a
  libsgx_tstdc.a
  libsgx_trts.a
  libsgx_tservice.a
)

# Track folders that contained matched source files
declare -A matched_dirs

for rel_path in "${ARCHIVES[@]}"; do
  archive="$LIB_DIR/$rel_path"

  if [ ! -f "$archive" ]; then
    echo "❌ Archive not found: $archive"
    continue
  fi

  echo ""
  echo "===================================================="
  echo "[PROCESSING] Archive: $archive"
  echo "----------------------------------------------------"

  # Extract function symbols (T for text/code section)
  SYMBOLS=$(nm -a -C "$archive" 2>/dev/null | awk '$2 ~ /^[Tt]$/ {print $3}' | sort -u)

  if [ -z "$SYMBOLS" ]; then
    echo "❌ No symbols found in $archive"
    continue
  fi

  printf "%-30s %s\n" "Function Symbol" "Matched Source Path"
  printf "%-30s %s\n" "------------------------------" "-------------------"

  while IFS= read -r symbol; do
    # Strip C++ decorations if any, only keep base function name
    base=$(basename "$symbol" | sed 's/(.*//g')
    match=$(find "$SGX_SDK_SRC" -type f \( -name "$base.c" -o -name "$base.cpp" \) | head -n 1)

    if [ -n "$match" ]; then
      printf "%-30s %s\n" "$symbol" "$match"
      dir=$(dirname "$match")
      matched_dirs["$dir"]=1
    fi
  done <<< "$SYMBOLS"
done

echo ""
echo "===================================================="
echo "[SUMMARY] SDK Folders Containing Matched Sources"
echo "----------------------------------------------------"
for dir in "${!matched_dirs[@]}"; do
  echo "$dir"
done
