#!/bin/bash
# Script to count SGX SDK runtime LOC (code only) per component using cloc, no jq required

SGX_SDK_PATH="$HOME/linux-sgx/sdk"
OUTFILE="sgx_runtime_loc_summary.txt"

COMPONENTS=(
  tkey_exchange
  tlibc
  tlibcrypto
  tlibcxx
  tlibthread
  tmm_rsrv
  trts
  tsafecrt
  tseal
  tsetjmp
  ttlstrts
  tlibc
  tlibcrypto
  tlibthread
  tseal
  tkey_exchange
  tsafecrt
)

echo "[INFO] Counting SGX SDK runtime LOC (code only) in: $SGX_SDK_PATH" | tee "$OUTFILE"
echo "---------------------------------------------------------------" | tee -a "$OUTFILE"

# Check cloc is installed
if ! command -v cloc &> /dev/null; then
    echo "❌ cloc is not installed. Install with: sudo apt install cloc" | tee -a "$OUTFILE"
    exit 1
fi

# Output header
printf "%-20s %10s\n" "Component" "LOC" | tee -a "$OUTFILE"
printf "%-20s %10s\n" "---------" "---" | tee -a "$OUTFILE"

# Count LOC per component
for dir in "${COMPONENTS[@]}"; do
  full_path="$SGX_SDK_PATH/$dir"
  if [ -d "$full_path" ]; then
    loc=$(cloc "$full_path" --quiet --json 2>/dev/null \
          | awk '/"SUM"/ {found=1} found && /"code"/ {gsub(/[",]/, "", $2); print $2; exit}')
    printf "%-20s %10s\n" "$dir" "$loc" | tee -a "$OUTFILE"
  else
    printf "%-20s %10s\n" "$dir" "[SKIPPED]" | tee -a "$OUTFILE"
  fi
done
