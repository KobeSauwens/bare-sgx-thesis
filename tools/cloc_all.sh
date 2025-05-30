#!/bin/bash

# Check usage
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/to/target-directory"
  exit 1
fi

TARGET_DIR="$1"

# Check for cloc
if ! command -v cloc &> /dev/null; then
  echo "❌ cloc not found. Install with: sudo apt install cloc"
  exit 1
fi

# Check if valid dir
if [ ! -d "$TARGET_DIR" ]; then
  echo "❌ Not a directory: $TARGET_DIR"
  exit 1
fi

echo "[INFO] Running cloc individually on each file/folder in: $TARGET_DIR"
echo "----------------------------------------------------------------------"

# Loop over all non-hidden items in the directory (non-recursive)
find "$TARGET_DIR" -mindepth 1 -maxdepth 1 -not -name '.*' | while read -r item; do
  echo ""
  echo ">>> cloc on: $item"
  echo "--------------------"
  cloc "$item"
done
