#!/bin/bash

# Path to the file containing the folder list
FOLDER_LIST="extracted_trusted_folder.txt"

# Check if cloc is installed
if ! command -v cloc &> /dev/null; then
  echo "❌ 'cloc' is not installed. Please install it and try again."
  exit 1
fi

# Check if the file exists
if [ ! -f "$FOLDER_LIST" ]; then
  echo "❌ Folder list file not found: $FOLDER_LIST"
  exit 1
fi

# Read and process each folder path
while IFS= read -r dir; do
  if [ -z "$dir" ]; then
    continue  # Skip empty lines
  fi

  if [ -d "$dir" ]; then
    sum_code=$(cloc "$dir" --quiet | awk '/^SUM:/ {print $5}')
    echo "$dir: $sum_code"
  else
    echo "$dir: Directory not found"
  fi
done < "$FOLDER_LIST"

