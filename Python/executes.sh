#!/bin/bash

# Directory containing pcap files
PCAP_DIR="../test_cases"
# Directory for mining reference files
MINING_REF_DIR="../pcap-files/unenc_mining/xmr"
# Directory where reports will be saved
REPORT_DIR="reports"

# Create reports directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Function to get filename without extension
get_base_filename() {
  local fullpath="$1"
  local filename=$(basename "$fullpath")
  echo "${filename%.*}"
}

# Find all pcap files in the mining reference directory
MINING_REF_FILES=()
while IFS= read -r file; do
  MINING_REF_FILES+=("$file")
done < <(find "$MINING_REF_DIR" -name "*.pcap" -type f)

# Check if we found any reference files
if [ ${#MINING_REF_FILES[@]} -eq 0 ]; then
  echo "No PCAP files found in $MINING_REF_DIR"
  exit 1
fi

echo "Found ${#MINING_REF_FILES[@]} mining reference files:"
for ref_file in "${MINING_REF_FILES[@]}"; do
  echo "  - $(basename "$ref_file")"
done

# Process each pcap file in the target directory
for pcap_file in "$PCAP_DIR"/*.pcap; do
  # Extract filename without extension
  base_filename=$(get_base_filename "$pcap_file")
  
  # Create report filename with same base name
  report_file="${base_filename}_report.txt"
  
  echo "Processing: $pcap_file"
  echo "Report will be saved to: $report_file"
  
  # Build the command with all mining reference files
  cmd="python ./main.py --pcap \"$pcap_file\" --mining-reference"
  for ref_file in "${MINING_REF_FILES[@]}"; do
    cmd+=" \"$ref_file\""
  done
  cmd+=" --verbose --alpha 0.5 --output-txt \"$report_file\""
  
  # Execute the command
  echo "Executing: $cmd"
  eval "$cmd"
  
  echo "Done processing $base_filename"
  echo "--------------------------"
done