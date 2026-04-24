import os
import glob
import time
import shutil
from concurrent.futures import ThreadPoolExecutor

def analyze_file(file_path):
    """
    Reads a file in chunks and estimates the instruction count
    by counting the occurrences of '"addr":' which corresponds to
    the start of an instruction block in the Ghidra output.
    """
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    filename = os.path.basename(file_path)
    label = "Unknown"
    
    instruction_count = 0
    chunk_size = 1024 * 1024 * 8 # 8 MB chunks
    
    try:
        with open(file_path, "rb") as f:
            first_chunk = True
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Check for label in the first chunk since the properties are at the top
                if first_chunk:
                    if b'"label_name": "benign"' in chunk or b'"label": 0' in chunk:
                        label = "Benign"
                    elif b'"label_name": "cryptojacking"' in chunk or b'"label": 1' in chunk:
                        label = "Cryptojacking"
                    first_chunk = False
                
                # Count occurrences of the address field
                instruction_count += chunk.count(b'"addr":')
                
        # If the JSON file is extremely small (< 100 KB), it's highly likely packed/broken
        if file_size_mb < 0.1:
            return file_path, filename, 0, file_size_mb, "Suspiciously small file size", label
                
        if instruction_count < 500:
            return file_path, filename, instruction_count, file_size_mb, "Low instruction count (< 500)", label
        else:
            return file_path, filename, instruction_count, file_size_mb, "Good", label
            
    except Exception as e:
        return file_path, filename, -1, file_size_mb, f"Error: {e}", label

def main(directory="combined_output"):
    json_files = glob.glob(os.path.join(directory, "*.json"))
    print(f"Analyzing {len(json_files)} JSON files...\n")
    
    start_time = time.time()
    
    filtered_dir = "filtered_output"
    os.makedirs(filtered_dir, exist_ok=True)
    
    suspicious_files = []
    good_files = []
    filtered_zero_files = []
    
    total_benign = 0
    total_crypto = 0
    
    # Process files concurrently using multithreading to speed up disk I/O
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(analyze_file, json_files)
        
        for result in results:
            file_path, filename, count, size_mb, status, label = result
            
            if count == 0:
                # Automatically move 0-instruction files to filtered output
                target_path = os.path.join(filtered_dir, filename)
                try:
                    shutil.move(file_path, target_path)
                    filtered_zero_files.append((filename, label))
                except Exception as e:
                    print(f"Failed to move {filename}: {e}")
                continue
                
            if label == "Benign":
                total_benign += 1
            elif label == "Cryptojacking":
                total_crypto += 1
            
            if status != "Good":
                suspicious_files.append((filename, count, size_mb, status, label))
            else:
                good_files.append((filename, count, size_mb, label))

    elapsed = time.time() - start_time
    
    print("=== Suspicious / Likely Packed Files (< 500 insts) ===")
    for fname, count, size_mb, reason, label in sorted(suspicious_files, key=lambda x: x[1]):
        print(f"[!] {fname} (Size: {size_mb:.2f} MB) | Label: {label} | {count} insts | {reason}")
        
    print(f"\n--- Filtered 0-instruction Files Moved to '{filtered_dir}' ---")
    for fname, label in filtered_zero_files:
        print(f"  -> {fname} (Label: {label})")
        
    print(f"\nCompleted in {elapsed:.2f} seconds.")
    print(f"Total Good Files (> 500 insts): {len(good_files)}")
    print(f"Total Suspicious Files (1-499 insts): {len(suspicious_files)}")
    print(f"Total 0-instruction Files Filtered: {len(filtered_zero_files)}")
    print(f"  -> Benign count: {total_benign}")
    print(f"  -> Cryptojacking count: {total_crypto}")

if __name__ == "__main__":
    main()
