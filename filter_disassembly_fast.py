import os
import glob
import time
from concurrent.futures import ThreadPoolExecutor

def analyze_file(file_path):
    """
    Reads a file in chunks and estimates the instruction count
    by counting the occurrences of '"addr":' which corresponds to
    the start of an instruction block in the Ghidra output.
    """
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    filename = os.path.basename(file_path)
    
    # If the JSON file is extremely small (< 100 KB), it's highly likely packed/broken
    if file_size_mb < 0.1:
        return filename, 0, file_size_mb, "Suspiciously small file size"
    
    instruction_count = 0
    chunk_size = 1024 * 1024 * 8 # 8 MB chunks
    
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                # Count occurrences of the address field
                instruction_count += chunk.count(b'"addr":')
                
        if instruction_count < 500:
            return filename, instruction_count, file_size_mb, "Low instruction count (< 500)"
        else:
            return filename, instruction_count, file_size_mb, "Good"
            
    except Exception as e:
        return filename, -1, file_size_mb, f"Error: {e}"

def main(directory="combined_output"):
    json_files = glob.glob(os.path.join(directory, "*.json"))
    print(f"Analyzing {len(json_files)} JSON files...\n")
    
    start_time = time.time()
    
    suspicious_files = []
    good_files = []
    
    # Process files concurrently using multithreading to speed up disk I/O
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(analyze_file, json_files)
        
        for result in results:
            filename, count, size_mb, status = result
            if status != "Good":
                suspicious_files.append((filename, count, size_mb, status))
            else:
                good_files.append((filename, count, size_mb))

    elapsed = time.time() - start_time
    
    print("=== Suspicious / Likely Packed Files ===")
    for fname, count, size_mb, reason in sorted(suspicious_files, key=lambda x: x[1]):
        print(f"[!] {fname} (Size: {size_mb:.2f} MB): {count} insts | {reason}")
        
    print(f"\nCompleted in {elapsed:.2f} seconds.")
    print(f"Total Good Files: {len(good_files)}")
    print(f"Total Suspicious Files: {len(suspicious_files)}")

if __name__ == "__main__":
    main()
