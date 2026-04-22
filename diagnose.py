#!/usr/bin/env python3
"""
Diagnostic script to verify Ghidra setup before running analysis.
Run this to debug any configuration issues.
"""

import os
import sys
import shutil
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths to check
GHIDRA_PATH = os.path.join(SCRIPT_DIR, "ghidra", "support", "analyzeHeadless.bat")
PROJECT_DIR = os.path.join(SCRIPT_DIR, "ghidra_projects", "MalwareProject")
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "ghidra_scripts")
BENIGN_DIR = os.path.join(SCRIPT_DIR, "benign")
CRYPTO_DIR = os.path.join(SCRIPT_DIR, "cryptojacking")

print("=" * 70)
print("GHIDRA ANALYSIS - DIAGNOSTIC CHECK")
print("=" * 70)
print()

# Check 1: Script directory
print("[✓] Script directory:", SCRIPT_DIR)
if not os.path.exists(SCRIPT_DIR):
    print("    [!] ERROR: Script directory not found!")
    sys.exit(1)
print()

# Check 2: Ghidra installation
print("[*] Checking Ghidra installation...")
if os.path.exists(GHIDRA_PATH):
    print("    [✓] Found:", GHIDRA_PATH)
else:
    print("    [!] ERROR: Not found:", GHIDRA_PATH)
    print("    Expected path: " + GHIDRA_PATH)
    print("    Does ghidra/support/ exist?", os.path.exists(os.path.dirname(GHIDRA_PATH)))
    sys.exit(1)

# Check 3: Ghidra scripts
print()
print("[*] Checking Ghidra scripts...")
scripts_to_check = ["ExportAsm.java", "ExportGraphs.java", "export_asm.py"]
all_scripts_found = True
for script in scripts_to_check:
    script_path = os.path.join(SCRIPTS_DIR, script)
    if os.path.exists(script_path):
        print(f"    [✓] Found: {script}")
    else:
        print(f"    [!] Missing: {script} (expected at {script_path})")
        all_scripts_found = False

if not all_scripts_found:
    sys.exit(1)
print()

# Check 4: Input directories
print("[*] Checking input directories...")
print()
for input_dir, label in [(BENIGN_DIR, "Benign"), (CRYPTO_DIR, "Cryptojacking")]:
    if os.path.exists(input_dir):
        file_count = len([f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))])
        print(f"    [✓] {label:20} {file_count:3} files")
        if file_count == 0:
            print(f"         ^ WARNING: No binaries found")
    else:
        print(f"    [!] {label:20} NOT FOUND (optional)")
        print(f"       Create directory: {input_dir}")

print()

# Check 5: Output directory (will be created)
print("[*] Output configuration...")
output_dir = os.path.join(SCRIPT_DIR, "combined_output")
print(f"    [✓] Output will be saved to: {output_dir}")
print()

# Check 6: Verify file permissions
print("[*] Checking file permissions...")
if os.access(SCRIPT_DIR, os.W_OK):
    print("    [✓] Write permission: OK")
else:
    print("    [!] WARNING: No write permission to script directory")
print()

# Check 7: Run test with analyzeHeadless
print("[*] Testing Ghidra with a simple command...")
try:
    # Try to run analyzeHeadless with -help
    result = subprocess.run(
        [GHIDRA_PATH, "-help"],
        capture_output=True,
        text=True,
        timeout=10
    )
    if "analyzeHeadless" in result.stdout or result.returncode == 0:
        print("    [✓] Ghidra responds correctly")
    else:
        print("    [?] Ghidra output (may be normal):")
        if result.stdout:
            for line in result.stdout.split('\n')[:5]:
                print(f"        {line}")
except subprocess.TimeoutExpired:
    print("    [!] Ghidra timeout (takes too long)")
except Exception as e:
    print(f"    [!] ERROR: {e}")
    print("    Make sure Ghidra is properly installed")
    sys.exit(1)

print()
print("=" * 70)
print("DIAGNOSTIC CHECK COMPLETE")
print("=" * 70)
print()
print("Next steps:")
print("  1. Ensure you have binaries in:")
print(f"     - {BENIGN_DIR}")
print(f"     - {CRYPTO_DIR}")
print()
print("  2. Run the analysis:")
print("     python disassemble.py")
print()
