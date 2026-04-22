#!/usr/bin/env python3
"""
Clean up old outputs to start fresh with debugging enabled.
Run this before re-running disassemble.py
"""

import os
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMBINED_OUTPUT = os.path.join(SCRIPT_DIR, "combined_output")
INTERMEDIATE_OUTPUT = os.path.join(SCRIPT_DIR, "intermediate_output")

print("Cleaning up old analysis output...")
print()

# Remove combined output
if os.path.exists(COMBINED_OUTPUT):
    try:
        shutil.rmtree(COMBINED_OUTPUT)
        print(f"[✓] Removed: {COMBINED_OUTPUT}")
    except Exception as e:
        print(f"[!] Failed to remove {COMBINED_OUTPUT}: {e}")

# Remove intermediate output
if os.path.exists(INTERMEDIATE_OUTPUT):
    try:
        shutil.rmtree(INTERMEDIATE_OUTPUT)
        print(f"[✓] Removed: {INTERMEDIATE_OUTPUT}")
    except Exception as e:
        print(f"[!] Failed to remove {INTERMEDIATE_OUTPUT}: {e}")

print()
print("Recreating output directories...")
os.makedirs(COMBINED_OUTPUT, exist_ok=True)
os.makedirs(INTERMEDIATE_OUTPUT, exist_ok=True)
print()

print("Ready to re-run: python disassemble.py")
print()
print("Note: Debugging is now enabled - you'll see detailed Ghidra output")
