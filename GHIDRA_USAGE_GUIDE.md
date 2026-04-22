# Ghidra Analysis Scripts - Usage Guide

This guide explains how to use the three Ghidra post-analysis scripts for extracting assembly code, CFG (Control Flow Graph), and DFG (Data Flow Graph) from executables.

## Overview

The analysis pipeline consists of three components:

1. **ExportAsm.java** - Exports normalized assembly code from all functions
2. **ExportGraphs.java** - Exports per-function CFG and DFG for machine learning pipeline
3. **disassemble.py** - Python orchestrator that runs Ghidra headless on multiple binaries

## Setup Requirements

### 1. Install Ghidra
```bash
# Download from https://ghidra-sre.org/
# Extract to a known location (e.g., C:\Thesis\ghidra)
```

### 2. Verify Ghidra Installation
```bash
# Check if Ghidra headless analyzer exists
C:\Thesis\ghidra\support\analyzeHeadless.bat
```

### 3. Prepare Python Environment
```bash
pip install pyghidra  # Already done based on your terminal
```

## Running Individual Binaries

### Option A: Using the Orchestrator Script (Recommended)

The `disassemble.py` script automates the entire process:

```bash
# Setup your binary directories
cd d:\BSCS\Cryptojacking Detection Thesis\thesis

# Create directories for organized binaries
mkdir benign
mkdir cryptojacking

# Place your binaries in these directories
# For cryptojacking samples:
# cryptojacking/sample1.exe
# cryptojacking/sample2.exe
# For benign samples:
# benign/sample1.exe

# Run the analysis
python disassemble.py
```

**What it does:**
1. Scans `benign/` and `cryptojacking/` directories recursively
2. Auto-detects and unpacks UPX-packed binaries
3. Runs Ghidra analysis on each binary
4. Exports assembly and graph data
5. Combines outputs into JSON files in `combined_output/`

### Option B: Manual Command Line

If you want to run Ghidra directly on a single binary:

```bash
C:\Thesis\ghidra\support\analyzeHeadless.bat ^
  C:\Thesis\ghidra\projects\MalwareProject MalwareProject ^
  -import "path\to\binary.exe" ^
  -scriptPath "d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts" ^
  -postScript "ExportAsm.java" "output\asm.asm" ^
  -postScript "ExportGraphs.java" "output\graphs.json" ^
  -deleteProject ^
  -analysisTimeoutPerFile 3600
```

**Parameters explained:**
- `C:\Thesis\ghidra\projects\MalwareProject` - Ghidra project directory
- `MalwareProject` - Project name  
- `-import` - Binary to analyze
- `-scriptPath` - Directory containing the Java scripts
- `-postScript` - Run after analysis (can use multiple times)
- `-deleteProject` - Clean up after (saves disk space)
- `-analysisTimeoutPerFile` - Timeout in seconds (3600 = 1 hour)

## Output Files

### Assembly Output (.asm)
```
; Disassembly of: sample.exe
; Format: PE
; Architecture: x86-64
; Functions: 125

; --- Function: main (0x401000) ---
0x401000:	push	BP
0x401001:	mov	BP | SP
0x401003:	sub	SP | IMM
...
```

**Format:**
- Normalized register names (SP, BP, REG64, REG32, etc.)
- Immediate values as IMM
- Memory references as MEM
- Operands separated by ` | `

### Graph Output (graphs.json)
```json
[
  {
    "function": "main",
    "entry": "0x401000",
    "instruction_count": 42,
    "instructions": [
      {
        "addr": "0x401000",
        "mnemonic": "push",
        "operands": "BP",
        "idx": 0
      }
    ],
    "cfg_nodes": [
      {
        "start": "0x401000",
        "end": "0x401010",
        "instr_indices": [0, 1, 2, 3]
      }
    ],
    "cfg_edges": [
      {
        "from": "0x401000",
        "to": "0x401020",
        "type": "unconditional_jump"
      }
    ],
    "dfg_edges": [
      {
        "from": 0,
        "to": 5,
        "var": "SP"
      }
    ]
  }
]
```

## Troubleshooting

### Issue: "ERROR: No output path provided"
**Cause:** Script arguments not passed correctly
**Fix:** Ensure `-postScript "ScriptName.java" "output_path"` format is exactly correct

### Issue: "Script not found"
**Cause:** Script directory or script names incorrect
**Fix:** Verify:
```bash
# Check files exist
dir d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts\
# Should show: ExportAsm.java, ExportGraphs.java, export_asm.py
```

### Issue: "Analysis timed out"
**Cause:** Binary too complex or timeout too short
**Fix:** Increase `-analysisTimeoutPerFile` (e.g., 7200 for 2 hours)

### Issue: "No output generated"
**Cause:** Function count = 0 or all functions skipped
**Fix:** 
- Ensure binary is valid and properly analyzed
- Check if it's stripped or obfuscated
- Look at Ghidra console output for analysis warnings

### Issue: "UPX not found"
**Cause:** UPX decompressor not in PATH
**Fix:**
```bash
# Install UPX
choco install upx
# Or download from: https://upx.github.io/

# Add to PATH or install to C:\Windows\System32\
```

## Output Directory Structure

```
thesis/
├── combined_output/           # Final ML-ready JSON files
│   ├── benign/
│   │   ├── sample1.exe.json
│   │   └── sample2.exe.json
│   └── cryptojacking/
│       ├── sample1.exe.json
│       └── sample2.exe.json
├── intermediate_output/       # (Deleted if KEEP_INTERMEDIATE=False)
│   ├── asm/
│   └── graph/
└── ghidra_scripts/
    ├── ExportAsm.java         # Assembly export
    ├── ExportGraphs.java      # Graph export
    └── export_asm.py          # Alternative Jython version
```

## Performance Tips

1. **Batch Processing:** `disassemble.py` processes all binaries automatically
2. **UPX Detection:** Automatically detects and unpacks UPX-packed samples
3. **Timeout Tuning:** Adjust timeout based on binary complexity:
   - Simple binaries: 300-600 seconds
   - Medium binaries: 600-1800 seconds
   - Large/obfuscated: 3600+ seconds

4. **Keep Intermediate Files:** Set `KEEP_INTERMEDIATE=True` if you want to inspect .asm and .json separately

## Next Steps: Using Output for GraphCodeBERT

The combined JSON output is ready for GraphCodeBERT fine-tuning:
- `asm` field contains normalized assembly
- `graphs` field contains CFG and DFG structures
- Labels (`label_name`: "benign" or "cryptojacking") are included

See `GraphCodeBERT_Stage2_Classification.ipynb` for how to use this data.

## Configuration

Edit `disassemble.py` to customize:

```python
# Paths
GHIDRA_PATH = r"C:\Thesis\ghidra\support\analyzeHeadless.bat"
PROJECT_DIR = r"C:\Thesis\ghidra\projects\MalwareProject"
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "ghidra_scripts")

# Input sources
INPUT_ROOTS = [
    os.path.join(SCRIPT_DIR, "benign"),
    os.path.join(SCRIPT_DIR, "cryptojacking"),
]

# Output location
OUTPUT_ROOT = os.path.join(SCRIPT_DIR, "combined_output")

# Keep intermediate files
KEEP_INTERMEDIATE = False  # Set to True to debug
```
