# Troubleshooting: "getScriptArgs is not defined"

## Problem

You're seeing an error like:
```
NameError: getScriptArgs is not defined
```

## Root Cause

The `getScriptArgs()` function is **only available inside Ghidra's scripting environment**. It's not a standard Python function - it's provided by Ghidra when scripts run via `analyzeHeadless.bat`.

### ❌ These Will Fail
```bash
# Direct Python execution - NOT supported
python export_asm.py

# Python IDLE or notebooks
# These don't have Ghidra context
```

### ✅ This Will Work
```bash
# Through Ghidra's headless analyzer - CORRECT
C:\Thesis\ghidra\support\analyzeHeadless.bat ^
  C:\Thesis\ghidra\projects\MyProject MyProject ^
  -import binary.exe ^
  -scriptPath "path\to\scripts" ^
  -postScript "ExportAsm.java" "output.asm" ^
  -deleteProject
```

## Solution

### If You're Using `disassemble.py` (Recommended)

The script handles all of this for you - just make sure:

1. **Ghidra path is correct** in `disassemble.py`:
   ```python
   GHIDRA_PATH = r"C:\Thesis\ghidra\support\analyzeHeadless.bat"
   ```

2. **Script directory is correct**:
   ```python
   SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "ghidra_scripts")
   # Should point to where ExportAsm.java and ExportGraphs.java are located
   ```

3. **Run via Python**:
   ```bash
   python disassemble.py
   ```

### If Running Manually

**Option A: Windows Command (PowerShell)**
```powershell
$GHIDRA = "C:\Thesis\ghidra\support\analyzeHeadless.bat"
$PROJECT = "C:\Thesis\ghidra\projects\Test"
$BINARY = "C:\path\to\binary.exe"
$OUTPUT_ASM = "C:\output\asm.asm"
$OUTPUT_GRAPH = "C:\output\graphs.json"
$SCRIPTS = "d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts"

& $GHIDRA $PROJECT Test `
  -import $BINARY `
  -scriptPath $SCRIPTS `
  -postScript "ExportAsm.java" $OUTPUT_ASM `
  -postScript "ExportGraphs.java" $OUTPUT_GRAPH `
  -deleteProject
```

**Option B: Batch Script (CMD)**
```batch
@echo off
set GHIDRA=C:\Thesis\ghidra\support\analyzeHeadless.bat
set PROJECT=C:\Thesis\ghidra\projects\Test
set BINARY=C:\path\to\binary.exe
set SCRIPTS=d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts

%GHIDRA% %PROJECT% Test ^
  -import %BINARY% ^
  -scriptPath %SCRIPTS% ^
  -postScript "ExportAsm.java" "output.asm" ^
  -postScript "ExportGraphs.java" "output.json" ^
  -deleteProject

echo Done!
```

## Verify Setup

Before running analysis, check:

```bash
# 1. Ghidra exists
dir "C:\Thesis\ghidra\support\analyzeHeadless.bat"

# 2. Scripts exist
dir "d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts\ExportAsm.java"
dir "d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts\ExportGraphs.java"

# 3. Python dependencies installed
pip list | findstr pyghidra
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Running `python export_asm.py` directly | Use `disassemble.py` or `analyzeHeadless.bat` with `-postScript` |
| Wrong Ghidra path | Verify `GHIDRA_PATH` in `disassemble.py` points to real `.bat` file |
| Scripts not in correct directory | Use `-scriptPath` to point to `ghidra_scripts/` folder |
| Missing output path argument | Always provide output path: `-postScript "Script.java" "output.txt"` |
| Typo in script names | Ensure exact names: `ExportAsm.java` and `ExportGraphs.java` |

## Debug Mode

To see what's happening:

1. **Check Ghidra output** - Look for any ERROR or WARNING messages
2. **Verify files created** - Check if output `.asm` and `.json` exist
3. **Add logging** to `disassemble.py`:
   ```python
   # In disassemble.py, set verbose output:
   for line in (result.stdout or "").splitlines():
       print(f"    [GHIDRA] {line.strip()}")  # Print ALL output, not filtered
   ```

## Still Not Working?

Check that:
1. Binary file actually exists: `test-path "C:\path\to\binary.exe"`
2. Ghidra can analyze it (try opening in GUI first)
3. Project directory is writable: `dir "C:\Thesis\ghidra\projects\"`
4. No special characters in binary path or output path

If still stuck, share:
- Full error message
- Command you ran
- Output from Ghidra (all lines)
