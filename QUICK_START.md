# Quick Start - Ghidra Analysis Pipeline

## TL;DR - Run This

```bash
cd d:\BSCS\Cryptojacking Detection Thesis\thesis
python disassemble.py
```

That's it! This will:
1. ✅ Analyze all binaries in `benign/` and `cryptojacking/` directories
2. ✅ Extract assembly code (normalized)
3. ✅ Extract CFG (Control Flow Graph)
4. ✅ Extract DFG (Data Flow Graph)  
5. ✅ Save to `combined_output/` as JSON

## Before Running

1. **Ensure Ghidra is installed:**
   ```bash
   # Verify this file exists
   dir "C:\Thesis\ghidra\support\analyzeHeadless.bat"
   ```

2. **Place your binaries in correct directories:**
   ```
   thesis/
   ├── benign/
   │   ├── bin1.exe
   │   └── bin2.exe
   └── cryptojacking/
       ├── mal1.exe
       └── mal2.exe
   ```

3. **Install dependencies (if needed):**
   ```bash
   pip install pyghidra
   ```

## What Gets Exported

### Assembly Code (ExportAsm.java)
- Normalized instructions per function
- Registers abstracted: SP, BP, REG64, REG32, etc.
- Immediates marked as IMM
- Memory refs marked as MEM

### Control Flow Graph (ExportGraphs.java)
- Instruction-level CFG nodes
- Block boundaries
- Edge types (jump, call, return, etc.)

### Data Flow Graph (ExportGraphs.java)
- P-code based variable dependencies
- Tracking register and memory uses/defs
- Normalized variable names

## Troubleshoot

| Problem | Solution |
|---------|----------|
| Ghidra not found | Update `GHIDRA_PATH` in disassemble.py |
| Scripts not found | Check `ghidra_scripts/` exists |
| Timeout errors | Increase `-analysisTimeoutPerFile` in disassemble.py |
| UPX binaries fail | Install UPX: `choco install upx` |
| No output | Check binary format (PE/ELF), check Ghidra console |

## Manual Single Binary

```bash
C:\Thesis\ghidra\support\analyzeHeadless.bat ^
  C:\Thesis\ghidra\projects\Test Test ^
  -import "C:\path\to\binary.exe" ^
  -scriptPath "d:\BSCS\Cryptojacking Detection Thesis\thesis\ghidra_scripts" ^
  -postScript "ExportAsm.java" "output.asm" ^
  -postScript "ExportGraphs.java" "output.json" ^
  -deleteProject
```

## Fixed Issues

✅ **export_asm.py** - Fixed Address object formatting in Jython  
✅ **ExportGraphs.java** - Added null check in JSON escaping  
✅ **All scripts** - Improved compatibility with headless Ghidra

## Output Example

**combined_output/cryptojacking/malware.exe.json:**
```json
{
  "binary": "malware.exe",
  "label": 1,
  "label_name": "cryptojacking",
  "asm": "; Disassembly of: malware.exe\n...",
  "graphs": [
    {
      "function": "main",
      "entry": "0x401000",
      "instruction_count": 42,
      "instructions": [...],
      "cfg_nodes": [...],
      "cfg_edges": [...],
      "dfg_edges": [...]
    }
  ]
}
```

Ready to analyze! 🚀
