# Technical Fixes - Detailed Report

## Issues Found and Fixed

### 1. export_asm.py - Address Object Formatting (FIXED)

**Issue:** 
```python
# ❌ BEFORE
f.write("0x%s:\t%s\t%s\n" % (addr, mnemonic, ops))
```

In Jython (Ghidra's Python environment), the `addr` variable is an `Address` object from Ghidra's API, not a string. When you directly format it into a string using `%s`, it may not produce the expected hex format.

**Fix:**
```python
# ✅ AFTER
f.write("0x%s:\t%s\t%s\n" % (str(addr), mnemonic, ops))
```

**Why it matters:**
- Ensures consistent hex address formatting in output
- Prevents potential type coercion issues with Ghidra objects
- Makes output parsing more reliable

---

### 2. ExportGraphs.java - JSON Escape Null Safety (FIXED)

**Issue:**
```java
// ❌ BEFORE
private String escapeJson(String s) {
    return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            ...
}
```

If `escapeJson()` receives a null string (e.g., from a function with no name), it throws `NullPointerException`.

**Fix:**
```java
// ✅ AFTER
private String escapeJson(String s) {
    if (s == null) return "";
    return s.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            ...
}
```

**Why it matters:**
- Prevents crashes when analyzing binaries with missing symbols
- Handles edge cases gracefully
- Makes JSON output valid even with unusual binaries

---

## Code Quality Improvements

### ExportAsm.java & ExportGraphs.java
These scripts already have good practices:
- ✅ Proper resource management (try-finally blocks)
- ✅ Directory creation before writing
- ✅ Function count validation
- ✅ Instruction normalization (registers, immediates, memory refs)
- ✅ Progress reporting via println()

---

## How the Pipeline Works

### 1. Headless Ghidra Execution
```bash
analyzeHeadless.bat [project_dir] [project_name] 
  -import [binary] 
  -scriptPath [script_directory]
  -postScript [script1] [arg1]
  -postScript [script2] [arg2]
```

### 2. Script Execution Order
1. Ghidra analyzes binary automatically
2. After analysis completes, `-postScript` commands run:
   - **ExportAsm.java** exports normalized assembly
   - **ExportGraphs.java** exports CFG + DFG as JSON

### 3. Data Flow
```
Binary (.exe)
    ↓
[Ghidra Analysis]
    ↓
ExportAsm.java  → assembly.asm
ExportGraphs.java → graphs.json
    ↓
disassemble.py combines into JSON
    ↓
combined_output/*.json (ML-ready)
```

---

## Normalization Strategy

### Register Normalization
- **SP Registers:** rsp, esp → "SP"
- **BP Registers:** rbp, ebp → "BP"  
- **Size-based:** 64-bit → "REG64", 32-bit → "REG32", etc.
- **Default:** Unknown → "REG"

```java
private String normalizeRegister(Register reg) {
    if (reg == null) return "REG";
    String name = reg.getName().toLowerCase();
    if (name.equals("rsp") || name.equals("esp")) return "SP";
    if (name.equals("rbp") || name.equals("ebp")) return "BP";
    
    int size = reg.getBitLength();
    if (size == 64) return "REG64";
    if (size == 32) return "REG32";
    ...
}
```

### Operand Types
- **Registers:** Register objects → normalized names
- **Immediates:** Scalar objects → "IMM"
- **Memory:** Address objects → "MEM"  
- **Unknown:** Other types → "UNK"

### P-Code Variables (for DFG)
- **Register variables:** Normalized like above
- **Unique variables:** TMP_[offset] (preserved for identity)
- **Constants:** "IMM"
- **Addresses:** "MEM"

---

## Error Handling

### Current Safeguards

1. **Directory Creation**
   ```java
   File parentDir = outFile.getParentFile();
   if (parentDir != null && !parentDir.exists()) {
       parentDir.mkdirs();  // Create missing directories
   }
   ```

2. **Null Checks**
   ```java
   if (s == null) return "";  // Handle null strings
   if (ops == null) continue;  // Skip missing operands
   ```

3. **Progress Monitoring**
   ```java
   if (monitor.isCancelled()) break;  // Allow user cancellation
   ```

4. **Resource Cleanup**
   ```java
   try {
       // Write data
   } finally {
       writer.close();  // Always close file
   }
   ```

---

## JSON Output Schema

### Combined Output (disassemble.py)
```json
{
  "binary": "malware.exe",
  "source_path": "/full/path/to/malware.exe",
  "label": 1,
  "label_name": "cryptojacking",
  "asm": "...",
  "graphs": [...]
}
```

### Assembly Format
```
; Disassembly of: [program_name]
; Format: PE (or ELF, Mach-O, etc.)
; Architecture: x86-64
; Functions: [count]

; --- Function: [name] (0x[entry_point]) ---
0x401000:   mov     REG64 | IMM
0x401003:   push    SP
```

### Graph Function Object
```json
{
  "function": "main",
  "entry": "0x401000",
  "instruction_count": 42,
  "instructions": [
    {"addr": "0x401000", "mnemonic": "mov", "operands": "REG64 IMM", "idx": 0}
  ],
  "cfg_nodes": [
    {"start": "0x401000", "end": "0x401010", "instr_indices": [0,1,2]}
  ],
  "cfg_edges": [
    {"from": "0x401000", "to": "0x401020", "type": "unconditional_jump"}
  ],
  "dfg_edges": [
    {"from": 0, "to": 5, "var": "SP"}
  ]
}
```

---

## Testing Recommendations

### Test Case 1: Simple Binary
```bash
# Test with a minimal PE binary
# Expected: Should generate assembly and graphs for all functions
```

### Test Case 2: UPX-Packed Binary  
```bash
# Test with upx sample
# Expected: Should auto-detect, unpack, then analyze
```

### Test Case 3: Stripped Binary
```bash
# Test with symbols removed
# Expected: Should handle gracefully with generic function names
```

### Test Case 4: Large Binary
```bash
# Test with complex binary > 100 functions
# Expected: Should respect timeout, output partial results
```

---

## Performance Considerations

### Bottlenecks
1. **Ghidra Analysis:** 80-90% of execution time
   - Disassembly: automatic function discovery
   - Decompilation: type/function analysis
   
2. **Data Extraction:** 10-20% of execution time
   - Instruction iteration: fast
   - P-code generation: moderate
   - JSON serialization: fast

### Optimization Tips
1. Adjust analysis depth in Ghidra settings
2. Use `-analysisTimeoutPerFile` appropriately  
3. Batch processing via `disassemble.py`
4. Cache analysis in Ghidra project (if reusing)

---

## Integration with GraphCodeBERT

These outputs are designed for graph neural network training:

1. **Assembly normalization:** Reduces vocabulary size
2. **CFG export:** Provides program structure
3. **DFG export:** Provides data dependencies
4. **Label included:** Ready for supervised learning

See `GraphCodeBERT_Stage2_Classification.ipynb` for usage.
