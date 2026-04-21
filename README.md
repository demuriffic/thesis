# Thesis

This repository contains materials for thesis work on malware mining analysis and reverse engineering.

Contents
- disassemble.py: Script for disassembling binaries and building combined JSON output.
- ghidra_scripts/: Ghidra automation scripts.
- combined_output/: Combined JSON artifacts (asm + graphs + label).
- intermediate_output/: Temporary asm/graph files (auto-cleaned by default).
- miners/: Sample miner binaries.
- ghidra_12.0.4_PUBLIC_20260303/: Local copy of Ghidra used for analysis.

Usage
- Put binaries under `benign/` and `cryptojacking/` at the repo root.
- Run disassembly with `python disassemble.py`.
- Combined JSON outputs are saved to `combined_output/` and include:
	- `asm`: disassembly text
	- `graphs`: CFG/DFG JSON array
	- `label`: 0 (benign) or 1 (cryptojacking)
- Use scripts in ghidra_scripts with the Ghidra installation in ghidra_12.0.4_PUBLIC_20260303.

Notes
- Large binary artifacts are included as-is to preserve analysis context.
