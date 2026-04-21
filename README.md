# Cryptojacking Malware Detection via Assembly Pretrained GraphCodeBERT

This repository contains the data generation and machine learning pipeline for detecting Cryptojacking malware via Domain-Adaptive Pretraining (DAPT) on GraphCodeBERT using x86/x64 assembly and control-flow graphs.

## Pipeline Components

1. **Data Extraction**:
   - disassemble.py: Automates Ghidra (v12) headless analyzer to extract raw sm instructions, graphs (CFG/DFG), and labels (0 = benign, 1 = cryptojacking) from Windows executables into JSON format.

2. **Data Filtration**:
   - ilter_disassembly_fast.py: A high-performance, stream-based filtering script to quickly discard "packed" or heavily obfuscated payloads that would degrade modeling quality.

3. **Stage 1 - Assembly Pretraining (DAPT)**:
   - GraphCodeBERT_Stage1_Pretraining.ipynb: A PyTorch / Hugging Face pipeline that streams the compiled JSONs (bypassing RAM-exhaustion limits), using Masked Language Modeling (MLM) to teach the base microsoft/graphcodebert-base model the syntactic structures of x86/x64 assembly. Optimized for consumer hardware (Ryzen 5 5600, RTX 3060 12GB).

## Usage

1. Place raw Windows binary files under enign/ and cryptojacking/ directories respectively.
2. Run python disassemble.py to generate the raw combined JSON datasets.
3. Run python filter_disassembly_fast.py to clean and vet the processed data.
4. Open and execute GraphCodeBERT_Stage1_Pretraining.ipynb to initialize the pretraining methodology.

## Notes on Dataset Integrity & Size Limits

> **Note:** The actual datasets (~22 GB of JSON disassembly) and the raw malware payload folders (cryptojacking/) are strictly omitted from this repository via .gitignore. This was done to comply with GitHub's file-size quotas & repository limitations, and to prevent the hosting of live functional malware components mapping to their Acceptable Use Policy. You will need to generate your own binaries mapping locally.
