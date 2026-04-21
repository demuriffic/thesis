import os
import shutil
import subprocess
import json


def is_upx_packed(filepath):
    """Check if a binary is UPX-packed by looking for UPX signatures."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(1024)  # UPX headers are near the start
        return b"UPX!" in data or b"UPX0" in data or b"UPX1" in data
    except Exception:
        return False


def try_upx_unpack(filepath):
    """Attempt to unpack a UPX-packed binary. Returns True if unpacked."""
    upx_cmd = shutil.which("upx")
    if not upx_cmd:
        print(f"  [WARN] UPX not found in PATH. Cannot unpack: {os.path.basename(filepath)}")
        return False
    try:
        result = subprocess.run(
            [upx_cmd, "-d", filepath],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            print(f"  [UPX]  Unpacked: {os.path.basename(filepath)}")
            return True
        else:
            print(f"  [WARN] UPX unpack failed: {result.stderr.strip().splitlines()[-1] if result.stderr else 'unknown error'}")
            return False
    except Exception as e:
        print(f"  [WARN] UPX error: {e}")
        return False


def get_label_from_path(path):
    parts = [part.lower() for part in os.path.normpath(path).split(os.sep)]
    if "cryptojacking" in parts:
        return 1
    if "benign" in parts:
        return 0
    return None


def label_name(label):
    if label == 1:
        return "cryptojacking"
    if label == 0:
        return "benign"
    return "unknown"


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


GHIDRA_PATH = r"C:\Thesis\ghidra\support\analyzeHeadless.bat"
PROJECT_DIR = r"C:\Thesis\ghidra\projects\MalwareProject"
PROJECT_NAME = "MalwareProject"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "ghidra_scripts")

INPUT_ROOTS = [
    os.path.join(SCRIPT_DIR, "benign"),
    os.path.join(SCRIPT_DIR, "cryptojacking"),
]

OUTPUT_ROOT = os.path.join(SCRIPT_DIR, "combined_output")
INTERMEDIATE_ROOT = os.path.join(SCRIPT_DIR, "intermediate_output")
KEEP_INTERMEDIATE = False

os.makedirs(PROJECT_DIR, exist_ok=True)

total = 0
failed = 0
skipped = 0

for raw_folder in INPUT_ROOTS:
    if not os.path.exists(raw_folder):
        print(f"Skipping (not found): {raw_folder}")
        continue

    for root, dirs, files in os.walk(raw_folder):
        for binary in files:
            binary_path = os.path.abspath(os.path.join(root, binary))
            label = get_label_from_path(binary_path)
            if label is None:
                print(f"  [SKIP] No label folder found for: {binary}")
                skipped += 1
                continue

            rel_path = os.path.relpath(binary_path, raw_folder)
            combined_path = os.path.abspath(os.path.join(OUTPUT_ROOT, rel_path + ".json"))
            asm_path = os.path.abspath(os.path.join(INTERMEDIATE_ROOT, "asm", rel_path + ".asm"))
            graph_path = os.path.abspath(os.path.join(INTERMEDIATE_ROOT, "graph", rel_path + ".json"))

            if os.path.exists(combined_path):
                print(f"  [SKIP] Combined exists: {binary[:16]}...")
                skipped += 1
                continue

            ensure_parent_dir(combined_path)
            ensure_parent_dir(asm_path)
            ensure_parent_dir(graph_path)

            # Check for UPX packing and auto-unpack
            if is_upx_packed(binary_path):
                print(f"  [INFO] UPX packing detected: {binary}")
                try_upx_unpack(binary_path)

            print(f"  [INFO] Disassembling: {binary} ({label_name(label)})...")

            cmd = [
                GHIDRA_PATH,
                PROJECT_DIR, PROJECT_NAME,
                "-import", binary_path,
                "-scriptPath", SCRIPTS_DIR,
                "-postScript", "ExportAsm.java", asm_path,
                "-postScript", "ExportGraphs.java", graph_path,
                "-deleteProject",
                "-analysisTimeoutPerFile", "3600",
            ]

            try:
                result = subprocess.run(cmd, timeout=3600, capture_output=True, text=True)

                # Dump relevant Ghidra output for diagnostics
                for line in (result.stdout or "").splitlines():
                    if any(kw in line for kw in ["ERROR", "WARN", "Script", "script", "Exported", "exception", "Exception", "postScript"]):
                        print(f"    [GHIDRA] {line.strip()}")

                if result.stderr:
                    for line in result.stderr.strip().splitlines()[-5:]:
                        print(f"    [STDERR] {line.strip()}")

                asm_ok = os.path.exists(asm_path)
                graph_ok = os.path.exists(graph_path)
                if asm_ok and graph_ok:
                    try:
                        with open(asm_path, "r", encoding="utf-8", errors="replace") as asm_file:
                            asm_text = asm_file.read()
                        with open(graph_path, "r", encoding="utf-8") as graph_file:
                            graphs = json.load(graph_file)

                        combined = {
                            "binary": os.path.basename(binary_path),
                            "source_path": binary_path,
                            "label": label,
                            "label_name": label_name(label),
                            "asm": asm_text,
                            "graphs": graphs,
                        }

                        with open(combined_path, "w", encoding="utf-8") as out_file:
                            json.dump(combined, out_file, indent=2)

                        print(f"  [ OK ] Saved combined: {os.path.basename(combined_path)}")
                        total += 1

                        if not KEEP_INTERMEDIATE:
                            try:
                                os.remove(asm_path)
                                os.remove(graph_path)
                            except Exception as e:
                                print(f"  [WARN] Failed to remove intermediate outputs: {e}")
                    except Exception as e:
                        print(f"  [FAIL] Combine error: {e}")
                        failed += 1
                elif asm_ok:
                    print(f"  [FAIL] Saved .asm but graph export failed: {binary}")
                    failed += 1
                else:
                    print(f"  [FAIL] No output generated")
                    failed += 1

            except subprocess.TimeoutExpired:
                print(f"  [FAIL] Timed out: {binary[:16]}")
                failed += 1
            except Exception as e:
                print(f"  [FAIL] Error: {e}")
                failed += 1

print(f"\nDone — {total} combined succeeded, {failed} failed, {skipped} skipped")
print(f"Combined JSON files saved to {OUTPUT_ROOT}")