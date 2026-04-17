import os
import shutil
import subprocess


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


GHIDRA_PATH = r"C:\Thesis\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\support\analyzeHeadless.bat"
PROJECT_DIR = r"C:\Thesis\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\projects\MalwareProject"
PROJECT_NAME = "MalwareProject"
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")

FOLDER_MAP = {
    r"C:\Thesis\miners": r"asm_output",
}

os.makedirs(PROJECT_DIR, exist_ok=True)

total = 0
failed = 0

for raw_folder, asm_folder in FOLDER_MAP.items():
    if not os.path.exists(raw_folder):
        print(f"Skipping (not found): {raw_folder}")
        continue

    graph_folder = asm_folder.replace("asm_output", "graph_output")
    os.makedirs(asm_folder, exist_ok=True)
    os.makedirs(graph_folder, exist_ok=True)

    for root, dirs, files in os.walk(raw_folder):
        for binary in files:
            binary_path = os.path.abspath(os.path.join(root, binary))
            asm_path = os.path.abspath(os.path.join(asm_folder, binary + ".asm"))
            graph_path = os.path.abspath(os.path.join(graph_folder, binary + ".json"))

            if os.path.exists(asm_path) and os.path.exists(graph_path):
                print(f"  [SKIP] Already exists: {binary[:16]}...")
                continue

            # Check for UPX packing and auto-unpack
            if is_upx_packed(binary_path):
                print(f"  [INFO] UPX packing detected: {binary}")
                try_upx_unpack(binary_path)

            print(f"  [INFO] Disassembling: {binary}...")

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
                    print(f"  [ OK ] Saved: {binary} (.asm + .json)")
                    total += 1
                elif asm_ok:
                    print(f"  [PART] Saved .asm but graph export failed: {binary}")
                    total += 1
                else:
                    print(f"  [FAIL] No output generated")
                    failed += 1

            except subprocess.TimeoutExpired:
                print(f"  [FAIL] Timed out: {binary[:16]}")
                failed += 1
            except Exception as e:
                print(f"  [FAIL] Error: {e}")
                failed += 1

print(f"\nDone — {total} succeeded, {failed} failed")
print(f"ASM files saved to data/asm/")