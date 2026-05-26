from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

LINE_RE = re.compile(r"^\s*(?:0x)?([0-9A-Fa-f]+):\s*(.*)$")
OPCODE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.]*)")
HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")
HEX_FALLBACK_RE = re.compile(r"\b[0-9A-Fa-f]{4,}\b")

MATH_OPS = {"xor", "add", "sub", "mul", "imul", "div", "idiv", "adc", "sbb"}


def parse_line(line: str):
    if not line or line.lstrip().startswith(";"):
        return None, None, None

    addr = None
    rest = line
    m = LINE_RE.match(line)
    if m:
        addr = int(m.group(1), 16)
        rest = m.group(2)

    rest = rest.strip()
    if not rest:
        return addr, None, None

    m2 = OPCODE_RE.match(rest)
    if not m2:
        return addr, None, None

    opcode = m2.group(1)
    operands = rest[len(opcode):].strip()
    return addr, opcode, operands


def shannon_entropy(items) -> float:
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def graph_density(graphs) -> float:
    if not isinstance(graphs, list):
        return 0.0

    densities = []

    for g in graphs:
        if not isinstance(g, dict):
            continue

        nodes = 0
        if isinstance(g.get("instructions"), list):
            nodes = len(g["instructions"])
        elif isinstance(g.get("instruction_count"), int):
            nodes = g["instruction_count"]
        elif isinstance(g.get("blocks"), list):
            nodes = len(g["blocks"])

        edges = 0
        if isinstance(g.get("cfg_edges"), list):
            edges += len(g["cfg_edges"])
        # CFG-only to avoid mixing in DFG edges from older samples.

        if nodes:
            densities.append(edges / nodes)

    return (sum(densities) / len(densities)) if densities else 0.0


def has_memory_operand(operands: str) -> bool:
    if not operands:
        return False
    lower = operands.lower()
    return "[" in lower or "]" in lower or "ptr" in lower


def extract_features(obj: dict) -> dict:
    asm = obj.get("asm") or ""
    lines = asm.splitlines()
    math_count = 0
    loop_count = 0
    call_count = 0
    mem_count = 0
    total_opcodes = 0
    unique_opcodes = set()
    opcode_stream = []

    for line in lines:
        addr, opcode, operands = parse_line(line)
        if not opcode:
            continue

        op = opcode.lower()
        total_opcodes += 1
        unique_opcodes.add(op)
        opcode_stream.append(op)

        if op in MATH_OPS:
            math_count += 1

        if op.startswith("call"):
            call_count += 1

        if has_memory_operand(operands):
            mem_count += 1

        if op.startswith("j") and addr is not None and operands:
            m = HEX_RE.search(operands)
            if not m:
                m = HEX_FALLBACK_RE.search(operands)
            if m:
                target = int(m.group(0), 16)
                if target < addr:
                    loop_count += 1

    math_density = (math_count / total_opcodes) if total_opcodes else 0.0
    loop_density = (loop_count / total_opcodes) if total_opcodes else 0.0
    instr_variance = (len(unique_opcodes) / total_opcodes) if total_opcodes else 0.0
    opcode_entropy = shannon_entropy(opcode_stream)
    call_density = (call_count / total_opcodes) if total_opcodes else 0.0
    mem_density = (mem_count / total_opcodes) if total_opcodes else 0.0

    return {
        "math_density": math_density,
        "loop_density": loop_density,
        "graph_density": graph_density(obj.get("graphs")),
        "instr_variance": instr_variance,
        "opcode_entropy": opcode_entropy,
        "call_density": call_density,
        "mem_density": mem_density,
        "label": int(obj.get("label", 0)),
    }


def main() -> None:
    input_dir = Path("combined_output")
    output_csv = Path("full_thesis_features.csv")

    files = sorted(input_dir.glob("*.json"))
    total = len(files)
    rows = []

    def update_progress(current: int) -> None:
        if total == 0:
            return
        width = 30
        filled = int(width * current / total)
        bar = "#" * filled + "-" * (width - filled)
        percent = 100.0 * current / total
        sys.stderr.write(f"\r[{bar}] {current}/{total} ({percent:5.1f}%)")
        sys.stderr.flush()

    update_progress(0)
    for idx, path in enumerate(files, start=1):
        try:
            with path.open("r", encoding="utf-8") as f:
                obj = json.load(f)
            rows.append(extract_features(obj))
        except Exception as exc:
            print(f"Skipping {path.name}: {exc}")
        update_progress(idx)

    if total:
        sys.stderr.write("\n")
        sys.stderr.flush()

    feature_columns = [
        "math_density",
        "loop_density",
        "graph_density",
        "instr_variance",
        "opcode_entropy",
        "call_density",
        "mem_density",
    ]
    df = pd.DataFrame(rows, columns=feature_columns + ["label"])

    df.to_csv(output_csv, index=False)

    features = feature_columns
    n_features = len(features)
    ncols = 4 if n_features > 4 else n_features
    nrows = math.ceil(n_features / ncols)

    fig, axes = plt.subplots(
        nrows, ncols, figsize=(4 * ncols, 3.5 * nrows), sharey=True
    )
    if n_features == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for ax, feat in zip(axes, features):
        ax.scatter(df[feat], df["label"], s=10, alpha=0.7)
        ax.set_xlabel(feat)
    axes[0].set_ylabel("label")

    for ax in axes[n_features:]:
        ax.set_visible(False)

    fig.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
