# Ghidra post-analysis script (Jython)
# ML-ready disassembly exporter for GraphCodeBERT pipeline

import os

# Check if running in Ghidra environment
try:
    args = getScriptArgs()
except NameError:
    print("ERROR: This script must be run from within Ghidra using analyzeHeadless.bat")
    print("Usage: analyzeHeadless.bat [project] [project_name] -import [binary] -postScript ExportAsm.java [output_path]")
    import sys
    sys.exit(1)

if len(args) < 1:
    println("ERROR: No output path provided as script argument.")
else:
    output_path = args[0]

    program = currentProgram
    listing = program.getListing()
    fm = program.getFunctionManager()

    # Ensure output directory exists
    parent = os.path.dirname(output_path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)

    # =========================
    # NORMALIZATION FUNCTIONS
    # =========================
    def normalize_register(reg):
        if reg is None:
            return "REG"

        name = reg.getName().lower()

        if name in ["rsp", "esp"]:
            return "SP"
        if name in ["rbp", "ebp"]:
            return "BP"

        size = reg.getBitLength()

        if size == 64:
            return "REG64"
        if size == 32:
            return "REG32"
        if size == 16:
            return "REG16"
        if size == 8:
            return "REG8"

        return "REG"

    def normalize_operand(obj):
        if obj is None:
            return "UNK"

        # Register
        if isinstance(obj, Register):
            return normalize_register(obj)

        # Immediate
        if isinstance(obj, Scalar):
            return "IMM"

        # Memory reference (Address objects often appear here)
        try:
            if obj.toString().startswith("0x"):
                return "MEM"
        except:
            pass

        return str(obj)

    # =========================
    # OUTPUT
    # =========================
    f = open(output_path, "w")

    try:
        f.write("; Disassembly of: %s\n" % program.getName())
        f.write("; Format: %s\n" % program.getExecutableFormat())
        f.write("; Architecture: %s\n" % program.getLanguageID())
        f.write("; Functions: %d\n\n" % fm.getFunctionCount())

        func_count = 0
        instr_count = 0

        functions = fm.getFunctions(True)

        for func in functions:

            entry = func.getEntryPoint()
            f.write("; --- Function: %s (0x%s) ---\n" % (func.getName(), entry))

            body = func.getBody()
            instr_iter = listing.getInstructions(body, True)

            for instr in instr_iter:

                addr = instr.getAddress()
                mnemonic = instr.getMnemonicString()
                num_ops = instr.getNumOperands()

                ops_list = []

                for i in range(num_ops):
                    objs = instr.getOpObjects(i)

                    if objs is None:
                        continue

                    norm = " ".join([normalize_operand(o) for o in objs])
                    ops_list.append(norm)

                ops = " | ".join(ops_list)

                f.write("0x%s:\t%s\t%s\n" % (str(addr), mnemonic, ops))
                instr_count += 1

            f.write("\n")
            func_count += 1

        println("Exported %d functions (%d instructions) -> %s"
                % (func_count, instr_count, output_path))

    finally:
        f.close()