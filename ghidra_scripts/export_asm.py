# Ghidra post-analysis script (Jython)
# Exports per-function disassembly to a single .asm file.
#
# Called by analyzeHeadless with:
#   -postScript export_asm.py <output_asm_path>
#
# @category Thesis

import os

args = getScriptArgs()
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

    f = open(output_path, "w")
    try:
        f.write("; Disassembly of: %s\n" % program.getName())
        f.write("; Format: %s\n" % program.getExecutableFormat())
        f.write("; Architecture: %s\n" % program.getLanguageID())
        f.write("; Functions: %d\n\n" % fm.getFunctionCount())

        func_count = 0
        instr_count = 0
        functions = fm.getFunctions(True)  # forward address order
        for func in functions:
            entry = func.getEntryPoint()
            f.write("; --- Function: %s (0x%s) ---\n" % (func.getName(), entry))

            body = func.getBody()
            instr_iter = listing.getInstructions(body, True)
            for instr in instr_iter:
                addr = instr.getAddress()
                mnemonic = instr.getMnemonicString()
                num_ops = instr.getNumOperands()
                ops = ", ".join(
                    [instr.getDefaultOperandRepresentation(i) for i in range(num_ops)]
                )
                f.write("0x%s:\t%s\t%s\n" % (addr, mnemonic, ops))
                instr_count += 1

            f.write("\n")
            func_count += 1

        println("Exported %d functions (%d instructions) -> %s" % (func_count, instr_count, output_path))
    finally:
        f.close()
