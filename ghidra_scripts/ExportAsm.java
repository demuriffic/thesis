import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.Register;

import java.io.*;
import java.util.*;

/**
 * Ghidra post-analysis script (Java)
 * Exports normalized assembly code for ML processing.
 * 
 * USAGE:
 * analyzeHeadless.bat [project] [project_name] -import [binary] \
 *   -postScript "ExportAsm.java" "[output_path.asm]" \
 *   -deleteProject
 * 
 * EXAMPLE:
 * analyzeHeadless.bat C:/ghidra/projects MyProject -import malware.exe \
 *   -postScript "ExportAsm.java" "output/asm.asm" \
 *   -deleteProject
 */
public class ExportAsm extends GhidraScript {

    // =========================
    // REGISTER NORMALIZATION
    // =========================
    private String normalizeRegister(Register reg) {
        if (reg == null) return "REG";

        String name = reg.getName().toLowerCase();

        if (name.equals("rsp") || name.equals("esp")) return "SP";
        if (name.equals("rbp") || name.equals("ebp")) return "BP";

        int size = reg.getBitLength();

        if (size == 64) return "REG64";
        if (size == 32) return "REG32";
        if (size == 16) return "REG16";
        if (size == 8) return "REG8";

        return "REG";
    }

    // =========================
    // OPERAND NORMALIZATION
    // =========================
    private String normalizeOperandObjects(Object[] objs) {
        if (objs == null || objs.length == 0) return "";

        List<String> parts = new ArrayList<>();

        for (Object obj : objs) {

            if (obj instanceof Register) {
                parts.add(normalizeRegister((Register) obj));
            }

            else if (obj instanceof Scalar) {
                parts.add("IMM");
            }

            else if (obj instanceof Address) {
                parts.add("MEM");
            }

            else {
                parts.add("UNK");
            }
        }

        return String.join(" ", parts);
    }

    @Override
    public void run() throws Exception {

        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: No output path provided as script argument.");
            return;
        }

        String outputPath = args[0];

        File outFile = new File(outputPath);
        File parentDir = outFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        Program program = currentProgram;
        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();

        PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));

        try {
            writer.println("; Disassembly of: " + program.getName());
            writer.println("; Format: " + program.getExecutableFormat());
            writer.println("; Architecture: " + program.getLanguageID());
            writer.println("; Functions: " + fm.getFunctionCount());
            writer.println();

            int funcCount = 0;
            int instrCount = 0;

            FunctionIterator functions = fm.getFunctions(true);

            while (functions.hasNext()) {

                if (monitor.isCancelled()) break;

                Function func = functions.next();
                Address entry = func.getEntryPoint();

                writer.println("; --- Function: " + func.getName()
                        + " (0x" + entry + ") ---");

                AddressSetView body = func.getBody();

                InstructionIterator instrIter = listing.getInstructions(body, true);

                while (instrIter.hasNext()) {

                    Instruction instr = instrIter.next();

                    Address addr = instr.getAddress();
                    String mnemonic = instr.getMnemonicString();

                    int numOps = instr.getNumOperands();
                    StringBuilder ops = new StringBuilder();

                    for (int i = 0; i < numOps; i++) {

                        if (i > 0) ops.append(" | ");

                        Object[] opObjs = instr.getOpObjects(i);
                        ops.append(normalizeOperandObjects(opObjs));
                    }

                    writer.println("0x" + addr + ":\t"
                            + mnemonic + "\t"
                            + ops.toString());

                    instrCount++;
                }

                writer.println();
                funcCount++;
            }

            println("Exported " + funcCount + " functions ("
                    + instrCount + " instructions) -> " + outputPath);

        } finally {
            writer.close();
        }
    }
}