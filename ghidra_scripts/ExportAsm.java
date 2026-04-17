// Ghidra post-analysis script (Java)
// Exports per-function disassembly to a single .asm file.
//
// Called by analyzeHeadless with:
//   -postScript ExportAsm.java <output_asm_path>
//
// @category Thesis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ExportAsm extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: No output path provided as script argument.");
            return;
        }

        String outputPath = args[0];

        // Ensure output directory exists
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
                if (monitor.isCancelled()) {
                    break;
                }

                Function func = functions.next();
                Address entry = func.getEntryPoint();
                writer.println("; --- Function: " + func.getName() + " (0x" + entry + ") ---");

                AddressSetView body = func.getBody();
                InstructionIterator instrIter = listing.getInstructions(body, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    Address addr = instr.getAddress();
                    String mnemonic = instr.getMnemonicString();

                    int numOps = instr.getNumOperands();
                    StringBuilder ops = new StringBuilder();
                    for (int i = 0; i < numOps; i++) {
                        if (i > 0) ops.append(", ");
                        ops.append(instr.getDefaultOperandRepresentation(i));
                    }

                    writer.println("0x" + addr + ":\t" + mnemonic + "\t" + ops);
                    instrCount++;
                }

                writer.println();
                funcCount++;
            }

            println("Exported " + funcCount + " functions (" + instrCount + " instructions) -> " + outputPath);
        } finally {
            writer.close();
        }
    }
}
