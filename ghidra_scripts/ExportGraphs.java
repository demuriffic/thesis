// Ghidra post-analysis script (Java)
// Exports per-function Control Flow Graphs (CFG) and Data Flow Graphs (DFG)
// as JSON for GraphCodeBERT fine-tuning.
//
// CFG: basic blocks as nodes, branch/fall-through edges between them.
// DFG: register/memory def-use chains between instructions.
//
// Called by analyzeHeadless with:
//   -postScript ExportGraphs.java <output_json_path>
//
// @category Thesis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import java.io.*;
import java.util.*;

public class ExportGraphs extends GhidraScript {

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
        BasicBlockModel bbModel = new BasicBlockModel(program);

        PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));
        try {
            writer.println("[");
            int funcCount = 0;
            boolean firstFunc = true;

            FunctionIterator functions = fm.getFunctions(true);
            while (functions.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }

                Function func = functions.next();
                AddressSetView body = func.getBody();

                // Skip thunks and tiny functions
                InstructionIterator testIter = listing.getInstructions(body, true);
                int instrTotal = 0;
                while (testIter.hasNext()) {
                    testIter.next();
                    instrTotal++;
                }
                if (instrTotal < 3) continue;

                if (!firstFunc) writer.println(",");
                firstFunc = false;

                writer.println("  {");
                writer.println("    \"function\": \"" + escapeJson(func.getName()) + "\",");
                writer.println("    \"entry\": \"0x" + func.getEntryPoint() + "\",");
                writer.println("    \"instruction_count\": " + instrTotal + ",");

                // === Collect instructions with index mapping ===
                List<Address> instrAddrs = new ArrayList<>();
                Map<String, Integer> addrToIdx = new HashMap<>();
                InstructionIterator allInstr = listing.getInstructions(body, true);
                while (allInstr.hasNext()) {
                    Instruction instr = allInstr.next();
                    String addrStr = "0x" + instr.getAddress().toString();
                    addrToIdx.put(addrStr, instrAddrs.size());
                    instrAddrs.add(instr.getAddress());
                }

                // === Instructions list ===
                writer.println("    \"instructions\": [");
                InstructionIterator instrIter = listing.getInstructions(body, true);
                boolean firstInstr = true;
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (!firstInstr) writer.println(",");
                    firstInstr = false;

                    String mnemonic = instr.getMnemonicString();
                    int numOps = instr.getNumOperands();
                    StringBuilder ops = new StringBuilder();
                    for (int i = 0; i < numOps; i++) {
                        if (i > 0) ops.append(", ");
                        ops.append(instr.getDefaultOperandRepresentation(i));
                    }
                    writer.print("      {\"addr\": \"0x" + instr.getAddress()
                            + "\", \"mnemonic\": \"" + escapeJson(mnemonic)
                            + "\", \"operands\": \"" + escapeJson(ops.toString())
                            + "\", \"idx\": " + addrToIdx.get("0x" + instr.getAddress().toString()) + "}");
                }
                writer.println();
                writer.println("    ],");

                // === CFG: Basic blocks and edges ===
                writer.println("    \"cfg_nodes\": [");
                List<CodeBlock> blocks = new ArrayList<>();
                CodeBlockIterator blockIter = bbModel.getCodeBlocksContaining(body, monitor);
                while (blockIter.hasNext()) {
                    blocks.add(blockIter.next());
                }

                boolean firstBlock = true;
                for (CodeBlock block : blocks) {
                    if (!firstBlock) writer.println(",");
                    firstBlock = false;

                    Address start = block.getFirstStartAddress();
                    Address end = block.getMaxAddress();

                    // Collect instruction indices in this block
                    List<Integer> blockInstrIdxs = new ArrayList<>();
                    for (int i = 0; i < instrAddrs.size(); i++) {
                        Address a = instrAddrs.get(i);
                        if (a.compareTo(start) >= 0 && a.compareTo(end) <= 0) {
                            blockInstrIdxs.add(i);
                        }
                    }

                    writer.print("      {\"start\": \"0x" + start
                            + "\", \"end\": \"0x" + end
                            + "\", \"instr_indices\": " + blockInstrIdxs + "}");
                }
                writer.println();
                writer.println("    ],");

                // === CFG edges ===
                writer.println("    \"cfg_edges\": [");
                boolean firstEdge = true;
                for (CodeBlock block : blocks) {
                    CodeBlockReferenceIterator destIter = block.getDestinations(monitor);
                    String srcAddr = "0x" + block.getFirstStartAddress().toString();
                    while (destIter.hasNext()) {
                        CodeBlockReference ref = destIter.next();
                        Address destAddr = ref.getDestinationAddress();
                        // Only include edges within this function
                        if (body.contains(destAddr)) {
                            if (!firstEdge) writer.println(",");
                            firstEdge = false;
                            writer.print("      {\"from\": \"" + srcAddr
                                    + "\", \"to\": \"0x" + destAddr
                                    + "\", \"type\": \"" + ref.getFlowType().getName() + "\"}");
                        }
                    }
                }
                writer.println();
                writer.println("    ],");

                // === DFG: Register def-use chains ===
                writer.println("    \"dfg_edges\": [");
                // Track where each register was last defined (addr -> instruction index)
                Map<String, Integer> lastDef = new HashMap<>();
                boolean firstDfg = true;

                InstructionIterator dfgIter = listing.getInstructions(body, true);
                while (dfgIter.hasNext()) {
                    Instruction instr = dfgIter.next();
                    String addrStr = "0x" + instr.getAddress().toString();
                    Integer curIdx = addrToIdx.get(addrStr);
                    if (curIdx == null) continue;

                    // Get objects read (uses) by this instruction
                    Object[] inputObjs = instr.getInputObjects();
                    if (inputObjs != null) {
                        Set<String> seenRegs = new HashSet<>();
                        for (Object obj : inputObjs) {
                            if (obj instanceof Register) {
                                String regName = ((Register) obj).getName();
                                if (seenRegs.contains(regName)) continue;
                                seenRegs.add(regName);
                                Integer defIdx = lastDef.get(regName);
                                if (defIdx != null && !defIdx.equals(curIdx)) {
                                    if (!firstDfg) writer.println(",");
                                    firstDfg = false;
                                    writer.print("      {\"from\": " + defIdx
                                            + ", \"to\": " + curIdx
                                            + ", \"var\": \"" + escapeJson(regName) + "\"}");
                                }
                            }
                        }
                    }

                    // Get objects written (defs) by this instruction
                    Object[] outputObjs = instr.getResultObjects();
                    if (outputObjs != null) {
                        for (Object obj : outputObjs) {
                            if (obj instanceof Register) {
                                String regName = ((Register) obj).getName();
                                lastDef.put(regName, curIdx);
                            }
                        }
                    }
                }
                writer.println();
                writer.println("    ]");
                writer.println("  }");
                funcCount++;
            }

            writer.println("]");
            println("Exported graphs for " + funcCount + " functions -> " + outputPath);
        } finally {
            writer.close();
        }
    }

    private String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
