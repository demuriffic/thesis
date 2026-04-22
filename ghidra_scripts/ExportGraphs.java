// Ghidra post-analysis script (Java)
// Exports per-function CFG and DFG for GraphCodeBERT fine-tuning.
//
// USAGE:
// analyzeHeadless.bat [project] [project_name] -import [binary] \
//   -postScript "ExportGraphs.java" "[output_path.json]" \
//   -deleteProject
//
// EXAMPLE:
// analyzeHeadless.bat C:/ghidra/projects MyProject -import malware.exe \
//   -postScript "ExportGraphs.java" "output/graphs.json" \
//   -deleteProject

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;

import java.io.*;
import java.util.*;

public class ExportGraphs extends GhidraScript {

    // =========================
    // NORMALIZATION
    // =========================
    private String normalizeRegister(Register reg) {
        if (reg == null) return "REG";

        String name = reg.getName().toLowerCase();

        if (name.equals("rsp") || name.equals("esp")) return "SP";
        if (name.equals("rbp") || name.equals("ebp")) return "BP";

        int size = reg.getBitLength();

        if (size == 64) return "REG64_" + reg.getName();
        if (size == 32) return "REG32_" + reg.getName();
        if (size == 16) return "REG16_" + reg.getName();
        if (size == 8) return "REG8_" + reg.getName();

        return "REG_" + reg.getName();
    }

    private String normalizeVarnode(Varnode v) {
        if (v == null) return "UNK";

        if (v.isRegister()) {
            Register reg = currentProgram.getRegister(v.getAddress(), v.getSize());
            if (reg != null) {
                return normalizeRegister(reg);
            }
            return "REG";
        }

        if (v.isUnique()) {
            return "TMP_" + v.getOffset(); // preserve identity
        }

        if (v.isConstant()) return "IMM";
        if (v.isAddress()) return "MEM";

        return "UNK";
    }

    // =========================
    // MAIN
    // =========================
    @Override
    public void run() throws Exception {

        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: No output path provided.");
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
            boolean firstFunc = true;

            FunctionIterator functions = fm.getFunctions(true);

            while (functions.hasNext()) {

                if (monitor.isCancelled()) break;

                Function func = functions.next();
                AddressSetView body = func.getBody();

                // skip tiny functions
                InstructionIterator countIter = listing.getInstructions(body, true);
                int instrTotal = 0;
                while (countIter.hasNext()) {
                    countIter.next();
                    instrTotal++;
                }
                if (instrTotal < 3) continue;

                if (!firstFunc) writer.println(",");
                firstFunc = false;

                writer.println("  {");
                writer.println("    \"function\": \"" + escapeJson(func.getName()) + "\",");
                writer.println("    \"entry\": \"0x" + func.getEntryPoint() + "\",");
                writer.println("    \"instruction_count\": " + instrTotal + ",");

                // =========================
                // INSTRUCTIONS
                // =========================
                List<Address> instrAddrs = new ArrayList<>();
                Map<String, Integer> addrToIdx = new HashMap<>();

                InstructionIterator instrIter1 = listing.getInstructions(body, true);
                while (instrIter1.hasNext()) {
                    Instruction instr = instrIter1.next();
                    String addrStr = "0x" + instr.getAddress().toString();
                    addrToIdx.put(addrStr, instrAddrs.size());
                    instrAddrs.add(instr.getAddress());
                }

                writer.println("    \"instructions\": [");

                InstructionIterator instrIter2 = listing.getInstructions(body, true);
                boolean firstInstr = true;

                while (instrIter2.hasNext()) {
                    Instruction instr = instrIter2.next();

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
                            + "\", \"idx\": " + addrToIdx.get("0x" + instr.getAddress().toString())
                            + "}");
                }

                writer.println();
                writer.println("    ],");

                // =========================
                // CFG NODES
                // =========================
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

                // =========================
                // CFG EDGES
                // =========================
                writer.println("    \"cfg_edges\": [");

                boolean firstEdge = true;

                for (CodeBlock block : blocks) {

                    CodeBlockReferenceIterator destIter = block.getDestinations(monitor);

                    String srcAddr = "0x" + block.getFirstStartAddress().toString();

                    while (destIter.hasNext()) {

                        CodeBlockReference ref = destIter.next();
                        Address destAddr = ref.getDestinationAddress();

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

                // =========================
                // DFG (P-CODE)
                // =========================
                writer.println("    \"dfg_edges\": [");

                Map<String, Integer> lastDef = new HashMap<>();
                Set<String> seenEdges = new HashSet<>();
                boolean firstDfg = true;

                InstructionIterator dfgIter = listing.getInstructions(body, true);

                while (dfgIter.hasNext()) {

                    Instruction instr = dfgIter.next();

                    String addrStr = "0x" + instr.getAddress().toString();
                    Integer curIdx = addrToIdx.get(addrStr);
                    if (curIdx == null) continue;

                    PcodeOp[] ops = instr.getPcode();
                    if (ops == null) continue;

                    for (PcodeOp op : ops) {

                        // USES
                        for (int i = 0; i < op.getNumInputs(); i++) {

                            Varnode in = op.getInput(i);
                            String varName = normalizeVarnode(in);

                            Integer defIdx = lastDef.get(varName);

                            if (defIdx != null && !defIdx.equals(curIdx)) {

                                String edgeKey = defIdx + "-" + curIdx + "-" + varName;

                                if (seenEdges.add(edgeKey)) {

                                    if (!firstDfg) writer.println(",");
                                    firstDfg = false;

                                    writer.print("      {\"from\": " + defIdx +
                                            ", \"to\": " + curIdx +
                                            ", \"var\": \"" + escapeJson(varName) + "\"}");
                                }
                            }
                        }

                        // DEF
                        Varnode out = op.getOutput();
                        if (out != null) {
                            String varName = normalizeVarnode(out);
                            lastDef.put(varName, curIdx);
                        }
                    }
                }

                writer.println();
                writer.println("    ]");

                writer.println("  }");
            }

            writer.println("]");

            println("Exported graphs -> " + outputPath);

        } finally {
            writer.close();
        }
    }

    // =========================
    // JSON ESCAPE
    // =========================
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}