// FindVulnerabilities.java
// Ghidra script to detect common vulnerabilities
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;

import java.util.*;

public class FindVulnerabilities extends GhidraScript {

    private final List<String> dangerousFunctions = Arrays.asList(
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "system"
    );

    private final List<String> printfFamily = Arrays.asList(
            "printf", "fprintf", "sprintf", "snprintf",
            "vprintf", "vfprintf", "vsprintf", "vsnprintf"
    );

    @Override
    public void run() throws Exception {
        println("=== Vulnerability Analysis ===");
        println("Program: " + currentProgram.getName());

        findDangerousFunctions();
        findFormatStringVulns();
        findBufferOperations();

        println("=== Analysis Complete ===");
    }

    private void findDangerousFunctions() throws Exception {
        println("\n[1] Searching for dangerous functions and references...");

        SymbolTable symTable = currentProgram.getSymbolTable();
        for (String fn : dangerousFunctions) {
            SymbolIterator it = symTable.getSymbolIterator(fn, true);
            boolean foundSymbol = false;

            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                foundSymbol = true;
                Address addr = s.getAddress();
                println("Found symbol: " + fn + " at " + addr);

                ReferenceManager refMgr = currentProgram.getReferenceManager();
                ReferenceIterator refs = refMgr.getReferencesTo(addr);
                int count = 0;

                while (refs.hasNext() && !monitor.isCancelled()) {
                    Reference r = refs.next();
                    count++;
                    println("  Ref " + count + ": from " + r.getFromAddress());
                }

                if (count == 0) {
                    println("  No references found to " + fn +
                            " (may be inlined or resolved differently).");
                }
            }

            if (!foundSymbol) {
                println("Symbol not found in table: " + fn +
                        " (may be statically linked/inlined).");
            }
        }
    }

    private void findFormatStringVulns() throws Exception {
        println("\n[2] Searching for potential format string issues...");

        Listing listing = currentProgram.getListing();
        SymbolTable symTable = currentProgram.getSymbolTable();

        for (String fn : printfFamily) {
            SymbolIterator it = symTable.getSymbolIterator(fn, true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                Address addr = s.getAddress();
                println("Checking callsites for: " + fn + " at " + addr);

                ReferenceManager refMgr = currentProgram.getReferenceManager();
                ReferenceIterator refs = refMgr.getReferencesTo(addr);

                while (refs.hasNext() && !monitor.isCancelled()) {
                    Reference r = refs.next();
                    Address from = r.getFromAddress();

                    Instruction instr = listing.getInstructionAt(from);
                    if (instr != null) {
                        println("  Callsite: " + from +
                                " :: " + instr.toString());
                        println("    Note: Manual review required to confirm exploitability.");
                    } else {
                        println("  Callsite: " + from +
                                " (instruction not decoded)");
                    }
                }
            }
        }
    }

    private void findBufferOperations() throws Exception {
        println("\n[3] Searching for stack buffers / local allocations (heuristic)...");

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        int reported = 0;

        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();

            if (f.isThunk() || f.isExternal()) {
                continue;
            }

            Variable[] locals = f.getLocalVariables();
            for (Variable v : locals) {
                DataType dt = v.getDataType();
                String dtName = dt.getName().toLowerCase();
                int size = (int) dt.getLength();

                boolean interesting =
                        dtName.contains("char") ||
                        dtName.contains("byte") ||
                        dtName.contains("array");

                if (interesting && size >= 32) {
                    reported++;
                    println("Function: " + f.getName() +
                            " :: Local variable '" + v.getName() +
                            "' type=" + dt.getName() +
                            " size=" + size);
                    println("  Note: Review for unsafe memory copy usage.");
                }
            }
        }

        if (reported == 0) {
            println("No large stack buffers detected via heuristic.");
        }
    }
}
