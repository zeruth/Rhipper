// Exports every function's extent, for programs without .pdata (32-bit x86): what pebin.py's
// Binary reads in place of the unwind table. One JSON document:
//   {"functions": [{"entry","name","thunk","cc","ranges": [[start, end), ...]}, ...],
//    "import_cleanup": {slot: bytes the import pops}}
// Addresses are hex strings; a range's end is exclusive. A function whose body Ghidra split
// over several address ranges lists them all (the x64 analogue of chained .pdata pieces).
//
// Usage (headless): -postScript ExportFunctions.java <out.json>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportFunctions extends GhidraScript {

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        int count = 0, imports = 0;
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            w.println("{\"functions\": [");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            boolean first = true;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal()) {
                    continue;
                }
                StringBuilder r = new StringBuilder();
                for (AddressRange ar : f.getBody()) {
                    if (r.length() > 0) {
                        r.append(',');
                    }
                    r.append(String.format("[\"0x%x\",\"0x%x\"]", ar.getMinAddress().getOffset(),
                                           ar.getMaxAddress().getOffset() + 1));
                }
                w.printf("%s{\"entry\":\"0x%x\",\"name\":\"%s\",\"thunk\":%b,\"cc\":\"%s\",\"ranges\":[%s]}%n",
                         first ? " " : ",", f.getEntryPoint().getOffset(), esc(f.getName(true)),
                         f.isThunk(), esc(f.getCallingConventionName()), r);
                first = false;
                count++;
            }
            // the stack bytes each import pops, by its slot (x86: a call through `[__imp_X]` to a
            // __stdcall import is cleaned up by the import, and protos32.py follows the caller's
            // stack across it)
            w.println("], \"import_cleanup\": {");
            boolean firstImp = true;
            FunctionIterator ex = currentProgram.getFunctionManager().getExternalFunctions();
            while (ex.hasNext()) {
                Function f = ex.next();
                int purge = 0;
                if (!"__cdecl".equals(f.getCallingConventionName()) && !f.hasVarArgs()) {
                    for (ghidra.program.model.listing.Parameter p : f.getParameters()) {
                        if (p.isStackVariable()) purge += (p.getLength() + 3) & ~3;
                    }
                }
                for (ghidra.program.model.symbol.Reference ref :
                        getReferencesTo(f.getExternalLocation().getExternalSpaceAddress())) {
                    // (the slot's own reference; the calls through it refer to the import too)
                    if (getInstructionAt(ref.getFromAddress()) != null) continue;
                    w.printf("%s\"0x%x\": %d%n", firstImp ? " " : ",", ref.getFromAddress().getOffset(), purge);
                    firstImp = false;
                    imports++;
                }
            }
            w.println("}}");
        }
        println("ExportFunctions: wrote " + count + " functions and " + imports + " import slots to " + out);
    }
}
