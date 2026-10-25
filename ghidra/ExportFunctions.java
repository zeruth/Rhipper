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
            // (and its prototype's stack parameter bytes whatever its convention, "import_params":
            // the type library declares some __stdcall ones __cdecl, d3d9's and dinput8's among
            // them, and protos32.py takes those its callers never clean up after as popping these)
            StringBuilder params = new StringBuilder();
            // (and the imports with no prototype at all, "import_untyped": protos32.py counts what
            // their callers push for them)
            StringBuilder untyped = new StringBuilder();
            w.println("], \"import_cleanup\": {");
            boolean firstImp = true;
            FunctionIterator ex = currentProgram.getFunctionManager().getExternalFunctions();
            while (ex.hasNext()) {
                Function f = ex.next();
                int bytes = 0;
                for (ghidra.program.model.listing.Parameter p : f.getParameters()) {
                    if (p.isStackVariable()) bytes += (p.getLength() + 3) & ~3;
                }
                int purge = !"__cdecl".equals(f.getCallingConventionName()) && !f.hasVarArgs() ? bytes : 0;
                for (ghidra.program.model.symbol.Reference ref :
                        getReferencesTo(f.getExternalLocation().getExternalSpaceAddress())) {
                    // (the slot's own reference; the calls through it refer to the import too)
                    if (getInstructionAt(ref.getFromAddress()) != null) continue;
                    w.printf("%s\"0x%x\": %d%n", firstImp ? " " : ",", ref.getFromAddress().getOffset(), purge);
                    if (!f.hasVarArgs())
                        params.append(String.format("%s\"0x%x\": %d%n", params.length() == 0 ? " " : ",",
                                ref.getFromAddress().getOffset(), bytes));
                    if (f.getSignatureSource() == ghidra.program.model.symbol.SourceType.DEFAULT)
                        untyped.append(String.format("%s\"0x%x\"", untyped.length() == 0 ? "" : ", ",
                                ref.getFromAddress().getOffset()));
                    firstImp = false;
                    imports++;
                }
            }
            w.println("}, \"import_params\": {");
            w.print(params);
            w.println("}, \"import_untyped\": [" + untyped + "]}");
        }
        println("ExportFunctions: wrote " + count + " functions and " + imports + " import slots to " + out);
    }
}
