// Exports every function's extent, for programs without .pdata (32-bit x86): what pebin.py's
// Binary reads in place of the unwind table. One JSON document:
//   {"functions": [{"entry","name","thunk","cc","ranges": [[start, end), ...]}, ...]}
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
        int count = 0;
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
            w.println("]}");
        }
        println("ExportFunctions: wrote " + count + " functions to " + out);
    }
}
