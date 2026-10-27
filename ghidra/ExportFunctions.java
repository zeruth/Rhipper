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

    // A function whose entry another one's code falls into, that nothing calls, jumps to or points
    // to by a relocated pointer: no function, a cut in that one. Ghidra made them of wide strings'
    // characters taken for code addresses, `S\0u\0` 0x750053 inside 0x750050, which it cut to its
    // first two instructions: its `mov ebx, ecx` unseen, a __stdcall with ecx lost, a stub on a
    // loader's path, 88 such in a VS2010 client (2026-10-26). Removed, and the function it cut
    // given its whole body again.
    // a relocation anywhere in the code unit a reference is from: `push offset fn`'s is at its
    // operand, not the instruction's start
    private boolean relocatedWithin(ghidra.program.model.reloc.RelocationTable relocs,
                                    ghidra.program.model.address.Address from) {
        ghidra.program.model.listing.CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(from);
        if (cu == null) return relocs.hasRelocation(from);
        for (ghidra.program.model.address.Address a = cu.getMinAddress(); a.compareTo(cu.getMaxAddress()) <= 0; a = a.next())
            if (relocs.hasRelocation(a)) return true;
        return false;
    }

    private int removeFallInFunctions() throws Exception {
        java.util.List<Function> cut = new java.util.ArrayList<>();
        ghidra.program.model.reloc.RelocationTable relocs = currentProgram.getRelocationTable();
        // (an image without relocations cannot tell a pointer from bytes that look like one: there
        // every reference keeps the function)
        boolean relocated = relocs.getSize() > 0;
        ghidra.program.model.symbol.SymbolTable symbols = currentProgram.getSymbolTable();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk() || f.isExternal()) continue;
            ghidra.program.model.address.Address entry = f.getEntryPoint();
            if (symbols.isExternalEntryPoint(entry)) continue;              // (an entry point, an export)
            ghidra.program.model.listing.Instruction before = getInstructionBefore(entry);
            if (before == null || before.getFallThrough() == null || !before.getFallThrough().equals(entry)) continue;
            Function host = getFunctionContaining(before.getAddress());
            if (host == null || host.equals(f)) continue;
            boolean wanted = false;
            for (ghidra.program.model.symbol.Reference r : getReferencesTo(entry)) {
                ghidra.program.model.address.Address from = r.getFromAddress();
                if (f.getBody().contains(from)) continue;              // (its own loop's)
                ghidra.program.model.symbol.RefType t = r.getReferenceType();
                if (t.isCall() || t.isJump() || !relocated || relocatedWithin(relocs, from)) {
                    wanted = true;
                    break;
                }
            }
            if (!wanted) cut.add(f);
        }
        java.util.Set<Function> hosts = new java.util.HashSet<>();
        for (Function f : cut) {
            ghidra.program.model.listing.Instruction before = getInstructionBefore(f.getEntryPoint());
            Function host = before != null ? getFunctionContaining(before.getAddress()) : null;
            println("ExportFunctions: " + f.getName() + " is " + (host != null ? host.getName() : "?")
                    + "'s code fallen into, no function: removed");
            currentProgram.getFunctionManager().removeFunction(f.getEntryPoint());
            if (host != null) hosts.add(host);
        }
        for (Function h : hosts)
            ghidra.app.cmd.function.CreateFunctionCmd.fixupFunctionBody(currentProgram, h, monitor);
        return cut.size();
    }

    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        int removed = removeFallInFunctions();
        if (removed > 0) println("ExportFunctions: functions fallen into removed " + removed);
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
