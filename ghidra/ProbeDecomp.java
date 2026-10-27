// Why a function will not decompile: its decompilation as it is, then with each listed callee's
// return made a plain 4-byte integer in turn (in this session only: run read-only), each result's
// error or success. `analyzeHeadless ... -readOnly -postScript ProbeDecomp.java b75490 b73e70 aae710`
//@category Rhipper
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ProbeDecomp extends GhidraScript {
    private String decompile(DecompInterface d, Function f) {
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        return r.decompileCompleted() ? "ok" : "failed: " + r.getErrorMessage().trim();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Function f = getFunctionAt(toAddr(Long.parseLong(args[0], 16)));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        println("ProbeDecomp: as it is: " + decompile(d, f));
        // (without its call-site overrides, then without its committed locals: cumulative)
        ghidra.program.model.symbol.Namespace space = currentProgram.getSymbolTable().getNamespace("override", f);
        if (space != null) {
            java.util.List<ghidra.program.model.symbol.Symbol> syms = new java.util.ArrayList<>();
            for (ghidra.program.model.symbol.Symbol s : currentProgram.getSymbolTable().getSymbols(space)) syms.add(s);
            for (ghidra.program.model.symbol.Symbol s : syms) s.delete();
            d.flushCache();
            println("ProbeDecomp: without its " + syms.size() + " call-site overrides: " + decompile(d, f));
        }
        // (the data it references made normal, not volatile: ApplyFacts' atomic words)
        int unvol = 0;
        for (ghidra.program.model.listing.Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
            for (ghidra.program.model.symbol.Reference r : ins.getReferencesFrom()) {
                ghidra.program.model.listing.Data dd = getDataContaining(r.getToAddress());
                if (dd != null && ghidra.program.model.data.MutabilitySettingsDefinition.DEF.getChoice(dd)
                        == ghidra.program.model.data.MutabilitySettingsDefinition.VOLATILE) {
                    ghidra.program.model.data.MutabilitySettingsDefinition.DEF.setChoice(dd,
                            ghidra.program.model.data.MutabilitySettingsDefinition.NORMAL);
                    unvol++;
                }
            }
        }
        d.flushCache();
        println("ProbeDecomp: with " + unvol + " volatile data it reads made normal: " + decompile(d, f));
        // (its own return as something else)
        DataType own = f.getReturnType();
        for (DataType t : new DataType[] { ghidra.program.model.data.VoidDataType.dataType,
                ghidra.program.model.data.Float10DataType.dataType, ghidra.program.model.data.Undefined4DataType.dataType }) {
            f.setReturnType(t, SourceType.USER_DEFINED);
            d.flushCache();
            println("ProbeDecomp: returning " + t.getName() + ": " + decompile(d, f));
        }
        f.setReturnType(own, SourceType.USER_DEFINED);
        // (its callees' keep conventions back to their base ones, one at a time, then all)
        java.util.List<Function> kept = new java.util.ArrayList<>();
        for (Function c : f.getCalledFunctions(monitor)) {
            String cc = c.getCallingConventionName();
            if (cc != null && (cc.contains("keep") || cc.contains("custom") || c.hasCustomVariableStorage())) kept.add(c);
        }
        for (Function c : kept) {
            String cc = c.getCallingConventionName();
            boolean custom = c.hasCustomVariableStorage();
            c.setCustomVariableStorage(false);
            c.setCallingConvention("__thiscall");
            d.flushCache();
            println("ProbeDecomp: " + c.getName() + " (" + cc + (custom ? ", custom" : "") + ") as __thiscall: " + decompile(d, f));
        }
        for (ghidra.program.model.listing.Variable v : f.getLocalVariables()) f.removeVariable(v);
        d.flushCache();
        println("ProbeDecomp: and without its locals: " + decompile(d, f));
        for (int k = 1; k < args.length; k++) {
            Function c = getFunctionAt(toAddr(Long.parseLong(args[k], 16)));
            if (c == null) continue;
            DataType was = c.getReturnType();
            c.setReturnType(ghidra.program.model.data.Undefined4DataType.dataType, SourceType.USER_DEFINED);
            d.flushCache();
            println("ProbeDecomp: " + c.getName() + " returning undefined4 (was " + was.getName() + "): " + decompile(d, f));
            c.setReturnType(was, SourceType.USER_DEFINED);
            d.flushCache();
        }
        d.dispose();
    }
}
