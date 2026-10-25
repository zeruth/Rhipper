// Read-only: what Ghidra holds for imports by name, the external function's signature and its
// parameters' storage, and the IAT slot's data type (ghidra.sh script ProbeImport.java NAME...)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;

public class ProbeImport extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String want : getScriptArgs()) {
            for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
                if (!f.getName().equals(want)) continue;
                println("ProbeImport: " + f.getName() + " sig=" + f.getSignature().getPrototypeString()
                        + " src=" + f.getSignatureSource() + " cc=" + f.getCallingConventionName()
                        + " custom=" + f.hasCustomVariableStorage());
                for (Parameter p : f.getParameters())
                    println("ProbeImport:   " + p.getName() + " " + p.getDataType().getName() + " len="
                            + p.getDataType().getLength() + " (" + p.getDataType().getClass().getSimpleName() + ") at "
                            + p.getVariableStorage());
                for (Reference r : getReferencesTo(f.getEntryPoint())) {
                    Data d = getDataAt(r.getFromAddress());
                    println("ProbeImport:   ref from " + r.getFromAddress() + " data="
                            + (d == null ? "none" : d.getDataType().getName()));
                }
            }
        }
    }
}
