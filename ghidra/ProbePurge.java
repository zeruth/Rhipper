// Read-only: an import's stack purge and storage, and at each call to it the stack depth Ghidra
// tracks before and after the call (ghidra.sh script ProbePurge.java NAME)
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class ProbePurge extends GhidraScript {
    @Override
    public void run() throws Exception {
        String want = getScriptArgs()[0];
        for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
            if (!f.getName().equals(want)) continue;
            println("ProbePurge: " + f.getName() + " purge=" + f.getStackPurgeSize() + " custom=" + f.hasCustomVariableStorage()
                    + " cc=" + f.getCallingConventionName() + " sig=" + f.getSignature().getPrototypeString());
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                for (Reference c : getReferencesTo(r.getFromAddress())) {
                    Address at = c.getFromAddress();
                    Instruction i = getInstructionAt(at);
                    Function owner = getFunctionContaining(at);
                    if (i == null || owner == null) continue;
                    CallDepthChangeInfo info = new CallDepthChangeInfo(owner, monitor);
                    println("ProbePurge:   call at " + at + " in " + owner.getName() + " depth before "
                            + info.getDepth(at) + " after " + info.getDepth(i.getNext().getAddress())
                            + " override=" + CallDepthChangeInfo.getStackDepthChange(currentProgram, at));
                }
            }
        }
    }
}
