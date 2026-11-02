// Prints what Ghidra holds for each function given (entry, body, inline, noreturn, thunk, call fixup)
// and, for each, how its body ends: the last instruction's fall-through and what sits there. A
// diagnostic for ghidra.sh script FnInfo.java <addr>...; changes nothing.
// @category Rhipper
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class FnInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address at = toAddr(a.toLowerCase().startsWith("0x") ? a.substring(2) : a);
            Function f = getFunctionAt(at);
            if (f == null) {
                println("FnInfo " + a + ": no function");
                continue;
            }
            println("FnInfo " + a + " " + f.getName() + " body " + f.getBody() + " inline " + f.isInline()
                    + " noreturn " + f.hasNoReturn() + " thunk " + f.isThunk() + " fixup " + f.getCallFixup()
                    + " cc " + f.getCallingConventionName());
            Instruction last = getInstructionContaining(f.getBody().getMaxAddress());
            if (last != null) {
                Address ft = last.getFallThrough();
                Function there = ft == null ? null : getFunctionAt(ft);
                println("FnInfo   last " + last.getAddress() + " " + last + " flow " + last.getFlowType()
                        + " override " + last.getFlowOverride() + " fallthrough " + ft
                        + (there != null ? " = function " + there.getName() : ""));
            }
        }
    }
}
