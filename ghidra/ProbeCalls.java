// For each address listed (hex): the function Ghidra has containing it (its body and prototype)
// and, for each indirect call in that body, the call-site overrides Ghidra holds for it
// (ApplyFacts' icall_ signatures, `override::prt_<address>_<hash>`) and its references. Why a call
// printed without the arguments its facts give it. `ghidra.sh script ProbeCalls.java 626610 626fa5`
//@category Rhipper
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class ProbeCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String arg : getScriptArgs()) {
            Address at = toAddr(Long.parseLong(arg.replaceFirst("^0x", ""), 16));
            Function f = getFunctionContaining(at);
            if (f == null) {
                println("ProbeCalls: " + at + " in no function");
                continue;
            }
            println("ProbeCalls: " + at + " in " + f.getName() + " " + f.getBody() + " "
                    + f.getPrototypeString(true, false) + (f.hasNoReturn() ? " noreturn" : ""));
            java.util.Map<Address, String> overrides = new java.util.HashMap<>();
            ghidra.program.model.symbol.Namespace space = currentProgram.getSymbolTable().getNamespace("override", f);
            if (space != null) {
                for (ghidra.program.model.symbol.Symbol s : currentProgram.getSymbolTable().getSymbols(space))
                    overrides.merge(s.getAddress(), s.getName(), (a, b) -> a + " | " + b);
            }
            for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                if (!ins.getFlowType().isCall() || !ins.getFlowType().isComputed()) continue;
                StringBuilder refs = new StringBuilder();
                for (Reference r : ins.getReferencesFrom())
                    refs.append(" ").append(r.getReferenceType()).append("->").append(r.getToAddress());
                String o = overrides.get(ins.getAddress());
                println("ProbeCalls:   " + ins.getAddress() + " " + ins + "  override=" + (o == null ? "none" : o) + refs);
            }
        }
    }
}
