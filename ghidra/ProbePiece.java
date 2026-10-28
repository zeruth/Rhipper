// ApplyFacts' piece merge, its inputs at each address given: the function there, its symbol's
// source, the function before it, and each reference to its entry with its type and the function it
// comes from (why one jumppieces.py lists is or is not merged).
//   bash ghidra/ghidra.sh script ProbePiece.java 0x594da8 0x5997bd
// @category Rhipper
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class ProbePiece extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String s : getScriptArgs()) {
            Address a = toAddr(Long.parseUnsignedLong(s.replace("0x", ""), 16));
            Function f = getFunctionAt(a);
            if (f == null) {
                println("PROBE " + a + ": no function (" + getFunctionContaining(a) + " contains it)");
                continue;
            }
            Function prev = getFunctionBefore(a);
            println("PROBE " + a + ": " + f.getName() + " source " + f.getSymbol().getSource() + " thunk " + f.isThunk()
                    + " body " + f.getBody() + "; before it " + prev + (prev != null ? " body " + prev.getBody() : ""));
            for (Reference r : getReferencesTo(a)) {
                println("PROBE   <- " + r.getFromAddress() + " " + r.getReferenceType() + " jump " + r.getReferenceType().isJump()
                        + " in " + getFunctionContaining(r.getFromAddress()));
            }
        }
    }
}
