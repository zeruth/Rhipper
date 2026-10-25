// For each address, read only: the code units from 16 bytes before it to 16 after (instruction
// or data, with its length), and the functions at and around it with their body ranges. A look at
// what Ghidra's listing holds where a body is cut.
//   bash ghidra/ghidra.sh script ProbeListing.java 0x9f9fa2
// @category FrostLite
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class ProbeListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        for (String s : getScriptArgs()) {
            Address at = toAddr(Long.parseUnsignedLong(s.replace("0x", ""), 16));
            Address a = at.subtract(16);
            Address end = at.add(16);
            while (a.compareTo(end) <= 0) {
                CodeUnit cu = listing.getCodeUnitContaining(a);
                if (cu == null) {
                    a = a.add(1);
                    continue;
                }
                println("PROBE " + s + ": " + cu.getMinAddress() + " len " + cu.getLength() + " "
                        + (cu instanceof ghidra.program.model.listing.Instruction ? "insn " : "data ") + cu);
                a = cu.getMaxAddress().add(1);
            }
            for (Function f : new Function[] {getFunctionAt(at), getFunctionContaining(at),
                    getFunctionContaining(at.subtract(1)), getFunctionContaining(at.add(1))}) {
                if (f == null) continue;
                StringBuilder r = new StringBuilder();
                for (AddressRange ar : f.getBody()) r.append(ar.getMinAddress()).append("..").append(ar.getMaxAddress()).append(" ");
                println("PROBE " + s + ": function " + f.getName() + " at " + f.getEntryPoint() + " body " + r);
            }
        }
    }
}
