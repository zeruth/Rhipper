// Prints a function's stack frame as Ghidra holds it: sizes and every variable.
// Usage (headless): -postScript ProbeFrame.java <hex address>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;

public class ProbeFrame extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (String a : getScriptArgs()) {
            Function f = getFunctionAt(toAddr(Long.parseLong(a, 16)));
            if (f == null) {
                println("ProbeFrame: no function at " + a);
                continue;
            }
            StackFrame sf = f.getStackFrame();
            println("ProbeFrame: " + f.getName() + " frame " + sf.getFrameSize() + " local " + sf.getLocalSize()
                    + " param offset " + sf.getParameterOffset() + " return offset " + sf.getReturnAddressOffset()
                    + " purge " + f.getStackPurgeSize() + " custom " + f.hasCustomVariableStorage());
            for (Variable v : sf.getStackVariables())
                println("ProbeFrame:   " + v.getName() + " @" + v.getStackOffset() + " " + v.getLength() + " "
                        + v.getDataType().getName() + " " + v.getSource());
        }
    }
}
