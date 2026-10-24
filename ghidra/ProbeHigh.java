// Decompiles a function and prints, for each p-code op writing or reading a named high variable,
// the op and the types of its varnodes' high variables: what the decompiler had when it printed
// (casts it inserted show as CAST ops). The pcode classes are reached by reflection: the script
// bundle does not import ghidra.program.model.pcode (as ApplyFacts' HighFunctionDBUtil).
//
// Usage (headless): -postScript ProbeHigh.java <hexaddr> <variable name>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.util.Iterator;

public class ProbeHigh extends GhidraScript {
    private static Object call(Object o, String m, Object... args) throws Exception {
        if (o == null) return null;
        Class<?>[] types = new Class<?>[args.length];
        for (int i = 0; i < args.length; i++) types[i] = args[i] instanceof Integer ? int.class : args[i].getClass();
        return o.getClass().getMethod(m, types).invoke(o, args);
    }

    private String describe(Object v) throws Exception {
        if (v == null) return "-";
        Object h = call(v, "getHigh");
        Object name = h == null ? "?" : call(h, "getName");
        Object type = h == null ? null : call(h, "getDataType");
        String t = type == null ? "?" : (String) call(type, "getDisplayName");
        boolean constant = (Boolean) call(v, "isConstant");
        return (name == null ? "(unnamed)" : name) + ":" + t + (constant ? "=" + call(v, "getOffset") : "");
    }

    private boolean named(Object v, String n) throws Exception {
        Object h = v == null ? null : call(v, "getHigh");
        return h != null && n.equals(call(h, "getName"));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Function f = getFunctionAt(toAddr(Long.parseLong(args[0].replaceFirst("^0[xX]", ""), 16)));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        Object hf = r.getClass().getMethod("getHighFunction").invoke(r);
        Iterator<?> it = (Iterator<?>) call(hf, "getPcodeOps");
        while (it.hasNext()) {
            Object op = it.next();
            Object out = call(op, "getOutput");
            int n = (Integer) call(op, "getNumInputs");
            boolean hit = named(out, args[1]);
            StringBuilder s = new StringBuilder();
            s.append(call(call(op, "getSeqnum"), "getTarget")).append(" ").append(call(op, "getMnemonic"))
                .append(" out=").append(describe(out));
            for (int i = 0; i < n; i++) {
                Object in = call(op, "getInput", i);
                s.append(" in").append(i).append("=").append(describe(in));
                hit |= named(in, args[1]);
            }
            if (hit) println("ProbeHigh: " + s);
        }
        d.dispose();
    }
}
