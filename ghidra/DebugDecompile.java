// Decompiles functions with the decompiler's debug recording on: each <outdir>/<addr>.xml holds
// everything the decompiler asked the program for, so the decompile replays in the console
// (ghidra/decompiler's decomp_dbg: `restore <addr>.xml`, `load addr 0x<addr>`, `decompile`)
// without a Ghidra session. The options are ExportDecompAll's: its main pass, or with `long` its
// long limits (alias blocking off, the raised instruction and payload limits).
//
// Usage (headless): -postScript DebugDecompile.java <outdir> [long] <hexaddr>...
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

import java.io.File;

public class DebugDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args[0]);
        dir.mkdirs();
        boolean longLimits = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("long")) {
                longLimits = true;
                continue;
            }
            long a = Long.parseLong(args[i].replaceFirst("^0[xX]", ""), 16);
            Function f = getFunctionAt(toAddr(a));
            if (f == null) {
                println("DebugDecompile: no function at " + args[i]);
                continue;
            }
            DecompInterface ifc = new DecompInterface();
            DecompileOptions opts = new DecompileOptions();
            opts.grabFromProgram(currentProgram);
            if (longLimits) {
                opts.setAliasBlock(DecompileOptions.AliasBlockEnum.None);
                opts.setMaxInstructions(400000);
                opts.setMaxPayloadMBytes(400);
            }
            ifc.setOptions(opts);
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(true);
            ifc.setSimplificationStyle("decompile");
            File out = new File(dir, String.format("%x.xml", a));
            ifc.enableDebug(out);
            ifc.openProgram(currentProgram);
            long t0 = System.currentTimeMillis();
            DecompileResults res = ifc.decompileFunction(f, longLimits ? 900 : 90, monitor);
            long s = (System.currentTimeMillis() - t0) / 1000;
            println("DebugDecompile: " + String.format("%x", a) + (res.decompileCompleted() ? " decompiled" :
                    " failed: " + res.getErrorMessage().trim().split("\n")[0]) + " in " + s + "s -> " + out);
            ifc.dispose();
        }
    }
}
