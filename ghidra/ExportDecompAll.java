// FrostLite copy of tools/recomp/ghidra/ExportDecompAll.java (3.3.5): 64-bit addresses, names
// with their namespace. Drives tools/corpus.py --export.
// Decompiles every function in the program (or an address range) in parallel and streams the C
// output to a JSON-lines file, one object per function: {"addr","name","size","c"} or
// {"addr","name","size","error"}. This is the one-off export behind tools/recomp/corpus.py: once
// it has run, every later read of a reference function is a file lookup instead of a headless
// Ghidra run.
//
// Usage (headless): -postScript ExportDecompAll.java <outfile.jsonl> [<lo> <hi>]
//   lo/hi are hex addresses; hi is exclusive. Thunks are skipped (they carry no body worth reading).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.TaskMonitor;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportDecompAll extends GhidraScript {

    private static String jsonEscape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    /** The widths the decompiler gave each global it reads or writes directly, as `"g"`:
     *  {"142725a78":[4], ...}. The C names a global by address only (`_UNK_142725a78`,
     *  `uRam0000000142ddedb0`), and a piece of a 16-byte constant or a raw address has no data item
     *  to give its width, so the translator guessed 8 where the decompiler had built the expression
     *  around a 4-byte lane (C4319 in four functions, C4293 in FUN_1401b94f0, 2026-10-18). */
    // (by reflection: the script's bundle cannot load ghidra.program.model.pcode, and a direct
    // reference failed every function with NoClassDefFoundError: HighFunction, 2026-10-19)
    private static volatile java.lang.reflect.Method mHigh, mOps, mOut, mIns, mAddr, mSize;

    private static java.lang.reflect.Method method(Object o, String name) throws Exception {
        java.lang.reflect.Method m = o.getClass().getMethod(name);
        m.setAccessible(true);
        return m;
    }

    private String globalWidths(DecompileResults res) {
        try {
            if (mHigh == null) mHigh = method(res, "getHighFunction");
            Object hf = mHigh.invoke(res);
            if (hf == null) {
                return null;
            }
            if (mOps == null) mOps = method(hf, "getPcodeOps");
            java.util.TreeMap<Long, java.util.TreeSet<Integer>> widths = new java.util.TreeMap<>();
            java.util.Iterator<?> ops = (java.util.Iterator<?>) mOps.invoke(hf);
            while (ops.hasNext()) {
                Object op = ops.next();
                if (mOut == null) {
                    mOut = method(op, "getOutput");
                    mIns = method(op, "getInputs");
                }
                Object out = mOut.invoke(op);
                if (out != null) {
                    note(widths, out);
                }
                for (Object v : (Object[]) mIns.invoke(op)) {
                    note(widths, v);
                }
            }
            return render(widths);
        } catch (Throwable e) {
            return null;
        }
    }

    private String render(java.util.TreeMap<Long, java.util.TreeSet<Integer>> widths) {
        if (widths.isEmpty()) {
            return null;
        }
        StringBuilder b = new StringBuilder("{");
        for (java.util.Map.Entry<Long, java.util.TreeSet<Integer>> e : widths.entrySet()) {
            if (b.length() > 1) b.append(',');
            b.append('"').append(Long.toHexString(e.getKey())).append("\":[");
            int n = 0;
            for (int w : e.getValue()) {
                if (n++ > 0) b.append(',');
                b.append(w);
            }
            b.append(']');
        }
        return b.append('}').toString();
    }

    private void note(java.util.Map<Long, java.util.TreeSet<Integer>> widths, Object v) throws Exception {
        if (v == null) {
            return;
        }
        if (mAddr == null) {
            mAddr = method(v, "getAddress");
            mSize = method(v, "getSize");
        }
        // (the address space says what the varnode is: ram is a global; register, unique, const
        // and stack spaces are not)
        Address a = (Address) mAddr.invoke(v);
        if (!a.isMemoryAddress() || a.isStackAddress() || a.isRegisterAddress() || a.isUniqueAddress()
                || a.isConstantAddress()) {
            return;
        }
        widths.computeIfAbsent(a.getOffset(), k -> new java.util.TreeSet<>()).add((Integer) mSize.invoke(v));
    }

    private static java.util.Set<Long> readAddresses(String path) throws Exception {
        java.util.Set<Long> out = new java.util.HashSet<>();
        for (String line : java.nio.file.Files.readAllLines(java.nio.file.Paths.get(path))) {
            if (!line.isBlank()) out.add(Long.parseLong(line.trim().replaceFirst("^0[xX]", ""), 16));
        }
        return out;
    }

    private static String line(String[] r) {
        StringBuilder b = new StringBuilder();
        b.append("{\"addr\":\"").append(r[0]).append("\",\"name\":\"").append(jsonEscape(r[1]))
         .append("\",\"size\":").append(r[2]);
        if (r[3] != null) {
            b.append(",\"c\":\"").append(jsonEscape(r[3])).append("\"");
            if (r[5] != null) b.append(",\"g\":").append(r[5]);
            b.append("}");
        } else {
            b.append(",\"error\":\"").append(jsonEscape(r[4] == null ? "" : r[4])).append("\"}");
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: ExportDecompAll <outfile.jsonl> [<lo> <hi>]");
            return;
        }
        long lo = 0, hi = Long.MAX_VALUE;
        // `@file`: only the functions at the addresses listed in it, one hex address a line (a
        // sample to check before a whole export). `slow=file`: the functions listed there (a
        // previous run's retries, ghidra/shards.py) are decompiled with the long limits from the
        // start, beside the main pass instead of after it: the 833-case FUN_140727d90 alone takes
        // ~600 s, and timing out at 90 s first then running it alone left one shard ten minutes
        // behind the other (2026-10-23). Two hex numbers: the address range.
        java.util.Set<Long> only = null;
        java.util.Set<Long> slow = new java.util.HashSet<>();
        List<Long> bounds = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("@")) {
                only = readAddresses(args[i].substring(1));
            } else if (args[i].startsWith("slow=")) {
                java.nio.file.Path p = java.nio.file.Paths.get(args[i].substring(5));
                if (java.nio.file.Files.exists(p)) {
                    slow = readAddresses(p.toString());
                }
            } else {
                bounds.add(Long.parseLong(args[i].replaceFirst("^0[xX]", ""), 16));
            }
        }
        if (bounds.size() >= 2) {
            lo = bounds.get(0);
            hi = bounds.get(1);
        }

        // a listed address Ghidra made no function of (code reached only through a table or a
        // tail jump, as the static initializer at 0x1401eef00 and the GUID handlers it installs
        // were, 2026-10-21): disassembled and made a function first, so it is exported too
        if (only != null) {
            for (long a : only) {
                Address at = toAddr(a);
                if (getFunctionAt(at) != null) {
                    continue;
                }
                Function inside = getFunctionContaining(at);
                if (inside != null) {
                    println("ExportDecompAll: " + at + " is inside " + inside.getName() + ", left as it is");
                    continue;
                }
                disassemble(at);
                Function made = createFunction(at, null);
                println("ExportDecompAll: " + (made != null ? "made a function at " : "could not make a function at ") + at);
            }
        }

        List<Function> functions = new ArrayList<>();
        final List<Function> slowFunctions = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isThunk()) {
                continue;
            }
            long a = f.getEntryPoint().getOffset();
            if (a < lo || a >= hi || (only != null && !only.contains(a))) {
                continue;
            }
            (slow.contains(a) ? slowFunctions : functions).add(f);
        }
        println("ExportDecompAll: " + (functions.size() + slowFunctions.size()) + " functions to decompile, "
                + slowFunctions.size() + " of them slow (long limits from the start)");

        DecompilerCallback<String[]> callback = new DecompilerCallback<String[]>(currentProgram,
                new DecompileConfigurer() {
                    @Override
                    public void configure(DecompInterface ifc) {
                        ifc.toggleCCode(true);
                        ifc.toggleSyntaxTree(true);
                        ifc.setSimplificationStyle("decompile");
                    }
                }) {
            @Override
            public String[] process(DecompileResults res, TaskMonitor mon) {
                Function f = res.getFunction();
                String addr = String.format("%x", f.getEntryPoint().getOffset());
                String name = f.getName(true);  // with namespace: Lua::C_Container::GetBagName
                String size = Long.toString(f.getBody().getNumAddresses());
                if (res.decompileCompleted()) {
                    return new String[] { addr, name, size, res.getDecompiledFunction().getC(), null,
                                          globalWidths(res) };
                }
                return new String[] { addr, name, size, null, res.getErrorMessage(), null };
            }
        };
        callback.setTimeout(90);
        // what failed in the first pass gets a second, alone, with ten times the time and the
        // decompiler's limits raised: the 90 s timeout lost five functions, among them the 833-case
        // FUN_140727d90 with its 268 KB frame (2026-10-16)
        DecompilerCallback<String[]> retry = longLimits(callback);
        // (the slow pass's own: it runs while the main pass's failures are retried through `retry`)
        DecompilerCallback<String[]> slowCallback = longLimits(callback);
        final List<Function> failed = new ArrayList<>();

        final int[] count = { 0 };
        final long start = System.currentTimeMillis();
        try (PrintWriter out = new PrintWriter(new FileWriter(args[0]))) {
            // the slow functions on their own thread, with the long limits, while the main pass runs
            final Exception[] slowError = { null };
            Thread slowPass = new Thread(() -> {
                try {
                    ParallelDecompiler.decompileFunctions(slowCallback, currentProgram, slowFunctions.iterator(), r -> {
                        if (r == null) {
                            return;
                        }
                        synchronized (out) {
                            out.println(line(r));
                            count[0]++;
                            println("ExportDecompAll: slow " + r[0] + (r[3] != null ? " decompiled" : " failed: "
                                    + (r[4] == null ? "" : r[4].trim().split("\n")[0])) + ", "
                                    + (System.currentTimeMillis() - start) / 1000 + "s");
                        }
                    }, monitor);
                } catch (Exception e) {
                    slowError[0] = e;
                }
            }, "ExportDecompAll slow pass");
            slowPass.start();
            ParallelDecompiler.decompileFunctions(callback, currentProgram, functions.iterator(), r -> {
                if (r == null) {
                    return;
                }
                if (r[3] == null) {
                    synchronized (failed) {
                        failed.add(getFunctionAt(toAddr(Long.parseUnsignedLong(r[0], 16))));
                    }
                    return;
                }
                synchronized (out) {
                    out.println(line(r));
                    count[0]++;
                    if (count[0] % 1000 == 0) {
                        long s = (System.currentTimeMillis() - start) / 1000;
                        println("ExportDecompAll: " + count[0] + " done, " + s + "s");
                        out.flush();
                    }
                }
            }, monitor);
            println("ExportDecompAll: " + failed.size() + " failed, decompiling them again with longer limits");
            failed.removeIf(f -> f == null);
            ParallelDecompiler.decompileFunctions(retry, currentProgram, failed.iterator(), r -> {
                if (r == null) {
                    return;
                }
                synchronized (out) {
                    out.println(line(r));
                    count[0]++;
                    println("ExportDecompAll: again " + r[0] + (r[3] != null ? " decompiled" : " failed: "
                            + (r[4] == null ? "" : r[4].trim().split("\n")[0])));
                }
            }, monitor);
            slowPass.join();
            if (slowError[0] != null) {
                throw slowError[0];
            }
        } finally {
            callback.dispose();
            retry.dispose();
            slowCallback.dispose();
        }
        long s = (System.currentTimeMillis() - start) / 1000;
        println("ExportDecompAll: wrote " + count[0] + " functions to " + args[0] + " in " + s + "s");
    }

    /** What failed in the first pass gets a second, with ten times the time and the decompiler's
     *  limits raised: the 90 s timeout lost five functions, among them the 833-case FUN_140727d90
     *  with its 268 KB frame (2026-10-16). The functions a previous run had to retry (`slow=`)
     *  start here. */
    private DecompilerCallback<String[]> longLimits(DecompilerCallback<String[]> callback) {
        DecompilerCallback<String[]> retry = new DecompilerCallback<String[]>(currentProgram,
                new DecompileConfigurer() {
                    @Override
                    public void configure(DecompInterface ifc) {
                        ifc.toggleCCode(true);
                        ifc.toggleSyntaxTree(true);
                        ifc.setSimplificationStyle("decompile");
                        DecompileOptions opts = new DecompileOptions();
                        opts.grabFromProgram(currentProgram);
                        // a pointer into the stack may reach any stack variable: with the default
                        // (arrays block an alias), a list head on the stack that an unlink wrote
                        // through a pointer was re-read as unchanged, FUN_1419c7450's rehash
                        // linked the wrong node, and entering the world never finished
                        // (2026-10-21; 104 functions keep a list sentinel on the stack)
                        opts.setAliasBlock(DecompileOptions.AliasBlockEnum.None);
                        opts.setMaxInstructions(400000);
                        opts.setMaxPayloadMBytes(400);
                        ifc.setOptions(opts);
                    }
                }) {
            @Override
            public String[] process(DecompileResults res, TaskMonitor mon) throws Exception {
                return callback.process(res, mon);
            }
        };
        retry.setTimeout(900);
        return retry;
    }
}
